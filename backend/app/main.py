import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .bus import bus
from .config import ROOT, settings
from .deps import principal_from_token
from .routers import auth, backup_r, cia, crypto_r, database, events_r, incidents_r, intel, settings_r, signatures, sim, shop
from .services import events, seed, state, telemetry

log = logging.getLogger("cyberguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    bus.loop = asyncio.get_running_loop()
    await asyncio.get_running_loop().run_in_executor(None, seed.init)
    await asyncio.get_running_loop().run_in_executor(None, state.load)
    task = asyncio.create_task(telemetry.background_loop())
    log.info("CyberGuard X ready — e-mail delivery configured: %s", settings.email_configured)
    yield
    task.cancel()


app = FastAPI(title="CyberGuard X", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])

CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if not request.url.path.startswith("/api/docs") and not request.url.path.startswith("/api/openapi"):
        resp.headers.setdefault("Content-Security-Policy", CSP)
    return resp


for r in (auth, sim, crypto_r, signatures, database, cia, incidents_r, backup_r, events_r, intel, settings_r, shop):
    app.include_router(r.router, prefix="/api")


@app.get("/api/health")
def health():
    return {"status": "ok", "smtp_configured": settings.email_configured, "telemetry": settings.telemetry_enabled}


@app.websocket("/api/ws")
async def ws(websocket: WebSocket, token: str = ""):
    try:
        from .deps import _resolve
        if _resolve(token).role == "customer":
            raise ValueError("staff only")
    except Exception:
        await websocket.close(code=4401)
        return
    await bus.connect(websocket)
    await websocket.send_json({"type": "hello", "data": {"state": state.snapshot(), "events": events.recent(30)}})
    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        pass
    finally:
        bus.disconnect(websocket)


DIST = ROOT / "frontend" / "dist"
if not DIST.exists():  # API-only deployment (the pages are hosted elsewhere, e.g. Netlify)
    @app.get("/", include_in_schema=False)
    def api_root():
        return {"service": "NovaMart API", "status": "ok", "health": "/api/health"}

if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        f = (DIST / path).resolve()
        if path and f.is_file() and DIST in f.parents:
            return FileResponse(f)
        return FileResponse(DIST / "index.html")
