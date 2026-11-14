"""Start CyberGuard X:  python run.py   (serves the API and the built dashboard on one port)."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))

if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    if not (ROOT / "frontend" / "dist").exists():
        print("NOTE: frontend/dist not found - run `cd frontend && npm install && npm run build` first, or use `npm run dev`.")
    uvicorn.run("app.main:app", host=host, port=port, log_level="info")
