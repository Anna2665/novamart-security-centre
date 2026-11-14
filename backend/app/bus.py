"""Thread-safe WebSocket broadcast bus (event-driven updates for the dashboard)."""
import asyncio
import json
from typing import Any

from fastapi import WebSocket


class Bus:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def _broadcast(self, text: str) -> None:
        dead = []
        for c in list(self.clients):
            try:
                await c.send_text(text)
            except Exception:  # client went away
                dead.append(c)
        for c in dead:
            self.clients.discard(c)

    def publish(self, type_: str, data: Any) -> None:
        """Callable from any thread."""
        if not self.loop or not self.clients:
            return
        text = json.dumps({"type": type_, "data": data}, default=str)
        asyncio.run_coroutine_threadsafe(self._broadcast(text), self.loop)


bus = Bus()
