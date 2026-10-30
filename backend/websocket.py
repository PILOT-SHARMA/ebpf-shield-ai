"""
websocket.py — WebSocket connection manager for live event streaming.
Owner: Aryan Gupta (backend)
"""

from fastapi import WebSocket
from typing import List
import json
import asyncio


class ConnectionManager:
    """Manages WebSocket connections for live event/alert streaming."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Send a message to all connected clients."""
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.disconnect(conn)

    async def broadcast_event(self, event_data: dict):
        """Broadcast a new event to the dashboard."""
        await self.broadcast({
            "type": "new_event",
            "data": event_data
        })

    async def broadcast_alert(self, alert_data: dict):
        """Broadcast a new alert to the dashboard."""
        await self.broadcast({
            "type": "new_alert",
            "data": alert_data
        })


# Global manager instance
manager = ConnectionManager()
