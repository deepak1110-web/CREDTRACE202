"""
CREDTRACE V2 - WebSocket Live Broadcasting & Synchronization Manager
Multi-Device Real-Time Sync across internet with room partitioning
"""
import json
import logging
from typing import Dict, Set, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from app.config import settings
from app.database import (
    get_overview_statistics,
    get_security_events,
    get_threat_alerts,
    get_credential
)

logger = logging.getLogger("credtrace.ws")
router = APIRouter()

class ConnectionManager:
    def __init__(self):
        # Maps room_id -> Set of active WebSockets
        self.rooms: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, room_id: str):
        await websocket.accept()
        if room_id not in self.rooms:
            self.rooms[room_id] = set()
        self.rooms[room_id].add(websocket)
        logger.info(f"Client connected to room '{room_id}'. Total clients in room: {len(self.rooms[room_id])}")

    def disconnect(self, websocket: WebSocket, room_id: str):
        if room_id in self.rooms and websocket in self.rooms[room_id]:
            self.rooms[room_id].remove(websocket)
            if not self.rooms[room_id]:
                del self.rooms[room_id]
            logger.info(f"Client disconnected from room '{room_id}'.")

    async def broadcast_to_room(self, room_id: str, message: Dict[str, Any]):
        """Broadcasts a JSON message to all clients connected in the given room."""
        if room_id not in self.rooms:
            return
        
        dead_connections = set()
        for connection in list(self.rooms[room_id]):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Error broadcasting to client in room {room_id}: {e}")
                dead_connections.add(connection)
                
        for dead in dead_connections:
            if dead in self.rooms[room_id]:
                self.rooms[room_id].remove(dead)

manager = ConnectionManager()

@router.websocket("/ws/events")
async def websocket_events_endpoint(
    websocket: WebSocket,
    room: str = Query(settings.DEFAULT_ROOM_ID)
):
    await manager.connect(websocket, room)
    try:
        # Immediately send room state snapshot on connection / reconnection
        stats = get_overview_statistics(room)
        recent_events = get_security_events(room, limit=25)
        recent_alerts = get_threat_alerts(room, limit=15)
        cred = get_credential(room)
        
        await websocket.send_json({
            "type": "INITIAL_SNAPSHOT",
            "room_id": room,
            "case_id": settings.CASE_ID,
            "statistics": stats,
            "events": recent_events,
            "alerts": recent_alerts,
            "credential": cred
        })
        
        # Keep connection alive & handle incoming pings
        while True:
            data = await websocket.receive_text()
            try:
                parsed = json.loads(data)
                msg_type = parsed.get("type")
                if msg_type == "PING":
                    await websocket.send_json({"type": "PONG", "timestamp": parsed.get("timestamp")})
                elif msg_type == "REQUEST_REFRESH":
                    stats = get_overview_statistics(room)
                    await websocket.send_json({
                        "type": "STATE_UPDATE",
                        "statistics": stats,
                        "credential": get_credential(room)
                    })
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, room)
    except Exception as e:
        logger.error(f"WebSocket error in room {room}: {e}")
        manager.disconnect(websocket, room)
