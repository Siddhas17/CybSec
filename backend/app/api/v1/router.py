from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1 import admin, analytics, attack_graph, auth, detections, events, health, risks, test_events, threats

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(events.router)
api_router.include_router(detections.router)
api_router.include_router(threats.router)
api_router.include_router(risks.router)
api_router.include_router(attack_graph.router)
api_router.include_router(analytics.router)
api_router.include_router(test_events.router)
api_router.include_router(admin.router)
