from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db
from backend.app.schemas.health import HealthOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health(db: Session = Depends(get_db)) -> HealthOut:
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "unreachable"

    try:
        from backend.app.services.model_registry import get_predictor, get_risk_config

        get_predictor()
        get_risk_config()
        core_status = "loaded"
    except Exception as exc:
        core_status = f"unavailable: {exc}"

    overall = "ok" if db_status == "connected" and core_status == "loaded" else "degraded"
    return HealthOut(status=overall, database=db_status, analytical_core=core_status, version="v1")
