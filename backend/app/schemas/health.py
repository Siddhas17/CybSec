from __future__ import annotations

from pydantic import BaseModel


class HealthOut(BaseModel):
    status: str
    database: str
    analytical_core: str
    version: str
