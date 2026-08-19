"""SQLAlchemy ORM models. Imported here so backend.app.db.base.Base.metadata
sees every table (needed by Base.metadata.create_all() and Alembic
autogenerate) regardless of which module actually gets imported first."""

from backend.app.models.attack_graph import AttackEdge, AttackNode
from backend.app.models.detection import Detection
from backend.app.models.event import Event
from backend.app.models.model_version import ModelVersion
from backend.app.models.prevention_action import PreventionAction
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.system_log import SystemLog
from backend.app.models.user import User

__all__ = [
    "User",
    "Event",
    "Detection",
    "RiskAssessment",
    "AttackNode",
    "AttackEdge",
    "ModelVersion",
    "SystemLog",
    "PreventionAction",
]
