"""Phase 7: controlled lab response (section 2 of the phase instructions).

    Detection -> Response Policy -> Response Adapter -> Action -> Audit Log -> Dashboard

Independent of the detection model: nothing here modifies ml/, attack_graph/,
or risk_engine/. Independent of the API layer too -- route handlers
(backend/app/api/v1/prevention.py) call response_service, never a
ResponseAdapter or shell/firewall command directly. See docs/prevention.md.
"""
