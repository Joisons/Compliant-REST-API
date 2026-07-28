"""Unauthenticated liveness/readiness endpoint -- standard for load balancers
and container orchestrators, and deliberately excluded from RBAC so it can
be polled without a token."""
from datetime import datetime, timezone
from fastapi import APIRouter

from app.config import get_settings

router = APIRouter(tags=["Health"])
settings = get_settings()


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
