"""Health check endpoints — pas d'authentification requise."""

from fastapi import APIRouter
from datetime import datetime, timezone

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Health check")
async def health_check():
    return {
        "status": "healthy",
        "service": "SpiderCrypt Enterprise API",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "modules": {
            "zerotrust":   "operational",
            "investigation": "operational",
            "pipeline":    "operational",
            "synthetic":   "operational",
            "timeseries":  "operational",
        },
    }


@router.get("/health/ready", summary="Readiness check")
async def readiness():
    return {"ready": True, "timestamp": datetime.now(timezone.utc).isoformat()}
