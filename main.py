"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT ENTERPRISE — Point d'Entrée API                       ║
║   Never Trust · Always Verify · Least Privilege · Continuous Monitoring    ║
╚══════════════════════════════════════════════════════════════════════════════╝

Lancer l'API :
    uvicorn main:app --reload --port 8000

Documentation interactive :
    http://localhost:8000/docs      ← Swagger UI
    http://localhost:8000/redoc     ← ReDoc
"""

from __future__ import annotations

import logging
import os
import time
import sentry_sdk
import os

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN", "https://747dacd774d2302db1fa3acfcc5d8113@o4507865010864128.ingest.us.sentry.io/4511258500268032"),
    send_default_pii=True,
    traces_sample_rate=1.0,
    environment=os.getenv("ENV", "production"),
    release="spidercrypt@1.0.0",
)
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import get_settings
from core.schemas import HealthResponse

# ── Routers ──────────────────────────────────────────────────────────────────
from routers.zerotrust_router import router as zerotrust_router
from routers.zerotrust_router import devices_router
from routers.investigation_router import router as investigation_router
from routers.timeseries_router import router as timeseries_router
from routers.synthetic_router import router as synthetic_router
from routers.pipeline_router import router as pipeline_router


settings = get_settings()
logger = logging.getLogger("spidercrypt.api")


# ══════════════════════════════════════════════════════════════════════════════
# LIFESPAN — Initialisation & Nettoyage
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🕷️  SpiderCrypt Enterprise API — Démarrage...")
    print(f"   ENV      : {settings.ENV}")
    print(f"   DEBUG    : {settings.DEBUG}")
    print(f"   Modules  : Zero-Trust · Investigation · TimeSeries · Synthetic · Pipeline")
    print("   Statut   : ✅ Prêt\n")
    yield
    print("🕷️  SpiderCrypt Enterprise API — Arrêt propre.")


# ══════════════════════════════════════════════════════════════════════════════
# APPLICATION FASTAPI
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title       = settings.APP_NAME,
    version     = settings.APP_VERSION,
    description = settings.APP_DESCRIPTION,
    lifespan    = lifespan,
    docs_url    = "/docs" if settings.DEBUG else None,
    redoc_url   = "/redoc" if settings.DEBUG else None,
    openapi_tags= [
        {"name": "Zero-Trust",           "description": "Moteur NIST SP 800-207 — Never Trust, Always Verify"},
        {"name": "Devices (MDM)",         "description": "Registre des appareils de confiance"},
        {"name": "Investigation",         "description": "Parcours d'investigation forensic & RGPD"},
        {"name": "Séries Temporelles",    "description": "Détection d'anomalies temporelles cybersécurité"},
        {"name": "Données Synthétiques",  "description": "Génération RGPD-ready pour tests & ML"},
        {"name": "Pipeline Chiffrement",  "description": "Pipeline ChaCha20-Poly1305 + Avro"},
        {"name": "Santé",                 "description": "Health-check et méta-informations"},
    ],
)


# ══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARES
# ══════════════════════════════════════════════════════════════════════════════

app.add_middleware(
    CORSMiddleware,
    allow_origins     = settings.CORS_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    t0       = time.perf_counter()
    response = await call_next(request)
    elapsed  = time.perf_counter() - t0
    response.headers["X-Process-Time"] = f"{elapsed:.4f}s"
    response.headers["X-SpiderCrypt"]  = "Never-Trust-Always-Verify"
    return response


# ══════════════════════════════════════════════════════════════════════════════
# GESTIONNAIRE D'ERREURS GLOBAL
# ══════════════════════════════════════════════════════════════════════════════

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", exc_info=exc)
    # #region agent log
    from core.agent_debug_log import agent_log

    detail_str = str(exc)
    safe_detail = detail_str if settings.DEBUG else "An unexpected error occurred."
    agent_log(
        "H1",
        "main.py:global_exception_handler",
        "500 response shaping",
        {
            "exc_type": type(exc).__name__,
            "detail_len": len(detail_str),
            "detail_sent_to_client": detail_str[:120],
            "response_detail_preview": safe_detail[:120],
            "redacted": not settings.DEBUG,
        },
        run_id=os.getenv("AGENT_RUN_ID", "post-fix"),
    )
    # #endregion
    return JSONResponse(
        status_code=500,
        content={
            "error":  "internal_server_error",
            "detail": safe_detail,
            "path":   str(request.url),
        },
    )


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES DE SANTÉ (sans authentification)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health", response_model=HealthResponse, tags=["Santé"])
async def health_check() -> HealthResponse:
    return HealthResponse(
        status  = "ok",
        version = settings.APP_VERSION,
        engine  = "SpiderCrypt Enterprise",
        modules = ["zero-trust", "investigation", "timeseries", "synthetic", "pipeline"],
    )


@app.get("/", tags=["Santé"], include_in_schema=False)
async def root() -> dict:
    return {
        "name":    settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs":    "/docs" if settings.DEBUG else None,
        "health":  "/health",
        "motto":   "🕷️  Never Trust · Always Verify · Least Privilege",
    }


# ══════════════════════════════════════════════════════════════════════════════
# ENREGISTREMENT DES ROUTERS
# ══════════════════════════════════════════════════════════════════════════════

app.include_router(zerotrust_router)      # /zerotrust/*
app.include_router(devices_router)        # /devices/*
app.include_router(investigation_router)  # /investigation/*
app.include_router(timeseries_router)     # /timeseries/*
app.include_router(synthetic_router)      # /synthetic/*
app.include_router(pipeline_router)       # /pipeline/*


# #region agent log
if os.getenv("AGENT_INSTRUMENT_TEST") == "832300":

    @app.get("/__instrument/boom", include_in_schema=False)
    async def _agent_instrument_boom() -> None:
        raise RuntimeError("agent instrumentation deliberate failure")


# #endregion



# ══════════════════════════════════════════════════════════════════════════════
# ENTRÉE DIRECTE
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host    = "0.0.0.0",
        port    = 8000,
        reload  = settings.DEBUG,
        workers = 1,
    )