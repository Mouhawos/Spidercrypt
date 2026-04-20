"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Router Séries Temporelles                           ║
║   Routes : /timeseries/analyze · /timeseries/stream/demo · /anomalies      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from core.dependencies import verify_api_key
from core.schemas import TimeSeriesAnalyzeRequest, StatsResponse
from services.timeseries_service import CyberTimeSeriesFactory, TimeSeriesEngine

router = APIRouter(
    prefix="/timeseries",
    tags=["Séries Temporelles"],
    dependencies=[Depends(verify_api_key)],
)


def _get_engine() -> TimeSeriesEngine:
    return TimeSeriesEngine()


# ── POST /timeseries/analyze ──────────────────────────────────────────────────

@router.post(
    "/analyze",
    summary="Analyser les séries temporelles d'un entité",
    description=(
        "Ingère un flux d'événements synthétiques, détecte les anomalies "
        "(spike, drift, level_shift…) et retourne un rapport forensic complet."
    ),
)
async def analyze_timeseries(body: TimeSeriesAnalyzeRequest) -> dict:
    engine = _get_engine()

    try:
        factory = CyberTimeSeriesFactory(seed=min(body.n_events, 2**31 - 1))
        for stream in factory.generate_full_scenario(body.entity_id, "normal"):
            engine.ingest(stream)

        report = engine.analyze(
            entity_id    = body.entity_id,
            window_hours = body.window_hours,
        )
        return report.to_dict()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur analyse : {e}")


# ── GET /timeseries/demo ──────────────────────────────────────────────────────

@router.get(
    "/demo",
    summary="Démonstration rapide séries temporelles",
    description="Génère et analyse 500 événements pour l'entité spécifiée.",
)
async def demo_timeseries(
    entity_id:    str = "usr_0042",
    window_hours: int = 24,
) -> dict:
    engine = _get_engine()

    try:
        factory = CyberTimeSeriesFactory(seed=42)
        for stream in factory.generate_full_scenario(entity_id, "normal"):
            engine.ingest(stream)
        report = engine.analyze(entity_id=entity_id, window_hours=window_hours)

        return {
            "entity_id":         entity_id,
            "window_hours":      window_hours,
            "streams_analyzed":  report.streams_analyzed,
            "alert_count":       len(report.alerts),
            "risk_score":        report.risk_score,
            "risk_level":        report.risk_level,
            "top_alerts":        report.alerts[:5],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /timeseries/stats ─────────────────────────────────────────────────────

@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Statistiques du moteur de séries temporelles",
)
async def get_stats() -> StatsResponse:
    engine = _get_engine()
    return StatsResponse(
        module="timeseries",
        stats={
            "signal_types":  [s.value for s in engine.SIGNAL_TYPES] if hasattr(engine, "SIGNAL_TYPES") else [],
            "status":        "operational",
        },
    )