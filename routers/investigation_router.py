"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Router Investigation                                ║
║   Routes : /investigation/run · /investigation/timeline · /anomalies       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from core.dependencies import verify_api_key
from core.schemas import InvestigationRequest
from services.investigation_service import InvestigationEngine

router = APIRouter(
    prefix="/investigation",
    tags=["Investigation"],
    dependencies=[Depends(verify_api_key)],
)


def _get_engine() -> InvestigationEngine:
    """Instancie le moteur d'investigation (stateless entre appels)."""
    return InvestigationEngine()


# ── POST /investigation/run ───────────────────────────────────────────────────

@router.post(
    "/run",
    summary="Lancer une investigation sur un acteur",
    description=(
        "Analyse l'ensemble des événements d'audit et transactions liés à un acteur "
        "sur une fenêtre temporelle. Retourne un rapport complet avec timeline, "
        "anomalies détectées et évaluation du risque."
    ),
)
async def run_investigation(body: InvestigationRequest) -> dict:
    """
    Lance une investigation complète.
    Les données sont synthétiques si aucun fichier source n'est fourni.
    """
    engine = _get_engine()

    # Génère des données synthétiques de démonstration
    try:
        from services.synthetic_service import SyntheticDataFactory
        factory = SyntheticDataFactory(locale="fr_FR", seed=42)

        audit_df = factory.generate("audit_events", n=500)
        tx_df    = factory.generate("transactions",  n=500)

        # Filtrer sur l'acteur demandé pour la démo
        if "acteur_id" in audit_df.columns:
            # Injecter l'acteur dans quelques lignes pour garantir des résultats
            audit_df.iloc[:50, audit_df.columns.get_loc("acteur_id")] = body.actor_id

        engine.load_audit_events_df(audit_df)
        engine.load_transactions_df(tx_df)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors du chargement des données : {e}",
        )

    try:
        report = engine.investigate(
            actor_id = body.actor_id,
            days_back = body.days_back,
            investigator_name = body.investigator,
        )
        return report.to_dict()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur investigation : {e}",
        )


# ── GET /investigation/anomalies ──────────────────────────────────────────────

@router.get(
    "/anomalies/demo",
    summary="Démonstration des anomalies détectées",
    description="Génère et analyse 1 000 événements synthétiques, retourne les anomalies.",
)
async def demo_anomalies(actor_id: str = "usr_0042", days_back: int = 7) -> dict:
    engine = _get_engine()

    try:
        from services.synthetic_service import SyntheticDataFactory
        factory  = SyntheticDataFactory(locale="fr_FR", seed=99)
        audit_df = factory.generate("audit_events", n=1000)

        if "acteur_id" in audit_df.columns:
            audit_df.iloc[:100, audit_df.columns.get_loc("acteur_id")] = actor_id

        engine.load_audit_events_df(audit_df)

        report = engine.investigate(actor_id=actor_id, days_back=days_back)
        return {
            "actor_id":      actor_id,
            "days_back":     days_back,
            "anomaly_count": len(report.anomalies),
            "risk_level":    report.risk_assessment.get("niveau", "N/A"),
            "anomalies":     report.anomalies[:10],  # Max 10 pour la démo
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))