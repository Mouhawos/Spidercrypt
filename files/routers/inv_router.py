"""
Router Investigation — Timeline, corrélation, détection d'anomalies, rapport RGPD.
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional
import io, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

import pandas as pd
from auth import verify_api_key
from spidercrypt_investigation import InvestigationEngine
from spidercrypt_synthetic import SyntheticDataFactory

router = APIRouter()

# Instance partagée
_engine = InvestigationEngine()

# Données synthétiques pré-chargées pour la démo
_factory = SyntheticDataFactory(seed=42)
_demo_audit = _factory.generate("audit_events", n=500)
_demo_tx    = _factory.generate("transactions",  n=200)
_engine.load_audit_events(_demo_audit)
_engine.load_transactions(_demo_tx)


# ── Schémas Pydantic ──────────────────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    actor_id:    Optional[str] = None
    resource_id: Optional[str] = None
    days_back:   int = 30
    investigator_name: str = "SpidercryptAPI/1.0"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/investigate", summary="Lancer une investigation sur un acteur ou ressource")
async def investigate(req: InvestigateRequest, _: dict = Depends(verify_api_key)):
    """
    Lance une investigation complète :
    - Construction de la timeline (audit + transactions)
    - Détection d'anomalies (brute force, exports massifs, hors-heures…)
    - Évaluation du risque (FAIBLE / MODÉRÉ / ÉLEVÉ / CRITIQUE)
    - Signature SHA-256 du rapport

    Utilise les données de démonstration synthétiques pré-chargées.
    """
    if not req.actor_id and not req.resource_id:
        raise HTTPException(status_code=400, detail="actor_id ou resource_id requis")

    report = _engine.investigate(
        actor_id=req.actor_id,
        resource_id=req.resource_id,
        days_back=req.days_back,
        investigator_name=req.investigator_name,
    )
    return report.to_dict()


@router.get("/demo/actors", summary="Liste les acteurs disponibles dans les données de démo")
async def list_demo_actors(_: dict = Depends(verify_api_key)):
    """Retourne un échantillon d'acteurs présents dans les données synthétiques de démo."""
    actors = _demo_audit["acteur_id"].unique().tolist()
    return {
        "total_actors": len(actors),
        "sample": actors[:20],
        "hint": "Utilisez l'un de ces actor_id dans /investigate",
    }


@router.post("/upload/audit-events", summary="Charger des événements d'audit CSV/Parquet")
async def upload_audit_events(
    file: UploadFile = File(...),
    _: dict = Depends(verify_api_key),
):
    """
    Charge vos propres événements d'audit (CSV ou Parquet).
    Colonnes attendues : event_id, timestamp_ms, acteur_id, action, succes, severite…
    """
    content = await file.read()
    ext = file.filename.split(".")[-1].lower()

    if ext == "csv":
        df = pd.read_csv(io.BytesIO(content))
    elif ext == "parquet":
        df = pd.read_parquet(io.BytesIO(content))
    else:
        raise HTTPException(status_code=400, detail="Format non supporté. Utilisez CSV ou Parquet.")

    _engine.load_audit_events(df)
    return {
        "loaded": True,
        "rows": len(df),
        "columns": list(df.columns),
        "filename": file.filename,
    }


@router.post("/upload/transactions", summary="Charger des transactions CSV/Parquet")
async def upload_transactions(
    file: UploadFile = File(...),
    _: dict = Depends(verify_api_key),
):
    """Charge vos propres transactions financières (CSV ou Parquet)."""
    content = await file.read()
    ext = file.filename.split(".")[-1].lower()

    if ext == "csv":
        df = pd.read_csv(io.BytesIO(content))
    elif ext == "parquet":
        df = pd.read_parquet(io.BytesIO(content))
    else:
        raise HTTPException(status_code=400, detail="Format non supporté. Utilisez CSV ou Parquet.")

    _engine.load_transactions(df)
    return {
        "loaded": True,
        "rows": len(df),
        "columns": list(df.columns),
        "filename": file.filename,
    }
