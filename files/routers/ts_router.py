"""
Router Séries Temporelles — Détection d'anomalies, UEBA, corrélation MITRE ATT&CK.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from auth import verify_api_key
from spidercrypt_timeseries import (
    TimeSeriesEngine, CyberTimeSeriesFactory,
    SignalType, DataPoint,
)

router = APIRouter()

# Instances partagées
_engine  = TimeSeriesEngine(sensitivity=1.2)
_factory = CyberTimeSeriesFactory(seed=42)

VALID_SCENARIOS  = ["apt", "ransomware", "insider", "ddos", "normal"]
VALID_SIGNAL_TYPES = [s.value for s in SignalType]


# ── Schémas Pydantic ──────────────────────────────────────────────────────────

class IngestPointRequest(BaseModel):
    entity_id:    str
    signal_type:  str
    value:        float
    timestamp_ms: Optional[int] = None
    tags:         dict = {}

class AnalyzeRequest(BaseModel):
    entity_id:        str
    window_hours:     int = 24
    include_forecast: bool = True

class ScenarioRequest(BaseModel):
    entity_id: str
    scenario:  str = "apt"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/signals", summary="Liste des types de signaux disponibles")
async def list_signals(_: dict = Depends(verify_api_key)):
    """Retourne tous les types de signaux supportés avec leur description."""
    descriptions = {
        "net_connections":  "Connexions réseau par seconde",
        "failed_logins":    "Tentatives de connexion échouées",
        "log_volume":       "Volume de logs (lignes/min)",
        "bytes_out":        "Trafic sortant (bytes/s)",
        "bytes_in":         "Trafic entrant (bytes/s)",
        "dns_queries":      "Requêtes DNS par minute",
        "process_spawns":   "Nouveaux processus créés",
        "file_ops":         "Opérations fichiers par seconde",
        "api_calls":        "Appels API par minute",
        "privilege_events": "Événements d'élévation de privilèges",
        "lateral_movement": "Tentatives de mouvement latéral",
        "crypto_ops":       "Opérations cryptographiques",
        "user_activity":    "Activité utilisateur globale",
    }
    return {"signals": descriptions}


@router.post("/ingest", summary="Ingérer un point de données temps réel")
async def ingest_point(req: IngestPointRequest, _: dict = Depends(verify_api_key)):
    """
    Ingère un point de mesure dans le moteur de séries temporelles.
    La baseline est recalculée automatiquement tous les 20 points.
    """
    if req.signal_type not in VALID_SIGNAL_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Signal invalide. Disponibles : {VALID_SIGNAL_TYPES}"
        )

    _engine.ingest_point(
        entity_id=req.entity_id,
        signal_type=SignalType(req.signal_type),
        value=req.value,
        timestamp_ms=req.timestamp_ms,
        tags=req.tags,
    )

    return {
        "ingested": True,
        "entity_id":   req.entity_id,
        "signal_type": req.signal_type,
        "value":       req.value,
    }


@router.post("/analyze", summary="Analyser les séries temporelles d'une entité")
async def analyze(req: AnalyzeRequest, _: dict = Depends(verify_api_key)):
    """
    Analyse complète des séries temporelles pour une entité :
    - Détection d'anomalies (Z-score, MAD, contextuel, beaconing, changepoints)
    - Corrélation multi-signaux (MITRE ATT&CK)
    - Prévision EWMA
    - Niveau de risque (FAIBLE / MODÉRÉ / ÉLEVÉ / CRITIQUE)
    """
    streams = _engine._streams.get(req.entity_id, {})
    if not streams:
        raise HTTPException(
            status_code=404,
            detail=f"Aucun stream pour '{req.entity_id}'. "
                   f"Utilisez /ingest ou /scenario pour charger des données."
        )

    report = _engine.analyze(req.entity_id, window_hours=req.window_hours,
                             include_forecast=req.include_forecast)
    return report.to_dict()


@router.post("/scenario", summary="Charger un scénario de démonstration")
async def load_scenario(req: ScenarioRequest, _: dict = Depends(verify_api_key)):
    """
    Charge un scénario de démonstration pré-généré dans le moteur.

    **Scénarios disponibles :**
    - `apt` : APT multi-étapes (brute force → mouvement latéral → exfiltration)
    - `ransomware` : Chiffrement de fichiers en cascade
    - `insider` : Menace interne avec activité nocturne
    - `ddos` : Attaque par déni de service distribué
    - `normal` : Trafic légitime (référence)
    """
    if req.scenario not in VALID_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Scénario invalide. Disponibles : {VALID_SCENARIOS}"
        )

    streams = _factory.generate_full_scenario(req.entity_id, req.scenario)

    if req.scenario == "apt":
        streams += _factory.generate_beaconing_scenario(req.entity_id)

    for stream in streams:
        _engine.ingest(stream)

    return {
        "loaded":      True,
        "entity_id":   req.entity_id,
        "scenario":    req.scenario,
        "streams":     len(streams),
        "total_points": sum(len(s) for s in streams),
        "signals": [s.signal_type.value for s in streams],
        "next_step": f"POST /timeseries/analyze avec entity_id='{req.entity_id}'",
    }


@router.get("/entities", summary="Liste des entités trackées")
async def list_entities(_: dict = Depends(verify_api_key)):
    """Retourne toutes les entités connues du moteur avec leurs signaux actifs."""
    entities = []
    for eid, signals in _engine._streams.items():
        entities.append({
            "entity_id": eid,
            "signals": [s.value for s in signals.keys()],
            "total_points": sum(len(st) for st in signals.values()),
        })
    return {"total": len(entities), "entities": entities}


@router.get("/stats", summary="Statistiques globales du moteur TS")
async def get_stats(_: dict = Depends(verify_api_key)):
    """Retourne les statistiques globales du moteur de séries temporelles."""
    return _engine.get_stats()


@router.get("/mitre/catalog", summary="Catalogue MITRE ATT&CK utilisé")
async def mitre_catalog(_: dict = Depends(verify_api_key)):
    """Retourne le mapping SignalType → catégories de menaces → techniques MITRE ATT&CK."""
    from spidercrypt_timeseries import SIGNAL_THREAT_MAP, MITRE_TECHNIQUES, RECOMMENDED_ACTIONS
    result = {}
    for signal, threats in SIGNAL_THREAT_MAP.items():
        result[signal.value] = [
            {
                "threat":      t.value,
                "mitre":       MITRE_TECHNIQUES.get(t, []),
                "action":      RECOMMENDED_ACTIONS.get(t, ""),
            }
            for t in threats
        ]
    return result
