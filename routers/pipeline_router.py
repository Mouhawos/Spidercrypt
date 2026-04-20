"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Router Pipeline Chiffrement                         ║
║   Routes : /pipeline/info · /pipeline/schemas · /pipeline/encrypt-demo     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import base64
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.dependencies import verify_api_key

router = APIRouter(
    prefix="/pipeline",
    tags=["Pipeline Chiffrement"],
    dependencies=[Depends(verify_api_key)],
)


class PipelineRunRequest(BaseModel):
    schema_name: str = "transactions"
    n_records:   int = 100
    master_key_b64: str | None = None  # Clé optionnelle (générée si absente)


# ── GET /pipeline/info ────────────────────────────────────────────────────────

@router.get(
    "/info",
    summary="Informations sur le pipeline de chiffrement",
)
async def pipeline_info() -> dict:
    return {
        "engine":     "SpiderCrypt Pipeline (Pandas + Avro)",
        "encryption": "ChaCha20-Poly1305",
        "formats":    ["Avro", "Parquet", "CSV"],
        "schemas":    ["transactions", "audit_events"],
        "features": [
            "Chiffrement par champ avec clé maître",
            "Schémas Avro auto-générés",
            "Hash RGPD des champs PII",
            "Traitement par batch configurable",
            "Export chiffré Parquet/Avro",
        ],
        "compliance": ["RGPD Art.25", "RGPD Art.30", "ISO 27001"],
    }


# ── GET /pipeline/schemas ─────────────────────────────────────────────────────

@router.get(
    "/schemas",
    summary="Schémas Avro disponibles dans le pipeline",
)
async def list_avro_schemas() -> dict:
    try:
        from services.pipeline_service import AVRO_SCHEMAS
        return {
            "schemas": {
                name: {
                    "name":   schema.get("name"),
                    "fields": [f["name"] for f in schema.get("fields", [])],
                }
                for name, schema in AVRO_SCHEMAS.items()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── POST /pipeline/encrypt-demo ───────────────────────────────────────────────

@router.post(
    "/encrypt-demo",
    summary="Démonstration du chiffrement ChaCha20-Poly1305",
    description=(
        "Génère N enregistrements synthétiques, les chiffre avec ChaCha20-Poly1305 "
        "et retourne un aperçu des données avant/après chiffrement."
    ),
)
async def encrypt_demo(body: PipelineRunRequest) -> dict:
    if body.n_records > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1 000 enregistrements pour la démo.")

    try:
        from services.synthetic_service import SyntheticDataFactory
        from services.pipeline_service import SpidercryptPipeline

        # Clé maître : utiliser celle fournie ou en générer une
        if body.master_key_b64:
            key_b64 = body.master_key_b64
        else:
            raw_key = os.urandom(32)
            key_b64 = base64.b64encode(raw_key).decode()

        # Générer les données
        factory  = SyntheticDataFactory(locale="fr_FR", seed=42)
        df       = factory.generate(body.schema_name, n=body.n_records)

        # Pipeline de chiffrement
        pipeline = SpidercryptPipeline(master_key_b64=key_b64)
        result   = pipeline.process_dataframe(df, schema_name=body.schema_name)

        # Retourner un aperçu (5 premières lignes) avant et après
        plain_sample     = df.head(5).to_dict(orient="records")
        encrypted_sample = result.head(5).to_dict(orient="records")

        return {
            "schema":            body.schema_name,
            "n_records":         body.n_records,
            "encryption":        "ChaCha20-Poly1305",
            "master_key_b64":    key_b64,  # ⚠️ démo seulement — ne jamais exposer en prod
            "plain_sample":      plain_sample,
            "encrypted_sample":  encrypted_sample,
            "columns_encrypted": [
                c for c in result.columns if "_enc" in c or "_hash" in c
            ],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur pipeline : {e}")