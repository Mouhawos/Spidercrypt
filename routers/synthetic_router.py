"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Router Données Synthétiques                         ║
║   Routes : /synthetic/generate · /synthetic/schemas · /synthetic/preview   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from core.dependencies import verify_api_key
from core.schemas import SyntheticGenerateRequest
from services.synthetic_service import SyntheticDataFactory

router = APIRouter(
    prefix="/synthetic",
    tags=["Données Synthétiques"],
    dependencies=[Depends(verify_api_key)],
)

AVAILABLE_SCHEMAS = ["transactions", "audit_events", "users", "api_keys"]


# ── GET /synthetic/schemas ────────────────────────────────────────────────────

@router.get(
    "/schemas",
    summary="Lister les schémas disponibles",
)
async def list_schemas() -> dict:
    return {
        "schemas": AVAILABLE_SCHEMAS,
        "description": {
            "transactions":  "Transactions financières PME françaises (SEPA, Stripe…)",
            "audit_events":  "Événements d'audit de sécurité (LOGIN, WRITE, DELETE…)",
            "users":         "Profils utilisateurs anonymisés RGPD",
            "api_keys":      "Clés API avec métadonnées de rotation",
        },
    }


# ── POST /synthetic/generate ──────────────────────────────────────────────────

@router.post(
    "/generate",
    response_model=None,
    summary="Générer des données synthétiques",
    description=(
        "Génère N enregistrements synthétiques RGPD-ready selon le schéma choisi. "
        "Formats disponibles : json, csv."
    ),
)
async def generate_data(body: SyntheticGenerateRequest):
    if body.schema_name not in AVAILABLE_SCHEMAS:
        raise HTTPException(
            status_code=400,
            detail=f"Schéma inconnu. Disponibles : {AVAILABLE_SCHEMAS}",
        )
    if body.n > 10_000:
        raise HTTPException(status_code=400, detail="Maximum 10 000 enregistrements par appel.")

    try:
        factory = SyntheticDataFactory(locale=body.locale, seed=body.seed)
        df      = factory.generate(body.schema_name, n=body.n)

        if body.format == "csv":
            csv_content = df.to_csv(index=False)
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename=spidercrypt_{body.schema_name}.csv"
                },
            )

        # JSON par défaut
        records = df.to_dict(orient="records")
        return {
            "schema":   body.schema_name,
            "n":        len(records),
            "locale":   body.locale,
            "seed":     body.seed,
            "records":  records,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur génération : {e}")


# ── GET /synthetic/preview ────────────────────────────────────────────────────

@router.get(
    "/preview/{schema_name}",
    summary="Aperçu de 5 enregistrements synthétiques",
)
async def preview_schema(schema_name: str) -> dict:
    if schema_name not in AVAILABLE_SCHEMAS:
        raise HTTPException(
            status_code=404,
            detail=f"Schéma inconnu. Disponibles : {AVAILABLE_SCHEMAS}",
        )
    try:
        factory = SyntheticDataFactory(locale="fr_FR", seed=0)
        df      = factory.generate(schema_name, n=5)
        return {
            "schema":  schema_name,
            "columns": list(df.columns),
            "sample":  df.to_dict(orient="records"),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))