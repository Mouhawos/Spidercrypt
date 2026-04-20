"""
Router Données Synthétiques — Génération RGPD-ready multi-schémas.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional
import io, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from auth import verify_api_key
from spidercrypt_synthetic import SyntheticDataFactory

router = APIRouter()

VALID_SCHEMAS = ["transactions", "contacts", "audit_events", "entreprises"]


# ── Schémas Pydantic ──────────────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    schema_name:   str = "transactions"
    n:             int = 100
    seed:          Optional[int] = 42
    locale:        str = "fr_FR"
    anomaly_rate:  float = 0.03   # pour transactions
    failure_rate:  float = 0.06   # pour audit_events

class SuiteRequest(BaseModel):
    n_entreprises:  int = 20
    n_contacts_per: int = 4
    n_transactions: int = 500
    n_audit_events: int = 200
    seed:           Optional[int] = 42


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/schemas", summary="Liste des schémas disponibles")
async def list_schemas(_: dict = Depends(verify_api_key)):
    """Retourne la liste des schémas de génération disponibles avec leur description."""
    return {
        "schemas": {
            "transactions":  "Transactions financières PME françaises (montants, marchands, anomalies)",
            "contacts":      "Contacts PME avec données personnelles synthétiques",
            "audit_events":  "Événements d'audit système (LOGIN, EXPORT, CONFIG_CHANGE…)",
            "entreprises":   "Profils d'entreprises PME françaises (SIRET, CA, banque…)",
        }
    }


@router.post("/generate", summary="Générer des données synthétiques")
async def generate(req: GenerateRequest, _: dict = Depends(verify_api_key)):
    """
    Génère N enregistrements synthétiques selon le schéma demandé.
    Retourne un JSON avec les données et les métadonnées de génération.

    **Limites :** max 10 000 enregistrements par appel.
    """
    if req.schema_name not in VALID_SCHEMAS:
        raise HTTPException(
            status_code=400,
            detail=f"Schéma invalide. Disponibles : {VALID_SCHEMAS}"
        )
    if req.n > 10_000:
        raise HTTPException(status_code=400, detail="Maximum 10 000 enregistrements par appel")
    if req.n < 1:
        raise HTTPException(status_code=400, detail="n doit être >= 1")

    factory = SyntheticDataFactory(locale=req.locale, seed=req.seed)

    kwargs = {}
    if req.schema_name == "transactions":
        kwargs["anomaly_rate"] = req.anomaly_rate
    elif req.schema_name == "audit_events":
        kwargs["failure_rate"] = req.failure_rate

    df = factory.generate(req.schema_name, n=req.n, **kwargs)

    return {
        "schema":    req.schema_name,
        "n":         len(df),
        "columns":   list(df.columns),
        "locale":    req.locale,
        "seed":      req.seed,
        "records":   df.to_dict(orient="records"),
        "disclaimer": "DONNÉES 100% SYNTHÉTIQUES — Aucune donnée personnelle réelle. Conforme RGPD Art.25.",
    }


@router.post("/generate/csv", summary="Générer des données synthétiques au format CSV")
async def generate_csv(req: GenerateRequest, _: dict = Depends(verify_api_key)):
    """Génère des données synthétiques et les retourne en CSV téléchargeable."""
    if req.schema_name not in VALID_SCHEMAS:
        raise HTTPException(status_code=400, detail=f"Schéma invalide. Disponibles : {VALID_SCHEMAS}")
    if req.n > 10_000:
        raise HTTPException(status_code=400, detail="Maximum 10 000 enregistrements par appel")

    factory = SyntheticDataFactory(locale=req.locale, seed=req.seed)
    df      = factory.generate(req.schema_name, n=req.n)

    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=synthetic_{req.schema_name}_{req.n}.csv"},
    )


@router.post("/generate/suite", summary="Générer une suite complète de datasets liés")
async def generate_suite(req: SuiteRequest, _: dict = Depends(verify_api_key)):
    """
    Génère un ensemble cohérent de datasets liés :
    entreprises → contacts → transactions → audit_events.

    Idéal pour des tests d'intégration ou des démos clients.
    """
    factory = SyntheticDataFactory(seed=req.seed)
    datasets = factory.generate_suite(
        n_entreprises=req.n_entreprises,
        n_contacts_per=req.n_contacts_per,
        n_transactions=req.n_transactions,
        n_audit_events=req.n_audit_events,
        output_dir="/tmp/spidercrypt_suite",
    )

    return {
        "generated": {
            name: {"rows": len(df), "columns": len(df.columns)}
            for name, df in datasets.items()
        },
        "seed":       req.seed,
        "disclaimer": "DONNÉES 100% SYNTHÉTIQUES — Conforme RGPD Art.25.",
    }


@router.get("/describe/{schema_name}", summary="Décrire les colonnes d'un schéma")
async def describe_schema(schema_name: str, _: dict = Depends(verify_api_key)):
    """Génère 5 enregistrements de démo et décrit la structure du schéma."""
    if schema_name not in VALID_SCHEMAS:
        raise HTTPException(status_code=400, detail=f"Schéma invalide. Disponibles : {VALID_SCHEMAS}")

    factory = SyntheticDataFactory(seed=42)
    df      = factory.generate(schema_name, n=5)

    return {
        "schema":  schema_name,
        "columns": [
            {
                "name":    col,
                "dtype":   str(df[col].dtype),
                "example": str(df[col].iloc[0]),
                "nulls":   int(df[col].isna().sum()),
            }
            for col in df.columns
        ],
        "sample_records": df.head(3).to_dict(orient="records"),
    }
