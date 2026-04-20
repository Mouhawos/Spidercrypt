"""
Router Pipeline — Chiffrement ChaCha20-Poly1305, traitement CSV/Parquet/Avro.
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional
import io, os, sys, tempfile, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from auth import verify_api_key
from spidercrypt_pandas import SpidercryptPipeline, SpidercryptCrypto, generate_master_key

router = APIRouter()

# Clé par défaut pour la démo (en prod : charger depuis un vault)
_DEFAULT_KEY = os.environ.get(
    "SPIDERCRYPT_MASTER_KEY",
    SpidercryptCrypto.generate_key_b64()
)


# ── Schémas Pydantic ──────────────────────────────────────────────────────────

class EncryptTextRequest(BaseModel):
    plaintext:   str
    master_key:  Optional[str] = None
    aad:         str = "spidercrypt"

class DecryptRequest(BaseModel):
    ciphertext_b64: str
    master_key:     Optional[str] = None
    aad:            str = "spidercrypt"

class PiiStrategyRequest(BaseModel):
    strategy:    str = "encrypt"   # encrypt | hash | drop
    master_key:  Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/key/generate", summary="Générer une nouvelle Master Key 256-bit")
async def generate_key(_: dict = Depends(verify_api_key)):
    """
    Génère une Master Key aléatoire 256-bit encodée en Base64.
    ⚠️  Ne jamais stocker en clair — utiliser un gestionnaire de secrets.
    """
    key = SpidercryptCrypto.generate_key_b64()
    return {
        "master_key_b64": key,
        "bits": 256,
        "algorithm": "ChaCha20-Poly1305",
        "warning": "Stocker dans SPIDERCRYPT_MASTER_KEY ou un vault sécurisé.",
    }


@router.post("/encrypt/text", summary="Chiffrer un texte avec ChaCha20-Poly1305")
async def encrypt_text(req: EncryptTextRequest, _: dict = Depends(verify_api_key)):
    """
    Chiffre un texte en clair avec ChaCha20-Poly1305.
    Retourne le ciphertext encodé en Base64.
    """
    try:
        key    = req.master_key or _DEFAULT_KEY
        crypto = SpidercryptCrypto(key)
        ct     = crypto.encrypt(req.plaintext, req.aad.encode())
        return {
            "ciphertext_b64": base64.b64encode(ct).decode(),
            "algorithm": "ChaCha20-Poly1305",
            "aad": req.aad,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/decrypt/text", summary="Déchiffrer un ciphertext ChaCha20-Poly1305")
async def decrypt_text(req: DecryptRequest, _: dict = Depends(verify_api_key)):
    """Déchiffre un ciphertext Base64 avec la Master Key fournie."""
    try:
        key    = req.master_key or _DEFAULT_KEY
        crypto = SpidercryptCrypto(key)
        ct     = base64.b64decode(req.ciphertext_b64)
        plain  = crypto.decrypt(ct, req.aad.encode())
        return {"plaintext": plain.decode("utf-8")}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Déchiffrement échoué : {e}")


@router.post("/process/csv", summary="Traiter un CSV — pseudonymisation + chiffrement PII")
async def process_csv(
    file: UploadFile = File(...),
    strategy: str = "hash",       # encrypt | hash | drop
    master_key: Optional[str] = None,
    _: dict = Depends(verify_api_key),
):
    """
    Charge un CSV, détecte et protège les colonnes PII (email, phone, name…).

    **Strategies :**
    - `hash` : SHA-256 irréversible (pseudonymisation RGPD)
    - `encrypt` : ChaCha20-Poly1305 réversible
    - `drop` : suppression de la colonne
    """
    import pandas as pd

    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Fichier CSV requis")

    content = await file.read()
    try:
        import io
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur lecture CSV : {e}")

    key      = master_key or _DEFAULT_KEY
    pipeline = SpidercryptPipeline(master_key_b64=key)
    df_sec   = pipeline.encrypt_pii_columns(df, strategy=strategy)

    # Retourner le résultat en CSV
    output = io.StringIO()
    df_sec.to_csv(output, index=False)
    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=secure_{file.filename}"},
    )


@router.post("/process/report", summary="Rapport de traitement d'un CSV")
async def process_report(
    file: UploadFile = File(...),
    _: dict = Depends(verify_api_key),
):
    """
    Analyse un CSV et retourne un rapport JSON :
    colonnes détectées, colonnes PII, statistiques, audit trail.
    """
    import pandas as pd, io

    content = await file.read()
    df = pd.read_csv(io.BytesIO(content))

    pipeline = SpidercryptPipeline(master_key_b64=_DEFAULT_KEY)

    pii_cols = [
        c for c in df.columns
        if any(pii in c.lower() for pii in pipeline.PII_COLUMNS)
    ]

    return {
        "filename":    file.filename,
        "rows":        len(df),
        "columns":     list(df.columns),
        "pii_columns": pii_cols,
        "dtypes":      {c: str(df[c].dtype) for c in df.columns},
        "null_counts": {c: int(df[c].isna().sum()) for c in df.columns},
        "recommendation": (
            f"{len(pii_cols)} colonnes PII détectées. "
            "Utiliser /process/csv avec strategy=hash ou encrypt avant tout partage."
        ),
    }
