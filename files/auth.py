"""
Authentification par API Key pour SpiderCrypt Enterprise API.
En production : utiliser un gestionnaire de secrets (HashiCorp Vault, AWS Secrets Manager).
"""

import os
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# En production : charger depuis les variables d'environnement / vault
VALID_API_KEYS: dict[str, dict] = {
    os.environ.get("SPIDERCRYPT_API_KEY", "spidercrypt-dev-key-1234"): {
        "name": "dev-key",
        "roles": ["admin"],
        "rate_limit": 1000,
    },
    "spidercrypt-readonly-key-5678": {
        "name": "readonly-key",
        "roles": ["reader"],
        "rate_limit": 100,
    },
}


async def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> dict:
    """
    Dépendance FastAPI pour valider la clé API.
    Retourne le profil associé à la clé si valide.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header X-API-Key manquant",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Clé API invalide ou révoquée",
        )
    return VALID_API_KEYS[api_key]
