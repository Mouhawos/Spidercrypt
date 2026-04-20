"""SpiderCrypt Enterprise — dependency injection (Zero-Trust singletons, API key)."""

from __future__ import annotations

import os
from functools import lru_cache

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from core.config import Settings, get_settings
from core.zerotrust_engine import (
    ZeroTrustEngine,
    DeviceRegistry,
    SessionStore,
)


# ── Singletons (instanciés une seule fois au démarrage) ──────────────────────

@lru_cache
def get_device_registry() -> DeviceRegistry:
    """Registre MDM partagé entre toutes les requêtes."""
    registry = DeviceRegistry()
    # Pré-charge une flotte de démo
    registry.generate_demo_fleet(n=20)
    return registry


@lru_cache
def get_session_store(max_session_age_min: float) -> SessionStore:
    """Store de sessions Zero-Trust partagé (clé hashable : âge max session)."""
    return SessionStore(max_session_age_min=max_session_age_min)


@lru_cache
def get_zero_trust_engine_cached(
    allowed_countries: frozenset[str],
    corporate_ip_prefixes: tuple[str, ...],
    max_session_age_min: float,
) -> ZeroTrustEngine:
    """
    Moteur Zero-Trust singleton.
    Paramètres limités à des types hashables pour compatibilité avec lru_cache
    (Settings / BaseModel ne sont pas hashables).
    """
    # #region agent log
    from core.agent_debug_log import agent_log

    agent_log(
        "H5",
        "core/dependencies.py:get_zero_trust_engine_cached",
        "engine singleton resolved",
        {
            "countries_n": len(allowed_countries),
            "prefixes_n": len(corporate_ip_prefixes),
            "max_session_age_min": max_session_age_min,
        },
        run_id=os.getenv("AGENT_RUN_ID", "lru-fix"),
    )
    # #endregion
    return ZeroTrustEngine(
        device_registry       = get_device_registry(),
        session_store         = get_session_store(max_session_age_min),
        allowed_countries     = set(allowed_countries),
        corporate_ip_prefixes = list(corporate_ip_prefixes),
    )


def get_zero_trust_engine(
    settings: Settings = Depends(get_settings),
) -> ZeroTrustEngine:
    return get_zero_trust_engine_cached(
        frozenset(settings.ZT_ALLOWED_COUNTRIES),
        tuple(settings.ZT_CORPORATE_IP_PREFIXES),
        float(settings.ZT_MAX_SESSION_AGE_MIN),
    )


# ── Authentification API Key ──────────────────────────────────────────────────

_api_key_header = APIKeyHeader(name="X-SpiderCrypt-Key", auto_error=False)


async def verify_api_key(
    api_key: str | None = Security(_api_key_header),
    settings: Settings  = Depends(get_settings),
) -> str:
    """
    Vérifie la clé API dans l'en-tête X-SpiderCrypt-Key.
    Retourne la clé validée ou lève une HTTPException 401.
    """
    if not api_key or api_key not in settings.ALLOWED_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé API manquante ou invalide. Fournir X-SpiderCrypt-Key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key
