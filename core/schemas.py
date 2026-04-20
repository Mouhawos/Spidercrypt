"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT ENTERPRISE — Schémas Pydantic (API I/O)               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


# ══════════════════════════════════════════════════════════════════════════════
# ZERO-TRUST — Schémas d'entrée
# ══════════════════════════════════════════════════════════════════════════════

class DeviceContextIn(BaseModel):
    device_id:    str
    is_managed:   bool  = False
    is_compliant: bool  = False
    os_type:      str   = "UNKNOWN"
    os_version:   str   = "UNKNOWN"
    certificate:  str | None = None
    trust_score:  float = 0.5

    model_config = {"json_schema_extra": {"example": {
        "device_id": "DEV-0001",
        "is_managed": True,
        "is_compliant": True,
        "os_type": "MACOS",
        "os_version": "14.4",
        "certificate": "cert_abc123",
        "trust_score": 0.9,
    }}}


class NetworkContextIn(BaseModel):
    ip_address:   str
    country:      str | None = None
    is_vpn:       bool = False
    is_tor:       bool = False
    is_proxy:     bool = False
    is_corporate: bool = False
    user_agent:   str | None = None
    tls_version:  str = "TLS1.3"


class IdentityContextIn(BaseModel):
    user_id:          str
    roles:            list[str] = []
    auth_method:      str   = "PASSWORD"
    mfa_verified:     bool  = False
    session_id:       str | None = None
    session_age_min:  float = 0.0
    failed_attempts:  int   = 0
    risk_score:       float = 0.0
    last_login_time:  str | None = None
    is_service_account: bool = False


class ResourceRequestIn(BaseModel):
    resource_id:   str
    resource_type: str   = "DOCUMENT"
    sensitivity:   str   = "INTERNAL"
    action:        str   = "READ"
    is_bulk:       bool  = False
    data_volume_mb: float = 0.0


class ZeroTrustEvaluateRequest(BaseModel):
    """Corps de la requête POST /zerotrust/evaluate"""
    identity: IdentityContextIn
    device:   DeviceContextIn
    network:  NetworkContextIn
    resource: ResourceRequestIn

    model_config = {"json_schema_extra": {"example": {
        "identity": {
            "user_id": "usr_0042",
            "roles": ["analyst"],
            "auth_method": "MFA_TOTP",
            "mfa_verified": True,
            "session_age_min": 30,
            "failed_attempts": 0,
            "risk_score": 0.1,
        },
        "device": {
            "device_id": "DEV-0001",
            "is_managed": True,
            "is_compliant": True,
            "os_type": "MACOS",
            "os_version": "14.4",
            "trust_score": 0.9,
        },
        "network": {
            "ip_address": "192.168.1.42",
            "country": "FR",
            "is_corporate": True,
            "tls_version": "TLS1.3",
        },
        "resource": {
            "resource_id": "doc-001",
            "resource_type": "DOCUMENT",
            "sensitivity": "CONFIDENTIAL",
            "action": "READ",
        },
    }}}


# ══════════════════════════════════════════════════════════════════════════════
# ZERO-TRUST — Schémas de sortie
# ══════════════════════════════════════════════════════════════════════════════

class ZeroTrustDecisionOut(BaseModel):
    request_id:       str
    decided_at:       str
    verdict:          str
    trust_score:      int
    risk_factors:     list[str]
    violations:       list[dict[str, Any]]
    ttl_seconds:      int
    session_bindings: dict[str, Any]
    recommendations:  list[str]
    context_hash:     str
    summary:          str


# ══════════════════════════════════════════════════════════════════════════════
# DEVICES — Schémas
# ══════════════════════════════════════════════════════════════════════════════

class DeviceRegisterRequest(BaseModel):
    device_id:    str
    is_managed:   bool  = True
    is_compliant: bool  = True
    os_type:      str   = "UNKNOWN"
    os_version:   str   = "UNKNOWN"
    certificate:  str | None = None
    trust_score:  float = 0.8


class DeviceRegisterResponse(BaseModel):
    device_id:   str
    fingerprint: str
    message:     str


# ══════════════════════════════════════════════════════════════════════════════
# INVESTIGATION — Schémas
# ══════════════════════════════════════════════════════════════════════════════

class InvestigationRequest(BaseModel):
    actor_id:   str
    days_back:  int = Field(default=30, ge=1, le=365)
    investigator: str = "API"

    model_config = {"json_schema_extra": {"example": {
        "actor_id": "usr_0042",
        "days_back": 7,
        "investigator": "SOC-Analyst-01",
    }}}


# ══════════════════════════════════════════════════════════════════════════════
# TIMESERIES — Schémas
# ══════════════════════════════════════════════════════════════════════════════

class TimeSeriesAnalyzeRequest(BaseModel):
    entity_id:    str
    window_hours: int = Field(default=24, ge=1, le=720)
    n_events:     int = Field(default=500, ge=10, le=10_000)

    model_config = {"json_schema_extra": {"example": {
        "entity_id": "usr_0042",
        "window_hours": 24,
        "n_events": 500,
    }}}


# ══════════════════════════════════════════════════════════════════════════════
# SYNTHETIC — Schémas
# ══════════════════════════════════════════════════════════════════════════════

class SyntheticGenerateRequest(BaseModel):
    schema_name: str = Field(
        default="transactions",
        description="transactions | audit_events | users | api_keys",
    )
    n:      int = Field(default=100, ge=1, le=50_000)
    seed:   int = Field(default=42)
    locale: str = Field(default="fr_FR")
    format: str = Field(default="json", description="json | csv | parquet")

    model_config = {"json_schema_extra": {"example": {
        "schema_name": "transactions",
        "n": 500,
        "seed": 42,
        "locale": "fr_FR",
        "format": "json",
    }}}


# ══════════════════════════════════════════════════════════════════════════════
# RÉPONSES GÉNÉRIQUES
# ══════════════════════════════════════════════════════════════════════════════

class HealthResponse(BaseModel):
    status:  str
    version: str
    engine:  str
    modules: list[str]


class StatsResponse(BaseModel):
    module:  str
    stats:   dict[str, Any]


class ErrorResponse(BaseModel):
    error:   str
    detail:  str
    code:    int