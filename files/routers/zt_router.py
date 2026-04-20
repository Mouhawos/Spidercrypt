"""
Router Zero-Trust — NIST SP 800-207
Endpoints pour évaluer les requêtes d'accès, gérer les sessions et la flotte d'appareils.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from auth import verify_api_key
from zerotrust import (
    ZeroTrustEngine, ZeroTrustRequest, IdentityContext, DeviceContext,
    NetworkContext, ResourceRequest, Verdict,
)

router = APIRouter()

# Instance partagée du moteur (singleton par service)
_engine = ZeroTrustEngine()
_fleet  = _engine.devices.generate_demo_fleet(n=10)


# ── Schémas Pydantic ──────────────────────────────────────────────────────────

class IdentityIn(BaseModel):
    user_id:           str
    roles:             list[str] = []
    auth_method:       str = "PASSWORD"
    mfa_verified:      bool = False
    session_id:        Optional[str] = None
    session_age_min:   float = 0
    failed_attempts:   int = 0
    risk_score:        float = 0.0
    last_login_ip:     Optional[str] = None
    last_login_time:   Optional[str] = None
    is_service_account: bool = False

class DeviceIn(BaseModel):
    device_id:    str
    is_managed:   bool = False
    is_compliant: bool = False
    os_type:      str = "UNKNOWN"
    os_version:   str = "UNKNOWN"
    certificate:  Optional[str] = None
    trust_score:  float = 0.5

class NetworkIn(BaseModel):
    ip_address:  str
    asn:         Optional[str] = None
    country:     Optional[str] = None
    city:        Optional[str] = None
    is_vpn:      bool = False
    is_tor:      bool = False
    is_proxy:    bool = False
    is_corporate: bool = False
    user_agent:  Optional[str] = None
    tls_version: str = "TLS1.3"

class ResourceIn(BaseModel):
    resource_id:   str
    resource_type: str = "DOCUMENT"
    sensitivity:   str = "INTERNAL"
    action:        str = "READ"
    is_bulk:       bool = False
    data_volume_mb: float = 0.0

class EvaluateRequest(BaseModel):
    identity: IdentityIn
    device:   DeviceIn
    network:  NetworkIn
    resource: ResourceIn

class DeviceRegisterIn(BaseModel):
    device_id:    str
    is_managed:   bool = True
    is_compliant: bool = True
    os_type:      str = "WINDOWS"
    os_version:   str = "latest"
    certificate:  Optional[str] = None
    trust_score:  float = 0.8


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/evaluate", summary="Évaluer une requête d'accès Zero-Trust")
async def evaluate(req: EvaluateRequest, _: dict = Depends(verify_api_key)):
    """
    Évalue une requête d'accès selon les 5 piliers Zero-Trust (NIST SP 800-207).

    Retourne : verdict (ALLOW/DENY/CHALLENGE_MFA/STEP_UP/QUARANTINE),
    score de confiance (0-100), facteurs de risque et violations de politique.
    """
    zt_request = ZeroTrustRequest(
        identity=IdentityContext(
            user_id=req.identity.user_id,
            roles=req.identity.roles,
            auth_method=req.identity.auth_method,
            mfa_verified=req.identity.mfa_verified,
            session_id=req.identity.session_id,
            session_age_min=req.identity.session_age_min,
            failed_attempts=req.identity.failed_attempts,
            risk_score=req.identity.risk_score,
            last_login_ip=req.identity.last_login_ip,
            last_login_time=req.identity.last_login_time,
            is_service_account=req.identity.is_service_account,
        ),
        device=DeviceContext(
            device_id=req.device.device_id,
            is_managed=req.device.is_managed,
            is_compliant=req.device.is_compliant,
            os_type=req.device.os_type,
            os_version=req.device.os_version,
            certificate=req.device.certificate,
            trust_score=req.device.trust_score,
        ),
        network=NetworkContext(
            ip_address=req.network.ip_address,
            asn=req.network.asn,
            country=req.network.country,
            city=req.network.city,
            is_vpn=req.network.is_vpn,
            is_tor=req.network.is_tor,
            is_proxy=req.network.is_proxy,
            is_corporate=req.network.is_corporate,
            user_agent=req.network.user_agent,
            tls_version=req.network.tls_version,
        ),
        resource=ResourceRequest(
            resource_id=req.resource.resource_id,
            resource_type=req.resource.resource_type,
            sensitivity=req.resource.sensitivity,
            action=req.resource.action,
            is_bulk=req.resource.is_bulk,
            data_volume_mb=req.resource.data_volume_mb,
        ),
    )

    decision = _engine.evaluate(zt_request)
    return decision.to_dict()


@router.post("/demo/evaluate", summary="Évaluer un scénario d'attaque de démonstration")
async def demo_evaluate(_: dict = Depends(verify_api_key)):
    """Lance le scénario d'attaque de démonstration (Tor + compte verrouillé + ressource SECRET)."""
    from spidercrypt_zerotrust import IdentityContext, DeviceContext, NetworkContext, ResourceRequest
    attack = ZeroTrustRequest(
        identity=IdentityContext(
            user_id="usr_hacker", roles=["analyst"],
            auth_method="PASSWORD", mfa_verified=False, failed_attempts=7,
        ),
        device=DeviceContext(device_id="UNKNOWN-DEVICE"),
        network=NetworkContext(ip_address="185.220.101.45", is_tor=True, country="RU"),
        resource=ResourceRequest(
            resource_id="secret-keys-vault",
            resource_type="API_KEY", sensitivity="SECRET", action="EXPORT",
        ),
    )
    decision = _engine.evaluate(attack)
    return decision.to_dict()


@router.get("/stats", summary="Statistiques globales du moteur Zero-Trust")
async def get_stats(_: dict = Depends(verify_api_key)):
    """Retourne les statistiques agrégées : total requêtes, taux de refus, score moyen."""
    return _engine.get_stats()


@router.get("/audit-log", summary="Journal d'audit immuable")
async def get_audit_log(limit: int = 100, _: dict = Depends(verify_api_key)):
    """Retourne les dernières entrées du journal d'audit (conformité RGPD Art.30)."""
    log = _engine.get_audit_log()
    return {"total": len(log), "entries": log[-limit:]}


@router.post("/devices/register", summary="Enregistrer un appareil dans le MDM")
async def register_device(device: DeviceRegisterIn, _: dict = Depends(verify_api_key)):
    """Enregistre un nouvel appareil dans le registre MDM/EMM."""
    from spidercrypt_zerotrust import DeviceContext
    d = DeviceContext(
        device_id=device.device_id,
        is_managed=device.is_managed,
        is_compliant=device.is_compliant,
        os_type=device.os_type,
        os_version=device.os_version,
        certificate=device.certificate,
        trust_score=device.trust_score,
    )
    fp = _engine.devices.register(d)
    return {"device_id": device.device_id, "fingerprint": fp, "registered": True}


@router.get("/devices/{device_id}", summary="Vérifier l'état d'un appareil")
async def get_device(device_id: str, _: dict = Depends(verify_api_key)):
    """Retourne le statut d'enregistrement et de conformité d'un appareil."""
    device = _engine.devices.lookup(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Appareil '{device_id}' introuvable")
    return {
        "device_id":    device.device_id,
        "is_registered": True,
        "is_managed":   device.is_managed,
        "is_compliant": device.is_compliant,
        "os_type":      device.os_type,
        "trust_score":  device.trust_score,
        "fingerprint":  device.fingerprint(),
    }


@router.get("/sessions/{user_id}", summary="Sessions actives d'un utilisateur")
async def get_user_sessions(user_id: str, _: dict = Depends(verify_api_key)):
    """Liste les sessions actives pour un utilisateur donné."""
    sessions = _engine.sessions.get_user_sessions(user_id)
    return {
        "user_id": user_id,
        "active_sessions": len(sessions),
        "sessions": [
            {
                "session_id":    s.session_id,
                "ip_address":    s.ip_address,
                "country":       s.country,
                "age_minutes":   round(s.age_minutes, 1),
                "trust_score":   s.trust_score,
                "mfa_verified":  s.mfa_verified,
                "is_quarantined": s.is_quarantined,
            }
            for s in sessions
        ],
    }
