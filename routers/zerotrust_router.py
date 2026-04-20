"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Router Zero-Trust                                   ║
║   Routes : /zerotrust/evaluate · /devices · /sessions · /audit · /stats    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from core.dependencies import get_zero_trust_engine, get_device_registry, verify_api_key
from core.schemas import (
    ZeroTrustEvaluateRequest,
    ZeroTrustDecisionOut,
    DeviceRegisterRequest,
    DeviceRegisterResponse,
    StatsResponse,
)
from core.zerotrust_engine import (
    ZeroTrustEngine,
    DeviceRegistry,
    ZeroTrustRequest,
    IdentityContext,
    DeviceContext,
    NetworkContext,
    ResourceRequest,
)

router = APIRouter(
    prefix="/zerotrust",
    tags=["Zero-Trust"],
    dependencies=[Depends(verify_api_key)],
)


# ── POST /zerotrust/evaluate ──────────────────────────────────────────────────

@router.post(
    "/evaluate",
    response_model=ZeroTrustDecisionOut,
    summary="Évaluer une requête d'accès Zero-Trust",
    description=(
        "Soumet un contexte complet (identité, appareil, réseau, ressource) "
        "au moteur Zero-Trust. Retourne un verdict ALLOW | DENY | CHALLENGE_MFA "
        "| STEP_UP | QUARANTINE avec score de confiance et justifications."
    ),
)
async def evaluate_request(
    body:   ZeroTrustEvaluateRequest,
    engine: ZeroTrustEngine = Depends(get_zero_trust_engine),
) -> ZeroTrustDecisionOut:
    """
    Point d'entrée principal du moteur Zero-Trust.
    Chaque appel est indépendant — Never Trust, Always Verify.
    """
    # Mapper les schémas Pydantic vers les dataclasses internes
    zt_request = ZeroTrustRequest(
        identity = IdentityContext(
            user_id           = body.identity.user_id,
            roles             = body.identity.roles,
            auth_method       = body.identity.auth_method,
            mfa_verified      = body.identity.mfa_verified,
            session_id        = body.identity.session_id,
            session_age_min   = body.identity.session_age_min,
            failed_attempts   = body.identity.failed_attempts,
            risk_score        = body.identity.risk_score,
            last_login_time   = body.identity.last_login_time,
            is_service_account= body.identity.is_service_account,
        ),
        device = DeviceContext(
            device_id    = body.device.device_id,
            is_managed   = body.device.is_managed,
            is_compliant = body.device.is_compliant,
            os_type      = body.device.os_type,
            os_version   = body.device.os_version,
            certificate  = body.device.certificate,
            trust_score  = body.device.trust_score,
        ),
        network = NetworkContext(
            ip_address   = body.network.ip_address,
            country      = body.network.country,
            is_vpn       = body.network.is_vpn,
            is_tor       = body.network.is_tor,
            is_proxy     = body.network.is_proxy,
            is_corporate = body.network.is_corporate,
            user_agent   = body.network.user_agent,
            tls_version  = body.network.tls_version,
        ),
        resource = ResourceRequest(
            resource_id    = body.resource.resource_id,
            resource_type  = body.resource.resource_type,
            sensitivity    = body.resource.sensitivity,
            action         = body.resource.action,
            is_bulk        = body.resource.is_bulk,
            data_volume_mb = body.resource.data_volume_mb,
        ),
    )

    decision = engine.evaluate(zt_request)

    return ZeroTrustDecisionOut(
        request_id       = decision.request_id,
        decided_at       = decision.decided_at,
        verdict          = decision.verdict.value,
        trust_score      = decision.trust_score,
        risk_factors     = [r.value for r in decision.risk_factors],
        violations       = [
            {
                "policy_id":   v.policy_id,
                "policy_name": v.policy_name,
                "severity":    v.severity,
                "description": v.description,
                "remediation": v.remediation,
            }
            for v in decision.violations
        ],
        ttl_seconds      = decision.ttl_seconds,
        session_bindings = decision.session_bindings,
        recommendations  = decision.recommendations,
        context_hash     = decision.context_hash,
        summary          = decision.summary(),
    )


# ── POST /zerotrust/demo ──────────────────────────────────────────────────────

@router.post(
    "/demo",
    summary="Simuler N requêtes de démonstration",
    description="Génère et évalue N requêtes variées (normal, risky, attack, anomaly).",
)
async def run_demo(
    n:      int             = 10,
    engine: ZeroTrustEngine = Depends(get_zero_trust_engine),
) -> dict:
    if n < 1 or n > 100:
        raise HTTPException(status_code=400, detail="n doit être entre 1 et 100.")

    requests   = engine.generate_demo_requests(n=n)
    decisions  = [engine.evaluate(r) for r in requests]

    return {
        "evaluated": n,
        "results": [
            {
                "request_id": d.request_id,
                "verdict":    d.verdict.value,
                "trust_score": d.trust_score,
                "risk_count":  len(d.risk_factors),
                "summary":     d.summary(),
            }
            for d in decisions
        ],
        "stats": engine.get_stats(),
    }


# ── GET /zerotrust/stats ──────────────────────────────────────────────────────

@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Statistiques globales du moteur Zero-Trust",
)
async def get_stats(
    engine: ZeroTrustEngine = Depends(get_zero_trust_engine),
) -> StatsResponse:
    return StatsResponse(module="zero-trust", stats=engine.get_stats())


# ── GET /zerotrust/audit ─────────────────────────────────────────────────────

@router.get(
    "/audit",
    summary="Journal d'audit complet",
    description="Retourne toutes les décisions journalisées (immuables).",
)
async def get_audit_log(
    limit:  int             = 100,
    engine: ZeroTrustEngine = Depends(get_zero_trust_engine),
) -> dict:
    log = engine.get_audit_log()
    return {
        "total":   len(log),
        "entries": log[-limit:],
    }


# ══════════════════════════════════════════════════════════════════════════════
# DEVICES
# ══════════════════════════════════════════════════════════════════════════════

devices_router = APIRouter(
    prefix="/devices",
    tags=["Devices (MDM)"],
    dependencies=[Depends(verify_api_key)],
)


@devices_router.post(
    "/register",
    response_model=DeviceRegisterResponse,
    summary="Enregistrer un appareil dans le MDM",
)
async def register_device(
    body:     DeviceRegisterRequest,
    registry: DeviceRegistry = Depends(get_device_registry),
) -> DeviceRegisterResponse:
    device = DeviceContext(
        device_id    = body.device_id,
        is_managed   = body.is_managed,
        is_compliant = body.is_compliant,
        os_type      = body.os_type,
        os_version   = body.os_version,
        certificate  = body.certificate,
        trust_score  = body.trust_score,
    )
    fp = registry.register(device)
    return DeviceRegisterResponse(
        device_id   = body.device_id,
        fingerprint = fp,
        message     = "Appareil enregistré avec succès.",
    )


@devices_router.get(
    "/{device_id}",
    summary="Consulter un appareil par ID",
)
async def get_device(
    device_id: str,
    registry:  DeviceRegistry = Depends(get_device_registry),
) -> dict:
    device = registry.lookup(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Appareil {device_id!r} introuvable.")
    return {
        "device_id":    device.device_id,
        "is_managed":   device.is_managed,
        "is_compliant": device.is_compliant,
        "os_type":      device.os_type,
        "os_version":   device.os_version,
        "trust_score":  device.trust_score,
        "fingerprint":  device.fingerprint(),
    }


@devices_router.patch(
    "/{device_id}/compliance",
    summary="Mettre à jour la conformité d'un appareil",
)
async def update_device_compliance(
    device_id: str,
    compliant: bool,
    registry:  DeviceRegistry = Depends(get_device_registry),
) -> dict:
    if not registry.is_registered(device_id):
        raise HTTPException(status_code=404, detail=f"Appareil {device_id!r} introuvable.")
    registry.update_compliance(device_id, compliant)
    return {"device_id": device_id, "compliant": compliant, "updated": True}