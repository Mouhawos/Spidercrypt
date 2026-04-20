"""
🕷️  SPIDERCRYPT — Helpers partagés entre les tests
"""
from core.zerotrust_engine import (
    ZeroTrustRequest, IdentityContext,
    DeviceContext, NetworkContext, ResourceRequest,
)


def make_request(
    user_id="usr_test", roles=None,
    auth_method="MFA_TOTP", mfa_verified=True,
    session_age_min=10.0, failed_attempts=0,
    risk_score=0.1, is_service_account=False,
    device_id="DEV-MANAGED-OK", is_managed=True,
    is_compliant=True, os_type="MACOS",
    certificate="cert_abc", trust_score=0.9,
    ip_address="192.168.1.42", country="FR",
    is_tor=False, is_vpn=False, is_proxy=False,
    is_corporate=True, tls_version="TLS1.3",
    user_agent="Mozilla/5.0", resource_id="doc-001",
    resource_type="DOCUMENT", sensitivity="INTERNAL",
    action="READ", is_bulk=False, last_login_time=None,
) -> ZeroTrustRequest:
    return ZeroTrustRequest(
        identity=IdentityContext(
            user_id=user_id, roles=roles or ["analyst"],
            auth_method=auth_method, mfa_verified=mfa_verified,
            session_age_min=session_age_min, failed_attempts=failed_attempts,
            risk_score=risk_score, is_service_account=is_service_account,
            last_login_time=last_login_time,
        ),
        device=DeviceContext(
            device_id=device_id, is_managed=is_managed,
            is_compliant=is_compliant, os_type=os_type,
            certificate=certificate, trust_score=trust_score,
        ),
        network=NetworkContext(
            ip_address=ip_address, country=country,
            is_tor=is_tor, is_vpn=is_vpn, is_proxy=is_proxy,
            is_corporate=is_corporate, user_agent=user_agent,
            tls_version=tls_version,
        ),
        resource=ResourceRequest(
            resource_id=resource_id, resource_type=resource_type,
            sensitivity=sensitivity, action=action, is_bulk=is_bulk,
        ),
    )