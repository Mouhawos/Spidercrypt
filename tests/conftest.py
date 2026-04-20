""""
🕷️  SPIDERCRYPT — Fixtures Partagées Pytest
"""
import pytest
from fastapi.testclient import TestClient

from core.zerotrust_engine import (
    ZeroTrustEngine,
    DeviceRegistry,
    SessionStore,
    DeviceContext,
)


@pytest.fixture
def device_registry() -> DeviceRegistry:
    return DeviceRegistry()


@pytest.fixture
def session_store() -> SessionStore:
    return SessionStore()


@pytest.fixture
def engine(device_registry, session_store) -> ZeroTrustEngine:
    zt = ZeroTrustEngine(
        device_registry=device_registry,
        session_store=session_store,
    )
    device_registry.register(DeviceContext(
        device_id="DEV-MANAGED-OK", is_managed=True,
        is_compliant=True, os_type="MACOS",
        certificate="cert_test_abc123", trust_score=0.95,
    ))
    device_registry.register(DeviceContext(
        device_id="DEV-MANAGED-NONCOMPLIANT", is_managed=True,
        is_compliant=False, os_type="WINDOWS", trust_score=0.5,
    ))
    device_registry.register(DeviceContext(
        device_id="DEV-UNMANAGED", is_managed=False,
        is_compliant=False, os_type="LINUX", trust_score=0.1,
    ))
    return zt


@pytest.fixture
def build_request():
    from tests.helpers import make_request
    return make_request


@pytest.fixture
def api_client():
    from main import app
    return TestClient(app)


@pytest.fixture
def api_headers():
    return {
        "Content-Type":      "application/json",
        "X-SpiderCrypt-Key": "dev-key-001",
    }