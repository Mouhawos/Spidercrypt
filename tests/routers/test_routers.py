"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Tests Routers API                                   ║
║   Couvre : health, zero-trust, synthetic, investigation, pipeline          ║
╚══════════════════════════════════════════════════════════════════════════════╝

Lancer :
    pytest tests/routers/ -v
    pytest tests/routers/test_routers.py -v
"""

import pytest
from fastapi.testclient import TestClient

from main import app

# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def headers() -> dict:
    return {
        "Content-Type":      "application/json",
        "X-SpiderCrypt-Key": "dev-key-001",
    }


@pytest.fixture
def zt_body() -> dict:
    """Corps minimal valide pour /zerotrust/evaluate."""
    return {
        "identity": {
            "user_id":         "usr_test",
            "roles":           ["analyst"],
            "auth_method":     "MFA_TOTP",
            "mfa_verified":    True,
            "session_age_min": 10.0,
            "failed_attempts": 0,
            "risk_score":      0.1,
            "is_service_account": False,
        },
        "device": {
            "device_id":    "DEV-TEST-001",
            "is_managed":   True,
            "is_compliant": True,
            "os_type":      "MACOS",
            "trust_score":  0.9,
        },
        "network": {
            "ip_address":   "192.168.1.42",
            "country":      "FR",
            "is_tor":       False,
            "is_corporate": True,
            "tls_version":  "TLS1.3",
        },
        "resource": {
            "resource_id":   "doc-001",
            "resource_type": "DOCUMENT",
            "sensitivity":   "INTERNAL",
            "action":        "READ",
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthCheck:

    def test_health_retourne_200(self, client):
        """GET /health → 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_structure(self, client):
        """GET /health → structure correcte."""
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        assert data["status"] == "ok"
        assert "version" in data
        assert "modules" in data

    def test_health_modules_presents(self, client):
        """GET /health → tous les modules sont listés."""
        response = client.get("/health")
        modules = response.json()["modules"]
        assert "zero-trust" in modules
        assert "synthetic" in modules
        assert "investigation" in modules
        assert "pipeline" in modules

    def test_root_retourne_200(self, client):
        """GET / → 200 OK."""
        response = client.get("/")
        assert response.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 2. SÉCURITÉ — Authentification API
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthentification:

    def test_sans_cle_api_bloquee_zerotrust(self, client, zt_body):
        """Sans clé API → accès refusé sur /zerotrust/evaluate."""
        response = client.post("/zerotrust/evaluate", json=zt_body)
        assert response.status_code in (401, 403, 422)

    def test_sans_cle_api_bloquee_synthetic(self, client):
        """Sans clé API → accès refusé sur /synthetic/generate."""
        response = client.post(
            "/synthetic/generate",
            json={"schema_name": "transactions", "n": 10},
        )
        assert response.status_code in (401, 403, 422)

    def test_sans_cle_api_bloquee_investigation(self, client):
        """Sans clé API → accès refusé sur /investigation/run."""
        response = client.post(
            "/investigation/run",
            json={"actor_id": "usr_test", "days_back": 7},
        )
        assert response.status_code in (401, 403, 422)

    def test_sans_cle_api_bloquee_pipeline(self, client):
        """Sans clé API → accès refusé sur /pipeline/encrypt-demo."""
        response = client.post(
            "/pipeline/encrypt-demo",
            json={"schema_name": "transactions", "n_records": 5},
        )
        assert response.status_code in (401, 403, 422)

    def test_health_accessible_sans_cle(self, client):
        """GET /health → accessible sans authentification."""
        response = client.get("/health")
        assert response.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 3. ZERO-TRUST ROUTER
# ══════════════════════════════════════════════════════════════════════════════

class TestZeroTrustRouter:

    def test_evaluate_retourne_200(self, client, headers, zt_body):
        """POST /zerotrust/evaluate → 200 avec corps valide."""
        response = client.post("/zerotrust/evaluate", headers=headers, json=zt_body)
        assert response.status_code == 200

    def test_evaluate_retourne_verdict(self, client, headers, zt_body):
        """POST /zerotrust/evaluate → contient un verdict."""
        response = client.post("/zerotrust/evaluate", headers=headers, json=zt_body)
        data = response.json()
        assert "verdict" in data
        assert data["verdict"] in ["ALLOW", "DENY", "CHALLENGE_MFA", "STEP_UP", "QUARANTINE"]

    def test_evaluate_retourne_trust_score(self, client, headers, zt_body):
        """POST /zerotrust/evaluate → contient un trust_score."""
        response = client.post("/zerotrust/evaluate", headers=headers, json=zt_body)
        data = response.json()
        assert "trust_score" in data
        assert 0 <= data["trust_score"] <= 100

    def test_evaluate_tor_retourne_deny(self, client, headers, zt_body):
        """POST /zerotrust/evaluate avec Tor → verdict DENY."""
        zt_body["network"]["is_tor"] = True
        response = client.post("/zerotrust/evaluate", headers=headers, json=zt_body)
        assert response.status_code == 200
        assert response.json()["verdict"] == "DENY"

    def test_evaluate_corps_invalide_422(self, client, headers):
        """POST /zerotrust/evaluate avec corps invalide → 422."""
        response = client.post(
            "/zerotrust/evaluate",
            headers=headers,
            json={"invalid": "data"},
        )
        assert response.status_code == 422

    def test_evaluate_structure_complete(self, client, headers, zt_body):
        """POST /zerotrust/evaluate → structure complète de la réponse."""
        response = client.post("/zerotrust/evaluate", headers=headers, json=zt_body)
        data = response.json()
        assert "verdict" in data
        assert "trust_score" in data
        assert "risk_factors" in data
        assert "violations" in data
        assert "recommendations" in data
        assert "ttl_seconds" in data
        assert "context_hash" in data

    def test_stats_retourne_200(self, client, headers):
        """GET /zerotrust/stats → 200."""
        response = client.get("/zerotrust/stats", headers=headers)
        assert response.status_code == 200

    def test_audit_log_retourne_200(self, client, headers):
        """GET /zerotrust/audit → 200."""
        response = client.get("/zerotrust/audit", headers=headers)
        assert response.status_code == 200

    def test_demo_retourne_200(self, client, headers):
        """POST /zerotrust/demo → 200."""
        response = client.post("/zerotrust/demo?n=3", headers=headers)
        assert response.status_code == 200

    def test_demo_retourne_resultats(self, client, headers):
        """POST /zerotrust/demo → contient les résultats."""
        response = client.post("/zerotrust/demo?n=3", headers=headers)
        data = response.json()
        assert "evaluated" in data
        assert "results" in data
        assert len(data["results"]) == 3

    def test_devices_register_retourne_200(self, client, headers):
        """POST /devices/register → 200."""
        response = client.post(
            "/devices/register",
            headers=headers,
            json={
                "device_id":    "DEV-ROUTER-TEST",
                "is_managed":   True,
                "is_compliant": True,
                "os_type":      "WINDOWS",
                "trust_score":  0.8,
            },
        )
        assert response.status_code == 200

    def test_devices_get_retourne_404_si_inconnu(self, client, headers):
        """GET /devices/INCONNU → 404."""
        response = client.get("/devices/DEV-INCONNU-XYZ", headers=headers)
        assert response.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# 4. SYNTHETIC ROUTER
# ══════════════════════════════════════════════════════════════════════════════

class TestSyntheticRouter:

    def test_schemas_retourne_200(self, client, headers):
        """GET /synthetic/schemas → 200."""
        response = client.get("/synthetic/schemas", headers=headers)
        assert response.status_code == 200

    def test_schemas_liste_non_vide(self, client, headers):
        """GET /synthetic/schemas → liste non vide."""
        response = client.get("/synthetic/schemas", headers=headers)
        data = response.json()
        assert "schemas" in data
        assert len(data["schemas"]) > 0

    def test_generate_transactions_200(self, client, headers):
        """POST /synthetic/generate transactions → 200."""
        response = client.post(
            "/synthetic/generate",
            headers=headers,
            json={"schema_name": "transactions", "n": 10, "format": "json"},
        )
        assert response.status_code == 200

    def test_generate_retourne_bons_records(self, client, headers):
        """POST /synthetic/generate → retourne le bon nombre de records."""
        response = client.post(
            "/synthetic/generate",
            headers=headers,
            json={"schema_name": "transactions", "n": 5, "format": "json"},
        )
        data = response.json()
        assert "records" in data
        assert len(data["records"]) == 5

    def test_generate_schema_inconnu_400(self, client, headers):
        """POST /synthetic/generate schéma inconnu → 400."""
        response = client.post(
            "/synthetic/generate",
            headers=headers,
            json={"schema_name": "schema_inexistant", "n": 5},
        )
        assert response.status_code == 400

    def test_generate_trop_grand_400(self, client, headers):
        """POST /synthetic/generate n > 10000 → 400."""
        response = client.post(
            "/synthetic/generate",
            headers=headers,
            json={"schema_name": "transactions", "n": 99999},
        )
        assert response.status_code == 400

    def test_preview_transactions_200(self, client, headers):
        """GET /synthetic/preview/transactions → 200."""
        response = client.get("/synthetic/preview/transactions", headers=headers)
        assert response.status_code == 200

    def test_preview_structure(self, client, headers):
        """GET /synthetic/preview/transactions → structure correcte."""
        response = client.get("/synthetic/preview/transactions", headers=headers)
        data = response.json()
        assert "schema" in data
        assert "columns" in data
        assert "sample" in data
        assert len(data["sample"]) == 5

    def test_preview_schema_inconnu_404(self, client, headers):
        """GET /synthetic/preview/inconnu → 404."""
        response = client.get("/synthetic/preview/schema_inconnu", headers=headers)
        assert response.status_code == 404

    def test_generate_audit_events_200(self, client, headers):
        """POST /synthetic/generate audit_events → 200."""
        response = client.post(
            "/synthetic/generate",
            headers=headers,
            json={"schema_name": "audit_events", "n": 5, "format": "json"},
        )
        assert response.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# 5. INVESTIGATION ROUTER
# ══════════════════════════════════════════════════════════════════════════════

class TestInvestigationRouter:

    def test_run_retourne_200(self, client, headers):
        """POST /investigation/run → 200."""
        response = client.post(
            "/investigation/run",
            headers=headers,
            json={
                "actor_id":   "usr_test",
                "days_back":  7,
                "investigator": "test-analyst",
            },
        )
        assert response.status_code == 200

    def test_run_retourne_rapport(self, client, headers):
        """POST /investigation/run → rapport structuré."""
        response = client.post(
            "/investigation/run",
            headers=headers,
            json={"actor_id": "usr_test", "days_back": 7},
        )
        data = response.json()
        assert "report_id" in data
        assert "risk_assessment" in data
        assert "timeline" in data
        assert "anomalies" in data
        assert "recommendations" in data

    def test_demo_anomalies_200(self, client, headers):
        """GET /investigation/anomalies/demo → 200."""
        response = client.get(
            "/investigation/anomalies/demo?actor_id=usr_test&days_back=7",
            headers=headers,
        )
        assert response.status_code == 200

    def test_demo_anomalies_structure(self, client, headers):
        """GET /investigation/anomalies/demo → structure correcte."""
        response = client.get(
            "/investigation/anomalies/demo",
            headers=headers,
        )
        data = response.json()
        assert "actor_id" in data
        assert "anomaly_count" in data
        assert "risk_level" in data


# ══════════════════════════════════════════════════════════════════════════════
# 6. PIPELINE ROUTER
# ══════════════════════════════════════════════════════════════════════════════

class TestPipelineRouter:

    def test_info_retourne_200(self, client, headers):
        """GET /pipeline/info → 200."""
        response = client.get("/pipeline/info", headers=headers)
        assert response.status_code == 200

    def test_info_structure(self, client, headers):
        """GET /pipeline/info → structure correcte."""
        response = client.get("/pipeline/info", headers=headers)
        data = response.json()
        assert "engine" in data
        assert "encryption" in data
        assert "formats" in data
        assert "compliance" in data

    def test_info_algorithme_chacha20(self, client, headers):
        """GET /pipeline/info → algorithme ChaCha20-Poly1305."""
        response = client.get("/pipeline/info", headers=headers)
        assert "ChaCha20" in response.json()["encryption"]

    def test_schemas_retourne_200(self, client, headers):
        """GET /pipeline/schemas → 200."""
        response = client.get("/pipeline/schemas", headers=headers)
        assert response.status_code == 200

    def test_schemas_contient_transactions(self, client, headers):
        """GET /pipeline/schemas → contient le schéma transactions."""
        response = client.get("/pipeline/schemas", headers=headers)
        data = response.json()
        assert "schemas" in data
        assert "transactions" in data["schemas"]

    def test_encrypt_demo_retourne_200(self, client, headers):
        """POST /pipeline/encrypt-demo → 200."""
        response = client.post(
            "/pipeline/encrypt-demo",
            headers=headers,
            json={"schema_name": "transactions", "n_records": 5},
        )
        assert response.status_code == 200

    def test_encrypt_demo_structure(self, client, headers):
        """POST /pipeline/encrypt-demo → structure correcte."""
        response = client.post(
            "/pipeline/encrypt-demo",
            headers=headers,
            json={"schema_name": "transactions", "n_records": 5},
        )
        data = response.json()
        assert "encryption" in data
        assert "n_records" in data
        assert "plain_sample" in data
        assert "encrypted_sample" in data
        assert "columns_encrypted" in data

    def test_encrypt_demo_trop_grand_400(self, client, headers):
        """POST /pipeline/encrypt-demo n > 1000 → 400."""
        response = client.post(
            "/pipeline/encrypt-demo",
            headers=headers,
            json={"schema_name": "transactions", "n_records": 9999},
        )
        assert response.status_code == 400

    def test_encrypt_demo_algorithme_correct(self, client, headers):
        """POST /pipeline/encrypt-demo → algorithme ChaCha20-Poly1305."""
        response = client.post(
            "/pipeline/encrypt-demo",
            headers=headers,
            json={"schema_name": "transactions", "n_records": 3},
        )
        assert response.json()["encryption"] == "ChaCha20-Poly1305"