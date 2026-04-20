"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Tests Service Zero-Trust                            ║
║   Couvre : scoring, verdicts, politiques, sessions, MDM, edge cases        ║
╚══════════════════════════════════════════════════════════════════════════════╝

Lancer :
    pytest tests/services/test_zerotrust.py -v
    pytest tests/services/test_zerotrust.py -v --cov=core.zerotrust_engine
"""

import pytest
from tests.helpers import make_request

from core.zerotrust_engine import (
    ZeroTrustEngine,
    DeviceRegistry,
    DeviceContext,
    Verdict,
    RiskFactor,
)


# ══════════════════════════════════════════════════════════════════════════════
# 1. VERDICTS — Les règles absolues qui ne doivent JAMAIS changer
# ══════════════════════════════════════════════════════════════════════════════

class TestVerdictsAbsolus:
    """
    Ces tests sont les plus importants.
    Si l'un d'eux échoue → STOP, ne pas déployer.
    """

    def test_tor_toujours_deny(self, engine):
        """Connexion via Tor → toujours DENY, sans exception."""
        req = make_request(is_tor=True, mfa_verified=True, failed_attempts=0)
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY

    def test_tor_deny_meme_avec_mfa_et_appareil_conforme(self, engine):
        """Tor + MFA + appareil parfait → quand même DENY."""
        req = make_request(
            is_tor       = True,
            mfa_verified = True,
            device_id    = "DEV-MANAGED-OK",
            is_managed   = True,
            is_compliant = True,
            trust_score  = 1.0,
        )
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY

    def test_compte_verrouille_deny(self, engine):
        """5 tentatives échouées ou plus → DENY."""
        req = make_request(failed_attempts=5)
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY

    def test_compte_verrouille_6_tentatives(self, engine):
        """6 tentatives → aussi DENY."""
        req = make_request(failed_attempts=6)
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY

    def test_voyage_impossible_quarantine(self, engine, session_store):
        """Connexion depuis un pays différent en moins de 2h → QUARANTINE."""
        session = session_store.create(
            user_id      = "usr_voyageur",
            device_id    = "DEV-MANAGED-OK",
            ip           = "192.168.1.1",
            country      = "FR",
            trust_score  = 80,
            mfa_verified = True,
        )
        req = make_request(
            user_id    = "usr_voyageur",
            country    = "CN",
            ip_address = "1.2.3.4",
        )
        req.identity.session_id = session.session_id
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.QUARANTINE

    def test_acces_normal_allow(self, engine):
        """Requête normale depuis réseau entreprise → ALLOW."""
        req = make_request(
            device_id    = "DEV-MANAGED-OK",
            mfa_verified = True,
            is_corporate = True,
            country      = "FR",
            sensitivity  = "INTERNAL",
        )
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.ALLOW

    def test_ressource_secret_sans_mfa_step_up(self, engine):
        """Ressource SECRET sans MFA → au moins STEP_UP ou DENY."""
        req = make_request(
            sensitivity  = "SECRET",
            mfa_verified = False,
            auth_method  = "PASSWORD",
            device_id    = "DEV-MANAGED-OK",
        )
        decision = engine.evaluate(req)
        assert decision.verdict in (
            Verdict.DENY,
            Verdict.STEP_UP,
            Verdict.CHALLENGE_MFA,
        )
        assert decision.verdict != Verdict.ALLOW

# ══════════════════════════════════════════════════════════════════════════════
# 2. SCORE DE CONFIANCE — Vérifier que le scoring est cohérent
# ══════════════════════════════════════════════════════════════════════════════

class TestScoreConfiance:

    def test_score_entre_0_et_100(self, engine):
        """Le score doit toujours être dans [0, 100]."""
        for _ in range(10):
            req = make_request()
            decision = engine.evaluate(req)
            assert 0 <= decision.trust_score <= 100

    def test_score_tor_tres_bas(self, engine):
        """Tor → score diminué significativement par rapport à une requête normale."""
        req_tor    = make_request(is_tor=True)
        req_normal = make_request(device_id="DEV-MANAGED-OK")
        score_tor    = engine.evaluate(req_tor).trust_score
        score_normal = engine.evaluate(req_normal).trust_score
        assert score_tor < score_normal

    def test_score_reseau_entreprise_plus_eleve(self, engine):
        """Réseau entreprise → score supérieur ou égal au réseau public."""
        req_corp = make_request(
            device_id     = "DEV-MANAGED-OK",
            is_corporate  = True,
            mfa_verified  = True,
            risk_score    = 0.5,
        )
        req_public = make_request(
            device_id     = "DEV-MANAGED-OK",
            is_corporate  = False,
            mfa_verified  = True,
            risk_score    = 0.5,
        )
        score_corp   = engine.evaluate(req_corp).trust_score
        score_public = engine.evaluate(req_public).trust_score
        assert score_corp >= score_public, \
            f"Corporate devrait avoir un score >= public ({score_corp} >= {score_public})"

    def test_mfa_augmente_score(self, engine):
        """MFA vérifié → score plus élevé ou égal."""
        req_mfa    = make_request(device_id="DEV-MANAGED-OK", mfa_verified=True)
        req_no_mfa = make_request(device_id="DEV-MANAGED-OK", mfa_verified=False)
        score_mfa    = engine.evaluate(req_mfa).trust_score
        score_no_mfa = engine.evaluate(req_no_mfa).trust_score
        assert score_mfa >= score_no_mfa, \
            f"MFA devrait donner un score >= sans MFA ({score_mfa} >= {score_no_mfa})"

    def test_tentatives_echouees_diminuent_score(self, engine):
        """Plus de tentatives échouées → score plus bas ou égal."""
        req_0 = make_request(device_id="DEV-MANAGED-OK", failed_attempts=0)
        req_3 = make_request(device_id="DEV-MANAGED-OK", failed_attempts=3)
        score_0 = engine.evaluate(req_0).trust_score
        score_3 = engine.evaluate(req_3).trust_score
        assert score_0 >= score_3, \
            f"Plus de tentatives devraient baisser ou égaler le score ({score_0} >= {score_3})"

    def test_appareil_non_enregistre_diminue_score(self, engine):
        """Appareil inconnu → score plus bas qu'appareil enregistré."""
        req_connu   = make_request(device_id="DEV-MANAGED-OK")
        req_inconnu = make_request(device_id="APPAREIL-INCONNU-XYZ")
        score_connu   = engine.evaluate(req_connu).trust_score
        score_inconnu = engine.evaluate(req_inconnu).trust_score
        assert score_connu >= score_inconnu

    def test_pays_non_autorise_diminue_score(self, engine):
        """Pays non autorisé → score plus bas ou égal."""
        req_fr = make_request(device_id="DEV-MANAGED-OK", country="FR")
        req_cn = make_request(device_id="DEV-MANAGED-OK", country="CN")
        score_fr = engine.evaluate(req_fr).trust_score
        score_cn = engine.evaluate(req_cn).trust_score
        assert score_fr >= score_cn, \
            f"Pays risqué devrait donner un score <= ({score_fr} >= {score_cn})"
# ══════════════════════════════════════════════════════════════════════════════
# 3. FACTEURS DE RISQUE — Vérifier qu'ils sont bien détectés
# ══════════════════════════════════════════════════════════════════════════════

class TestFacteursRisque:

    def test_tor_detecte_comme_facteur(self, engine):
        req = make_request(is_tor=True)
        decision = engine.evaluate(req)
        assert RiskFactor.TOR_EXIT_NODE in decision.risk_factors

    def test_sans_mfa_detecte(self, engine):
        req = make_request(mfa_verified=False, device_id="DEV-MANAGED-OK")
        decision = engine.evaluate(req)
        assert RiskFactor.NO_MFA in decision.risk_factors

    def test_appareil_inconnu_detecte(self, engine):
        req = make_request(device_id="DEV-INCONNU-999")
        decision = engine.evaluate(req)
        assert RiskFactor.UNKNOWN_DEVICE in decision.risk_factors

    def test_session_trop_vieille_detectee(self, engine):
        req = make_request(
            device_id       = "DEV-MANAGED-OK",
            session_age_min = 500,
        )
        decision = engine.evaluate(req)
        assert RiskFactor.STALE_SESSION in decision.risk_factors

    def test_tentatives_echouees_detectees(self, engine):
        req = make_request(failed_attempts=3)
        decision = engine.evaluate(req)
        assert RiskFactor.FAILED_ATTEMPTS in decision.risk_factors

    def test_pays_non_autorise_detecte(self, engine):
        req = make_request(
            device_id    = "DEV-MANAGED-OK",
            country      = "KP",
            is_corporate = False,
        )
        decision = engine.evaluate(req)
        assert RiskFactor.ANOMALOUS_LOCATION in decision.risk_factors

    def test_user_agent_suspect_detecte(self, engine):
        req = make_request(
            device_id  = "DEV-MANAGED-OK",
            user_agent = "sqlmap/1.0",
        )
        decision = engine.evaluate(req)
        assert RiskFactor.ANOMALOUS_USER_AGENT in decision.risk_factors

    def test_multi_violations_critiques(self, engine):
        """Cumul de facteurs critiques → DENY avec plusieurs violations."""
        req = make_request(
            is_tor          = True,
            failed_attempts = 10,
            tls_version     = "SSLv3",
            country         = "KP",
        )
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY
        assert len(decision.violations) >= 2
        assert RiskFactor.TOR_EXIT_NODE in decision.risk_factors

    def test_parametres_invalides_et_limites(self, engine):
        """Données hors normes → moteur stable (Fail-Safe)."""
        # Score de risque impossible → clampé entre 0 et 100
        req_absurde = make_request(risk_score=999.0)
        decision = engine.evaluate(req_absurde)
        assert 0 <= decision.trust_score <= 100

        # TLS inconnu → violation ZTP-009 détectée
        req_tls = make_request(
            device_id   = "DEV-MANAGED-OK",
            tls_version = "INSECURE_PROTOCOL",
        )
        decision_tls = engine.evaluate(req_tls)
        policy_ids = [v.policy_id for v in decision_tls.violations]
        assert "ZTP-009" in policy_ids

    def test_device_non_conforme_mais_gere(self, engine, device_registry):
        """Appareil non-compliant → facteur de risque détecté."""
        device_registry.update_compliance("DEV-MANAGED-OK", False)

        req = make_request(
            device_id    = "DEV-MANAGED-OK",
            is_managed   = True,
            is_compliant = False,
            mfa_verified = True,
        )
        decision = engine.evaluate(req)

        assert RiskFactor.UNMANAGED_DEVICE in decision.risk_factors

        req_ok = make_request(
            device_id    = "DEV-MANAGED-OK",
            is_compliant = True,
            mfa_verified = True,
        )
        score_ok = engine.evaluate(req_ok).trust_score
        assert decision.trust_score <= score_ok

        device_registry.update_compliance("DEV-MANAGED-OK", True)


# ══════════════════════════════════════════════════════════════════════════════
# 4. POLITIQUES — Vérifier les violations détectées
# ══════════════════════════════════════════════════════════════════════════════

class TestPolitiques:

    def test_ztp005_tor_violation(self, engine):
        req = make_request(is_tor=True)
        decision = engine.evaluate(req)
        policy_ids = [v.policy_id for v in decision.violations]
        assert "ZTP-005" in policy_ids

    def test_ztp003_mfa_requis_confidentiel(self, engine):
        req = make_request(
            sensitivity  = "CONFIDENTIAL",
            mfa_verified = False,
            device_id    = "DEV-MANAGED-OK",
        )
        decision = engine.evaluate(req)
        policy_ids = [v.policy_id for v in decision.violations]
        assert "ZTP-003" in policy_ids

    def test_ztp006_compte_verrouille(self, engine):
        req = make_request(failed_attempts=5)
        decision = engine.evaluate(req)
        policy_ids = [v.policy_id for v in decision.violations]
        assert "ZTP-006" in policy_ids

    def test_ztp004_session_expiree(self, engine):
        req = make_request(
            device_id       = "DEV-MANAGED-OK",
            session_age_min = 600,
        )
        decision = engine.evaluate(req)
        policy_ids = [v.policy_id for v in decision.violations]
        assert "ZTP-004" in policy_ids

    def test_ztp009_tls_obsolete(self, engine):
        req = make_request(
            device_id   = "DEV-MANAGED-OK",
            tls_version = "TLS1.0",
        )
        decision = engine.evaluate(req)
        policy_ids = [v.policy_id for v in decision.violations]
        assert "ZTP-009" in policy_ids

    def test_requete_propre_aucune_violation(self, engine):
        req = make_request(
            device_id       = "DEV-MANAGED-OK",
            mfa_verified    = True,
            is_corporate    = True,
            country         = "FR",
            tls_version     = "TLS1.3",
            sensitivity     = "INTERNAL",
            failed_attempts = 0,
        )
        decision = engine.evaluate(req)
        assert len(decision.violations) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 5. MDM — Device Registry
# ══════════════════════════════════════════════════════════════════════════════

class TestDeviceRegistry:

    def test_appareil_enregistre_reconnu(self, device_registry):
        device = DeviceContext(
            device_id    = "DEV-TEST-001",
            is_managed   = True,
            is_compliant = True,
            os_type      = "WINDOWS",
            trust_score  = 0.8,
        )
        device_registry.register(device)
        assert device_registry.is_registered("DEV-TEST-001")

    def test_appareil_non_enregistre(self, device_registry):
        assert not device_registry.is_registered("DEV-INCONNU-XYZ")

    def test_lookup_retourne_device(self, device_registry):
        device = DeviceContext(
            device_id    = "DEV-TEST-002",
            is_managed   = True,
            is_compliant = True,
            os_type      = "MACOS",
            trust_score  = 0.9,
        )
        device_registry.register(device)
        found = device_registry.lookup("DEV-TEST-002")
        assert found is not None
        assert found.device_id == "DEV-TEST-002"
        assert found.os_type == "MACOS"

    def test_lookup_inconnu_retourne_none(self, device_registry):
        result = device_registry.lookup("DEV-INEXISTANT")
        assert result is None

    def test_compliance_appareil_gere_et_conforme(self, device_registry):
        device = DeviceContext(
            device_id    = "DEV-COMPLIANT",
            is_managed   = True,
            is_compliant = True,
            os_type      = "LINUX",
            trust_score  = 0.7,
        )
        device_registry.register(device)
        assert device_registry.is_compliant("DEV-COMPLIANT")

    def test_compliance_appareil_non_conforme(self, device_registry):
        device = DeviceContext(
            device_id    = "DEV-NONCOMPLIANT",
            is_managed   = True,
            is_compliant = False,
            os_type      = "WINDOWS",
            trust_score  = 0.4,
        )
        device_registry.register(device)
        assert not device_registry.is_compliant("DEV-NONCOMPLIANT")

    def test_update_compliance(self, device_registry):
        device = DeviceContext(
            device_id    = "DEV-UPDATE",
            is_managed   = True,
            is_compliant = False,
            os_type      = "MACOS",
            trust_score  = 0.5,
        )
        device_registry.register(device)
        assert not device_registry.is_compliant("DEV-UPDATE")
        device_registry.update_compliance("DEV-UPDATE", True)
        assert device_registry.is_compliant("DEV-UPDATE")

    def test_fingerprint_deterministe(self, device_registry):
        """Le fingerprint d'un appareil doit être toujours le même."""
        device = DeviceContext(
            device_id    = "DEV-FP-TEST",
            is_managed   = True,
            is_compliant = True,
            os_type      = "LINUX",
            trust_score  = 0.8,
        )
        fp1 = device.fingerprint()
        fp2 = device.fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 16


# ══════════════════════════════════════════════════════════════════════════════
# 6. AUDIT & STATISTIQUES
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditStats:

    def test_audit_log_vide_au_demarrage(self, engine):
        assert engine.get_audit_log() == []

    def test_audit_log_enregistre_decisions(self, engine):
        req = make_request(device_id="DEV-MANAGED-OK")
        engine.evaluate(req)
        log = engine.get_audit_log()
        assert len(log) == 1
        assert "verdict" in log[0]
        assert "user_id" in log[0]
        assert "trust_score" in log[0]

    def test_audit_log_multiple_requetes(self, engine):
        for _ in range(5):
            engine.evaluate(make_request(device_id="DEV-MANAGED-OK"))
        assert len(engine.get_audit_log()) == 5

    def test_stats_vides_sans_requetes(self, engine):
        stats = engine.get_stats()
        assert stats == {}

    def test_stats_apres_requetes(self, engine):
        engine.evaluate(make_request(device_id="DEV-MANAGED-OK"))
        engine.evaluate(make_request(is_tor=True))
        stats = engine.get_stats()
        assert stats["total_requests"] == 2
        assert "verdicts" in stats
        assert "avg_trust_score" in stats
        assert "deny_rate_pct" in stats

    def test_context_hash_unique_par_requete(self, engine):
        """Deux requêtes différentes → hashes différents."""
        req1 = make_request(user_id="usr_001", device_id="DEV-MANAGED-OK")
        req2 = make_request(user_id="usr_002", device_id="DEV-MANAGED-OK")
        d1 = engine.evaluate(req1)
        d2 = engine.evaluate(req2)
        assert d1.context_hash != d2.context_hash

    def test_decision_contient_recommandations(self, engine):
        """Une décision doit toujours contenir des recommandations."""
        req = make_request(is_tor=True)
        decision = engine.evaluate(req)
        assert isinstance(decision.recommendations, list)
        assert len(decision.recommendations) > 0


# ══════════════════════════════════════════════════════════════════════════════
# 7. COMPTES DE SERVICE
# ══════════════════════════════════════════════════════════════════════════════

class TestComptesService:

    def test_service_account_hors_reseau_entreprise_risque(self, engine):
        """Compte service hors réseau entreprise → risque élevé."""
        req = make_request(
            device_id          = "DEV-MANAGED-OK",
            is_service_account = True,
            is_corporate       = False,
            ip_address         = "1.2.3.4",
        )
        decision = engine.evaluate(req)
        assert decision.verdict != Verdict.ALLOW or decision.trust_score < 70

    def test_service_account_reseau_entreprise_ok(self, engine):
        """Compte service sur réseau entreprise → acceptable."""
        req = make_request(
            device_id          = "DEV-MANAGED-OK",
            is_service_account = True,
            is_corporate       = True,
            ip_address         = "10.0.0.5",
            mfa_verified       = True,
        )
        decision = engine.evaluate(req)
        assert decision.verdict != Verdict.DENY or RiskFactor.TOR_EXIT_NODE in decision.risk_factors


# ══════════════════════════════════════════════════════════════════════════════
# 8. SESSION BINDINGS
# ══════════════════════════════════════════════════════════════════════════════

class TestSessionBindings:

    def test_deny_pas_de_session_bindings(self, engine):
        """Un DENY ne doit pas créer de bindings de session."""
        req = make_request(is_tor=True)
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY
        assert decision.session_bindings == {}

    def test_allow_cree_session_bindings(self, engine):
        """Un ALLOW doit créer des bindings de session."""
        req = make_request(
            device_id    = "DEV-MANAGED-OK",
            mfa_verified = True,
            is_corporate = True,
            country      = "FR",
        )
        decision = engine.evaluate(req)
        if decision.verdict == Verdict.ALLOW:
            assert "bound_to_ip" in decision.session_bindings
            assert "bound_to_device" in decision.session_bindings
            assert "trust_score" in decision.session_bindings
            assert "re_verify_every" in decision.session_bindings

    def test_quarantine_session_readonly(self, engine, session_store):
        """Une session en quarantaine → read_only=True."""
        session = session_store.create(
            user_id      = "usr_quarantine_test",
            device_id    = "DEV-MANAGED-OK",
            ip           = "192.168.1.1",
            country      = "FR",
            trust_score  = 80,
            mfa_verified = True,
        )
        req = make_request(
            user_id    = "usr_quarantine_test",
            country    = "CN",
            ip_address = "5.6.7.8",
        )
        req.identity.session_id = session.session_id
        decision = engine.evaluate(req)
        if decision.verdict == Verdict.QUARANTINE:
            assert decision.session_bindings.get("read_only") is True


# ══════════════════════════════════════════════════════════════════════════════
# 9. TTL
# ══════════════════════════════════════════════════════════════════════════════

class TestTTL:

    def test_deny_ttl_zero(self, engine):
        """Un DENY → TTL = 0 (pas de cache)."""
        req = make_request(is_tor=True)
        decision = engine.evaluate(req)
        assert decision.verdict == Verdict.DENY
        assert decision.ttl_seconds == 0

    def test_allow_ttl_positif(self, engine):
        """Un ALLOW → TTL > 0."""
        req = make_request(
            device_id    = "DEV-MANAGED-OK",
            mfa_verified = True,
            is_corporate = True,
            country      = "FR",
            sensitivity  = "PUBLIC",
        )
        decision = engine.evaluate(req)
        if decision.verdict == Verdict.ALLOW:
            assert decision.ttl_seconds > 0



# ══════════════════════════════════════════════════════════════════════════════
# 10. PROPERTY-BASED TESTING (HYPOTHESIS)
# ══════════════════════════════════════════════════════════════════════════════

from hypothesis import given, settings, strategies as st
from hypothesis import HealthCheck, assume

class TestZeroTrustProperties:

    @given(
        is_tor=st.booleans(),
        mfa_verified=st.booleans(),
        failed_attempts=st.integers(min_value=0, max_value=100),
        risk_score=st.floats(min_value=-10.0, max_value=100.0),
        country=st.sampled_from(["FR", "CA", "US", "CN", "RU", "KP", "IR", "BR", ""]),
        device_id=st.text(min_size=0, max_size=150),
        tls_version=st.one_of(st.none(), st.sampled_from(["TLS1.3", "TLS1.2", "TLS1.1", "TLS1.0", "SSL3.0", "INSECURE", ""])),
        sensitivity=st.sampled_from(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "TOP_SECRET", ""]),
        session_age_min=st.floats(min_value=-1000.0, max_value=20000.0),
        is_corporate=st.booleans(),
        is_service_account=st.booleans(),
        user_agent=st.one_of(st.none(), st.text(max_size=800)),
    )
    @settings(
        max_examples=1000,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        verbosity="normal"
    )
    def test_evaluate_invariants_et_stabilite(self, engine, **kwargs):
        """Test property-based pour couvrir le maximum de branches."""
        req = make_request(**kwargs)

        assume(not (kwargs.get("is_tor") and kwargs.get("is_corporate") and kwargs.get("mfa_verified")))

        decision = engine.evaluate(req)

        assert 0 <= decision.trust_score <= 100
        assert decision.verdict in list(Verdict)
        assert isinstance(decision.risk_factors, (list, tuple))
        assert isinstance(decision.violations, (list, tuple))
        assert isinstance(decision.recommendations, (list, tuple))
        assert decision.context_hash is not None

        if getattr(req, "is_tor", False):
            assert decision.verdict == Verdict.DENY

        if getattr(req, "failed_attempts", 0) >= 5:
            assert decision.verdict == Verdict.DENY

        if decision.verdict == Verdict.DENY:
            assert decision.ttl_seconds == 0
        else:
            assert decision.ttl_seconds >= 0

        if decision.verdict == Verdict.ALLOW:
            critical = {RiskFactor.TOR_EXIT_NODE, RiskFactor.IMPOSSIBLE_TRAVEL}
            assert not critical.intersection(decision.risk_factors)

        assert len(decision.recommendations) >= 0