"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Tests Service Investigation                         ║
║   Couvre : timeline, anomalies, statistiques, risque, rapport, signature   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Lancer :
    pytest tests/services/test_investigation.py -v
    pytest tests/services/test_investigation.py -v --cov=services.investigation_service
"""

import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pandas as pd
import pytest

from services.investigation_service import (
    InvestigationEngine,
    InvestigationReport,
    TimelineEvent,
    AnomalySignal,
    DetectionRule,
    DETECTION_RULES,
    RULES_BY_NAME,
    _categorize_action,
)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS — Générateurs de données de test
# ══════════════════════════════════════════════════════════════════════════════

def make_ts_ms(hours_ago: float = 0) -> int:
    """Retourne un timestamp en ms dans le passé."""
    return int((datetime.now(timezone.utc) - timedelta(hours=hours_ago)).timestamp() * 1000)


def make_audit_event(
    acteur_id: str = "usr_test",
    action: str = "LOGIN",
    succes: bool = True,
    severite: str = "INFO",
    hours_ago: float = 1.0,
    resource_type: str = "API",
    resource_id: str = "res-001",
) -> dict:
    """Crée un événement d'audit minimal pour les tests."""
    ts_ms = make_ts_ms(hours_ago)
    return {
        "event_id":      str(uuid.uuid4()),
        "timestamp_ms":  ts_ms,
        "timestamp_iso": datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat(),
        "acteur_id":     acteur_id,
        "action":        action,
        "succes":        succes,
        "severite":      severite,
        "resource_type": resource_type,
        "resource_id":   resource_id,
    }


def make_transaction(
    acteur_id: str = "usr_test",
    montant_eur: float = 100.0,
    statut: str = "COMPLETED",
    est_anomalie: bool = False,
    hours_ago: float = 1.0,
) -> dict:
    """Crée une transaction minimale pour les tests."""
    ts_ms = make_ts_ms(hours_ago)
    return {
        "transaction_id": str(uuid.uuid4()),
        "timestamp_ms":   ts_ms,
        "timestamp_iso":  datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat(),
        "acteur_id":      acteur_id,
        "montant_eur":    montant_eur,
        "statut":         statut,
        "est_anomalie":   est_anomalie,
        "risque_score":   0.9 if est_anomalie else 0.1,
        "type_anomalie":  "montant_suspect" if est_anomalie else None,
        "devise":         "EUR",
        "moyen_paiement": "carte_visa",
        "secteur":        "Commerce",
        "ville":          "Paris",
    }


def make_engine_with_audit(events: list[dict]) -> InvestigationEngine:
    """Crée un moteur chargé avec des événements d'audit."""
    engine = InvestigationEngine()
    df = pd.DataFrame(events)
    engine.load_audit_events_df(df)
    return engine


def make_engine_with_tx(transactions: list[dict]) -> InvestigationEngine:
    """Crée un moteur chargé avec des transactions."""
    engine = InvestigationEngine()
    df = pd.DataFrame(transactions)
    engine.load_transactions_df(df)
    return engine


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def engine() -> InvestigationEngine:
    """Moteur d'investigation vide."""
    return InvestigationEngine()


@pytest.fixture
def engine_avec_audit() -> InvestigationEngine:
    """Moteur avec 10 événements d'audit variés."""
    events = [
        make_audit_event("usr_0042", "LOGIN",   True,  "INFO",     2.0),
        make_audit_event("usr_0042", "READ",    True,  "INFO",     1.9),
        make_audit_event("usr_0042", "WRITE",   True,  "INFO",     1.8),
        make_audit_event("usr_0042", "EXPORT",  True,  "INFO",     1.7),
        make_audit_event("usr_0042", "READ",    False, "WARNING",  1.6),
        make_audit_event("usr_0042", "DELETE",  False, "ERROR",    1.5),
        make_audit_event("usr_0042", "LOGIN",   True,  "INFO",     1.4),
        make_audit_event("usr_0042", "API_CALL",True,  "INFO",     1.3),
        make_audit_event("usr_0042", "LOGOUT",  True,  "INFO",     1.2),
        make_audit_event("usr_9999", "LOGIN",   True,  "INFO",     1.0),
    ]
    return make_engine_with_audit(events)


@pytest.fixture
def engine_brute_force() -> InvestigationEngine:
    """Moteur avec scénario brute force (6 échecs en 5 minutes)."""
    events = []
    base_ms = make_ts_ms(2.0)
    for i in range(6):
        ts_ms = base_ms + i * 50_000  # 50 secondes entre chaque
        events.append({
            "event_id":      str(uuid.uuid4()),
            "timestamp_ms":  ts_ms,
            "timestamp_iso": datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat(),
            "acteur_id":     "usr_attacker",
            "action":        "LOGIN",
            "succes":        False,
            "severite":      "ERROR",
            "resource_type": "AUTH",
            "resource_id":   "auth-001",
        })
    return make_engine_with_audit(events)


@pytest.fixture
def engine_avec_transactions() -> InvestigationEngine:
    """Moteur avec audit + transactions."""
    engine = InvestigationEngine()
    audit_events = [
        make_audit_event("usr_0042", "LOGIN", True, "INFO", 2.0),
        make_audit_event("usr_0042", "READ",  True, "INFO", 1.0),
    ]
    transactions = [
        make_transaction("usr_0042", 500.0,    "COMPLETED", False, 1.5),
        make_transaction("usr_0042", 15_000.0, "COMPLETED", True,  1.0),
    ]
    engine.load_audit_events_df(pd.DataFrame(audit_events))
    engine.load_transactions_df(pd.DataFrame(transactions))
    return engine


# ══════════════════════════════════════════════════════════════════════════════
# 1. INITIALISATION
# ══════════════════════════════════════════════════════════════════════════════

class TestInitialisation:

    def test_engine_vide_au_demarrage(self, engine):
        """Moteur sans données → pas d'erreur."""
        assert engine._df_audit is None
        assert engine._df_tx is None

    def test_load_audit_events_df(self, engine):
        """Charger un DataFrame d'audit → stocké correctement."""
        df = pd.DataFrame([make_audit_event()])
        engine.load_audit_events_df(df)
        assert engine._df_audit is not None
        assert len(engine._df_audit) == 1

    def test_load_transactions_df(self, engine):
        """Charger un DataFrame de transactions → stocké correctement."""
        df = pd.DataFrame([make_transaction()])
        engine.load_transactions_df(df)
        assert engine._df_tx is not None
        assert len(engine._df_tx) == 1

    def test_chargement_chainable(self, engine):
        """Le chargement est chaînable (return self)."""
        df_audit = pd.DataFrame([make_audit_event()])
        df_tx    = pd.DataFrame([make_transaction()])
        result = engine.load_audit_events_df(df_audit).load_transactions_df(df_tx)
        assert result is engine

    def test_load_copie_dataframe(self, engine):
        """Le chargement copie le DataFrame (pas de mutation externe)."""
        df = pd.DataFrame([make_audit_event()])
        engine.load_audit_events_df(df)
        df["colonne_test"] = "modifiée"
        assert "colonne_test" not in engine._df_audit.columns


# ══════════════════════════════════════════════════════════════════════════════
# 2. TIMELINE
# ══════════════════════════════════════════════════════════════════════════════

class TestTimeline:

    def test_timeline_vide_sans_donnees(self, engine):
        """Sans données → timeline vide."""
        report = engine.investigate(actor_id="usr_inconnu", days_back=7)
        assert report.summary["total_events"] == 0

    def test_timeline_filtre_par_acteur(self, engine_avec_audit):
        """La timeline filtre correctement par acteur."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        assert report.summary["total_events"] == 9  # usr_9999 exclu

    def test_timeline_tous_acteurs(self, engine_avec_audit):
        """Sans filtre acteur → tous les événements."""
        report = engine_avec_audit.investigate(days_back=7)
        assert report.summary["total_events"] == 10

    def test_timeline_triee_par_timestamp(self, engine_avec_audit):
        """Les événements sont triés par timestamp croissant."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        timestamps = [e["timestamp_ms"] for e in report.timeline]
        assert timestamps == sorted(timestamps)

    def test_timeline_inclut_transactions(self, engine_avec_transactions):
        """La timeline inclut audit + transactions."""
        report = engine_avec_transactions.investigate(actor_id="usr_0042", days_back=7)
        sources = {e["source"] for e in report.timeline}
        assert "audit" in sources
        assert "transaction" in sources

    def test_timeline_event_structure(self, engine_avec_audit):
        """Chaque événement a la structure attendue."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        event = report.timeline[0]
        assert "event_id" in event
        assert "timestamp_ms" in event
        assert "action" in event
        assert "actor_id" in event
        assert "succes" in event
        assert "severite" in event
        assert "source" in event


# ══════════════════════════════════════════════════════════════════════════════
# 3. DÉTECTION D'ANOMALIES
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectionAnomalies:

    def test_brute_force_detecte(self, engine_brute_force):
        """6 échecs de connexion en 5 min → brute_force détecté."""
        report = engine_brute_force.investigate(
            actor_id="usr_attacker", days_back=7
        )
        types = [a["type_anomalie"] for a in report.anomalies]
        assert "brute_force_login" in types

    def test_brute_force_non_detecte_sous_seuil(self, engine):
        """4 échecs → pas de brute_force."""
        events = [
            make_audit_event("usr_test", "LOGIN", False, "ERROR", 2.0 + i * 0.01)
            for i in range(4)
        ]
        engine.load_audit_events_df(pd.DataFrame(events))
        report = engine.investigate(actor_id="usr_test", days_back=7)
        types = [a["type_anomalie"] for a in report.anomalies]
        assert "brute_force_login" not in types

    def test_high_value_transaction_detectee(self, engine_avec_transactions):
        """Transaction > 10 000€ → high_value_transaction détectée."""
        report = engine_avec_transactions.investigate(
            actor_id="usr_0042", days_back=7
        )
        types = [a["type_anomalie"] for a in report.anomalies]
        assert "high_value_transaction" in types

    def test_anomalies_triees_par_score(self, engine_brute_force):
        """Les anomalies sont triées par score décroissant."""
        report = engine_brute_force.investigate(
            actor_id="usr_attacker", days_back=7
        )
        scores = [a["score"] for a in report.anomalies]
        assert scores == sorted(scores, reverse=True)

    def test_anomalie_structure(self, engine_brute_force):
        """Chaque anomalie a la structure attendue."""
        report = engine_brute_force.investigate(
            actor_id="usr_attacker", days_back=7
        )
        if report.anomalies:
            anomalie = report.anomalies[0]
            assert "signal_id" in anomalie
            assert "type_anomalie" in anomalie
            assert "severite" in anomalie
            assert "score" in anomalie
            assert "description" in anomalie
            assert "recommandation" in anomalie
            assert "events_count" in anomalie

    def test_access_denied_detecte(self, engine):
        """3+ accès refusés en 30 min → repeated_access_denied."""
        base_ms = make_ts_ms(2.0)
        events = []
        for i in range(4):
            ts_ms = base_ms + i * 300_000  # 5 minutes entre chaque
            events.append({
                "event_id":      str(uuid.uuid4()),
                "timestamp_ms":  ts_ms,
                "timestamp_iso": datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat(),
                "acteur_id":     "usr_denied",
                "action":        "READ",
                "succes":        False,
                "severite":      "WARNING",
                "resource_type": "DOC",
                "resource_id":   "doc-001",
            })
        engine.load_audit_events_df(pd.DataFrame(events))
        report = engine.investigate(actor_id="usr_denied", days_back=7)
        types = [a["type_anomalie"] for a in report.anomalies]
        assert "repeated_access_denied" in types

    def test_mass_export_detecte(self, engine):
        """10+ exports en 1h → mass_data_export détecté."""
        base_ms = make_ts_ms(2.0)
        events = []
        for i in range(12):
            ts_ms = base_ms + i * 200_000  # ~3 min entre chaque
            events.append({
                "event_id":      str(uuid.uuid4()),
                "timestamp_ms":  ts_ms,
                "timestamp_iso": datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat(),
                "acteur_id":     "usr_exfil",
                "action":        "EXPORT",
                "succes":        True,
                "severite":      "INFO",
                "resource_type": "DOC",
                "resource_id":   "doc-001",
            })
        engine.load_audit_events_df(pd.DataFrame(events))
        report = engine.investigate(actor_id="usr_exfil", days_back=7)
        types = [a["type_anomalie"] for a in report.anomalies]
        assert "mass_data_export" in types


# ══════════════════════════════════════════════════════════════════════════════
# 4. STATISTIQUES
# ══════════════════════════════════════════════════════════════════════════════

class TestStatistiques:

    def test_statistiques_vides_sans_events(self, engine):
        """Sans événements → statistiques vides."""
        report = engine.investigate(actor_id="usr_inconnu", days_back=7)
        assert report.statistics == {}

    def test_statistiques_structure(self, engine_avec_audit):
        """Les statistiques ont la structure attendue."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        stats = report.statistics
        assert "total_events" in stats
        assert "echecs" in stats
        assert "taux_echec_pct" in stats
        assert "risque_moyen" in stats
        assert "par_source" in stats
        assert "par_severite" in stats
        assert "top_actions" in stats

    def test_taux_echec_calcule(self, engine_avec_audit):
        """Le taux d'échec est correctement calculé."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        stats = report.statistics
        # 2 échecs sur 9 événements pour usr_0042
        assert stats["echecs"] == 2
        assert stats["taux_echec_pct"] == round(2 / 9 * 100, 1)

    def test_mediane_paire_correcte(self, engine):
        """Médiane correcte pour liste paire de transactions."""
        transactions = [
            make_transaction("usr_test", 100.0, "COMPLETED", False, 4.0),
            make_transaction("usr_test", 200.0, "COMPLETED", False, 3.0),
            make_transaction("usr_test", 300.0, "COMPLETED", False, 2.0),
            make_transaction("usr_test", 400.0, "COMPLETED", False, 1.0),
        ]
        engine.load_transactions_df(pd.DataFrame(transactions))
        report = engine.investigate(actor_id="usr_test", days_back=7)
        tx_stats = report.statistics.get("transactions", {})
        if tx_stats:
            # Médiane de [100, 200, 300, 400] = (200 + 300) / 2 = 250
            assert tx_stats["median"] == 250.0

    def test_statistiques_transactions(self, engine_avec_transactions):
        """Les statistiques incluent les données de transactions."""
        report = engine_avec_transactions.investigate(actor_id="usr_0042", days_back=7)
        stats = report.statistics
        assert "transactions" in stats
        tx = stats["transactions"]
        assert "count" in tx
        assert "total" in tx
        assert "moyenne" in tx
        assert "median" in tx
        assert "max" in tx
        assert "min" in tx


# ══════════════════════════════════════════════════════════════════════════════
# 5. ÉVALUATION DU RISQUE
# ══════════════════════════════════════════════════════════════════════════════

class TestEvaluationRisque:

    def test_risque_faible_sans_anomalies(self, engine_avec_audit):
        """Sans anomalies critiques → risque FAIBLE ou MODÉRÉ."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        assert report.risk_assessment["niveau"] in ("FAIBLE", "MODÉRÉ", "ÉLEVÉ")

    def test_risque_eleve_avec_brute_force(self, engine_brute_force):
        """Brute force détecté → risque élevé."""
        report = engine_brute_force.investigate(
            actor_id="usr_attacker", days_back=7
        )
        assert report.risk_assessment["score_global"] > 0.5

    def test_score_entre_0_et_1(self, engine_avec_audit):
        """Le score de risque est toujours entre 0 et 1."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        score = report.risk_assessment["score_global"]
        assert 0.0 <= score <= 1.0

    def test_niveaux_possibles(self, engine_avec_audit):
        """Le niveau de risque est toujours l'un des 4 niveaux."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        assert report.risk_assessment["niveau"] in ("FAIBLE", "MODÉRÉ", "ÉLEVÉ", "CRITIQUE")

    def test_risk_level_coherent(self, engine_avec_audit):
        """risk_level() retourne le même niveau que risk_assessment."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        assert report.risk_level() == report.risk_assessment["niveau"]

    def test_structure_risk_assessment(self, engine_avec_audit):
        """La structure du risk_assessment est complète."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        risk = report.risk_assessment
        assert "score_global" in risk
        assert "niveau" in risk
        assert "anomalies_total" in risk
        assert "critiques" in risk
        assert "erreurs" in risk


# ══════════════════════════════════════════════════════════════════════════════
# 6. RAPPORT
# ══════════════════════════════════════════════════════════════════════════════

class TestRapport:

    def test_rapport_structure_complete(self, engine_avec_audit):
        """Le rapport contient tous les champs attendus."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        d = report.to_dict()
        assert "report_id" in d
        assert "generated_at" in d
        assert "investigator" in d
        assert "subject" in d
        assert "summary" in d
        assert "timeline" in d
        assert "anomalies" in d
        assert "statistics" in d
        assert "risk_assessment" in d
        assert "recommendations" in d
        assert "graph_summary" in d
        assert "signature_hash" in d

    def test_rapport_id_unique(self, engine_avec_audit):
        """Deux rapports ont des IDs différents."""
        r1 = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        r2 = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        assert r1.report_id != r2.report_id

    def test_signature_hash_presente(self, engine_avec_audit):
        """Le rapport est signé avec un hash SHA-256."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        assert report.signature_hash is not None
        assert len(report.signature_hash) == 64  # SHA-256 hex

    def test_signature_hash_deterministe(self, engine_avec_audit):
        """Même contenu → même hash (déterministe)."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        # Recalculer le hash manuellement
        import hashlib
        content = json.dumps({
            "report_id":   report.report_id,
            "generated_at": report.generated_at,
            "summary":     report.summary,
            "anomalies":   report.anomalies,
        }, sort_keys=True, ensure_ascii=False).encode("utf-8")
        expected_hash = hashlib.sha256(content).hexdigest()
        assert report.signature_hash == expected_hash

    def test_recommandations_non_vides(self, engine_avec_audit):
        """Le rapport contient toujours des recommandations."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        assert len(report.recommendations) > 0

    def test_recommandations_rgpd(self, engine_avec_audit):
        """La recommandation RGPD Art.30 est toujours présente."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        rgpd_mention = any("RGPD" in r or "3 ans" in r for r in report.recommendations)
        assert rgpd_mention

    def test_save_report(self, engine_avec_audit, tmp_path):
        """Sauvegarder le rapport → fichier JSON valide."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        path = str(tmp_path / "rapport" / "investigation.json")
        engine_avec_audit.save_report(report, path)
        assert Path(path).exists()
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert "report_id" in data
        assert data["report_id"] == report.report_id

    def test_subject_correct(self, engine_avec_audit):
        """Le subject du rapport contient les bonnes infos."""
        report = engine_avec_audit.investigate(
            actor_id="usr_0042", days_back=14
        )
        assert report.subject["actor_id"] == "usr_0042"
        assert report.subject["days_back"] == 14


# ══════════════════════════════════════════════════════════════════════════════
# 7. GRAPH SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

class TestGraphSummary:

    def test_graph_summary_structure(self, engine_avec_audit):
        """Le graph_summary a la structure attendue."""
        report = engine_avec_audit.investigate(actor_id="usr_0042", days_back=7)
        g = report.graph_summary
        assert "total_actors" in g
        assert "total_resources" in g
        assert "total_edges" in g
        assert "top_actors" in g
        assert "top_resources" in g
        assert "top_relations" in g

    def test_graph_summary_acteurs(self, engine_avec_audit):
        """Le graph summary compte correctement les acteurs."""
        report = engine_avec_audit.investigate(days_back=7)
        assert report.graph_summary["total_actors"] >= 2  # usr_0042 + usr_9999


# ══════════════════════════════════════════════════════════════════════════════
# 8. UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

class TestUtilitaires:

    def test_categorize_action_login(self):
        assert _categorize_action("LOGIN") == "auth"

    def test_categorize_action_logout(self):
        assert _categorize_action("LOGOUT") == "auth"

    def test_categorize_action_read(self):
        assert _categorize_action("READ") == "data_access"

    def test_categorize_action_write(self):
        assert _categorize_action("WRITE") == "data_access"

    def test_categorize_action_export(self):
        assert _categorize_action("EXPORT") == "data_access"

    def test_categorize_action_api_call(self):
        assert _categorize_action("API_CALL") == "api"

    def test_categorize_action_config(self):
        assert _categorize_action("CONFIG_CHANGE") == "config"

    def test_categorize_action_inconnu(self):
        assert _categorize_action("ACTION_INCONNUE") == "system"

    def test_detection_rules_completes(self):
        """Toutes les règles sont dans RULES_BY_NAME."""
        for rule in DETECTION_RULES:
            assert rule.name in RULES_BY_NAME

    def test_detection_rules_scores_valides(self):
        """Tous les scores de détection sont entre 0 et 1."""
        for rule in DETECTION_RULES:
            assert 0.0 <= rule.score <= 1.0

    def test_detection_rules_severites_valides(self):
        """Toutes les sévérités sont valides."""
        severites_valides = {"CRITICAL", "ERROR", "WARNING", "INFO"}
        for rule in DETECTION_RULES:
            assert rule.severite in severites_valides


# ══════════════════════════════════════════════════════════════════════════════
# 9. FLAGS TIMELINE
# ══════════════════════════════════════════════════════════════════════════════

class TestFlagsTimeline:

    def test_flag_echec_sur_action_echouee(self, engine):
        """Action échouée → flag ECHEC."""
        events = [make_audit_event("usr_test", "READ", False, "WARNING", 1.0)]
        engine.load_audit_events_df(pd.DataFrame(events))
        report = engine.investigate(actor_id="usr_test", days_back=7)
        flags = report.timeline[0]["flags"]
        assert "ECHEC" in flags

    def test_flag_alerte_securite_sur_error(self, engine):
        """Sévérité ERROR → flag ALERTE_SECURITE."""
        events = [make_audit_event("usr_test", "DELETE", False, "ERROR", 1.0)]
        engine.load_audit_events_df(pd.DataFrame(events))
        report = engine.investigate(actor_id="usr_test", days_back=7)
        flags = report.timeline[0]["flags"]
        assert "ALERTE_SECURITE" in flags

    def test_flag_transaction_anomalie(self, engine):
        """Transaction anomalie → flag ANOMALIE_*."""
        tx = [make_transaction("usr_test", 500_000.0, "COMPLETED", True, 1.0)]
        engine.load_transactions_df(pd.DataFrame(tx))
        report = engine.investigate(actor_id="usr_test", days_back=7)
        tx_events = [e for e in report.timeline if e["source"] == "transaction"]
        if tx_events:
            flags = tx_events[0]["flags"]
            assert any("ANOMALIE" in f for f in flags)

    def test_flag_montant_eleve(self, engine):
        """Transaction > 10 000€ → flag MONTANT_ELEVE."""
        tx = [make_transaction("usr_test", 15_000.0, "COMPLETED", False, 1.0)]
        engine.load_transactions_df(pd.DataFrame(tx))
        report = engine.investigate(actor_id="usr_test", days_back=7)
        tx_events = [e for e in report.timeline if e["source"] == "transaction"]
        if tx_events:
            flags = tx_events[0]["flags"]
            assert "MONTANT_ELEVE" in flags