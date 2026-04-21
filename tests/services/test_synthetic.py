"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Tests Service Synthetic                             ║
║   Couvre : générateurs, factory, schémas, cohérence, RGPD, sauvegarde     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Lancer :
    pytest tests/services/test_synthetic.py -v
    pytest tests/services/test_synthetic.py -v --cov=services.synthetic_service
"""

import json
from pathlib import Path

import pandas as pd
import pytest

from services.synthetic_service import (
    SyntheticDataFactory,
    TransactionGenerator,
    ContactPMEGenerator,
    AuditEventGenerator,
    EntreprisePMEGenerator,
    BaseGenerator,
    REGISTRY,
    SECTEURS_PME,
    BANQUES_FR,
    VILLES_FR,
    MOYENS_PAIEMENT,
    STATUTS_TX,
    ACTIONS_AUDIT,
    _audit_message,
)


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def factory() -> SyntheticDataFactory:
    """Factory avec seed fixe pour reproductibilité."""
    return SyntheticDataFactory(locale="fr_FR", seed=42)


@pytest.fixture
def tx_gen() -> TransactionGenerator:
    return TransactionGenerator(locale="fr_FR", seed=42)


@pytest.fixture
def contact_gen() -> ContactPMEGenerator:
    return ContactPMEGenerator(locale="fr_FR", seed=42)


@pytest.fixture
def audit_gen() -> AuditEventGenerator:
    return AuditEventGenerator(locale="fr_FR", seed=42)


@pytest.fixture
def entreprise_gen() -> EntreprisePMEGenerator:
    return EntreprisePMEGenerator(locale="fr_FR", seed=42)


# ══════════════════════════════════════════════════════════════════════════════
# 1. FACTORY — Initialisation & Schémas
# ══════════════════════════════════════════════════════════════════════════════

class TestFactoryInit:

    def test_factory_init_avec_seed(self):
        """Factory avec seed → reproductible."""
        f = SyntheticDataFactory(locale="fr_FR", seed=42)
        assert f.seed == 42
        assert f.locale == "fr_FR"

    def test_factory_init_sans_seed(self):
        """Factory sans seed → fonctionne quand même."""
        f = SyntheticDataFactory(locale="fr_FR", seed=None)
        assert f.seed is None

    def test_registry_contient_tous_schemas(self):
        """Le REGISTRY contient les 4 schémas principaux."""
        assert "transactions" in REGISTRY
        assert "contacts" in REGISTRY
        assert "audit_events" in REGISTRY
        assert "entreprises" in REGISTRY

    def test_schema_inconnu_leve_erreur(self, factory):
        """Schéma inconnu → ValueError."""
        with pytest.raises(ValueError, match="Schéma inconnu"):
            factory.generate("schema_inexistant", n=10)

    def test_generateur_mis_en_cache(self, factory):
        """Le même générateur est réutilisé (cache)."""
        factory.generate("transactions", n=5)
        factory.generate("transactions", n=5)
        assert len(factory._generators) == 1

    def test_generateurs_differents_par_schema(self, factory):
        """Schémas différents → générateurs différents."""
        factory.generate("transactions", n=5)
        factory.generate("audit_events", n=5)
        assert len(factory._generators) == 2


# ══════════════════════════════════════════════════════════════════════════════
# 2. GÉNÉRATION — Nombre d'enregistrements & colonnes
# ══════════════════════════════════════════════════════════════════════════════

class TestGeneration:

    def test_transactions_nombre_correct(self, factory):
        """generate('transactions', n=100) → 100 lignes."""
        df = factory.generate("transactions", n=100)
        assert len(df) == 100

    def test_audit_events_nombre_correct(self, factory):
        df = factory.generate("audit_events", n=50)
        assert len(df) == 50

    def test_contacts_nombre_correct(self, factory):
        df = factory.generate("contacts", n=30)
        assert len(df) == 30

    def test_entreprises_nombre_correct(self, factory):
        df = factory.generate("entreprises", n=20)
        assert len(df) == 20

    def test_transactions_colonnes_attendues(self, factory):
        """Le DataFrame transactions contient les colonnes attendues."""
        df = factory.generate("transactions", n=10)
        colonnes = list(df.columns)
        assert "transaction_id" in colonnes
        assert "montant_eur" in colonnes
        assert "statut" in colonnes
        assert "est_anomalie" in colonnes
        assert "risque_score" in colonnes

    def test_audit_events_colonnes_attendues(self, factory):
        df = factory.generate("audit_events", n=10)
        colonnes = list(df.columns)
        assert "event_id" in colonnes
        assert "acteur_id" in colonnes
        assert "action" in colonnes
        assert "succes" in colonnes
        assert "severite" in colonnes

    def test_contacts_colonnes_attendues(self, factory):
        df = factory.generate("contacts", n=10)
        colonnes = list(df.columns)
        assert "contact_id" in colonnes
        assert "email" in colonnes
        assert "consentement_rgpd" in colonnes
        assert "_synthetic" in colonnes

    def test_entreprises_colonnes_attendues(self, factory):
        df = factory.generate("entreprises", n=10)
        colonnes = list(df.columns)
        assert "entreprise_id" in colonnes
        assert "siret" in colonnes
        assert "raison_sociale" in colonnes
        assert "_synthetic" in colonnes

    def test_retourne_dataframe(self, factory):
        """generate() retourne toujours un DataFrame Pandas."""
        result = factory.generate("transactions", n=10)
        assert isinstance(result, pd.DataFrame)

    def test_reproductibilite_avec_seed(self):
        """Même seed → mêmes données."""
        f1 = SyntheticDataFactory(locale="fr_FR", seed=42)
        f2 = SyntheticDataFactory(locale="fr_FR", seed=42)
        df1 = f1.generate("transactions", n=5)
        df2 = f2.generate("transactions", n=5)
        assert list(df1["transaction_id"]) == list(df2["transaction_id"])


# ══════════════════════════════════════════════════════════════════════════════
# 3. TRANSACTIONS — Cohérence métier
# ══════════════════════════════════════════════════════════════════════════════

class TestTransactions:

    def test_montants_positifs(self, factory):
        """Tous les montants sont positifs."""
        df = factory.generate("transactions", n=100)
        assert (df["montant_eur"] > 0).all()

    def test_statuts_valides(self, factory):
        """Les statuts sont dans la liste autorisée."""
        df = factory.generate("transactions", n=100)
        assert set(df["statut"].unique()).issubset(set(STATUTS_TX))

    def test_devise_eur(self, factory):
        """La devise est toujours EUR."""
        df = factory.generate("transactions", n=50)
        assert (df["devise"] == "EUR").all()

    def test_moyens_paiement_valides(self, factory):
        """Les moyens de paiement sont dans la liste autorisée."""
        df = factory.generate("transactions", n=100)
        assert set(df["moyen_paiement"].unique()).issubset(set(MOYENS_PAIEMENT))

    def test_risque_score_entre_0_et_1(self, factory):
        """Le risque score est entre 0 et 1."""
        df = factory.generate("transactions", n=100)
        assert (df["risque_score"] >= 0).all()
        assert (df["risque_score"] <= 1).all()

    def test_anomalies_injectees(self, factory):
        """Avec anomaly_rate=0.1 → des anomalies sont présentes."""
        df = factory.generate("transactions", n=100, anomaly_rate=0.1)
        assert df["est_anomalie"].sum() > 0

    def test_transaction_ids_uniques(self, factory):
        """Les IDs de transactions sont uniques."""
        df = factory.generate("transactions", n=100)
        assert df["transaction_id"].nunique() == 100

    def test_client_hash_est_sha256(self, factory):
        """Le client_hash est un SHA-256 valide (64 caractères hex)."""
        df = factory.generate("transactions", n=10)
        for hash_val in df["client_hash"]:
            assert len(hash_val) == 64
            assert all(c in "0123456789abcdef" for c in hash_val)

    def test_villes_francaises(self, factory):
        """Les villes sont dans la liste des villes françaises."""
        villes_valides = {v[0] for v in VILLES_FR}
        df = factory.generate("transactions", n=50)
        assert set(df["ville"].unique()).issubset(villes_valides)

    def test_anomalie_montant_suspect(self, tx_gen):
        """Pattern montant_suspect → montant élevé."""
        record = tx_gen.generate_one(inject_anomaly=True)
        if record["type_anomalie"] == "montant_suspect":
            assert record["montant_eur"] >= 5000

    def test_anomalie_risque_score_eleve(self, tx_gen):
        """Une anomalie a un risque score élevé."""
        # Générer jusqu'à avoir une anomalie
        for _ in range(20):
            record = tx_gen.generate_one(inject_anomaly=True)
            assert record["est_anomalie"] is True
            assert record["risque_score"] >= 0.7
            break


# ══════════════════════════════════════════════════════════════════════════════
# 4. CONTACTS PME — Cohérence RGPD
# ══════════════════════════════════════════════════════════════════════════════

class TestContacts:

    def test_contact_ids_uniques(self, factory):
        df = factory.generate("contacts", n=50)
        assert df["contact_id"].nunique() == 50

    def test_emails_format_valide(self, factory):
        """Les emails contiennent un @."""
        df = factory.generate("contacts", n=20)
        assert df["email"].str.contains("@").all()

    def test_consentement_rgpd_booleen(self, factory):
        """Le consentement RGPD est un booléen."""
        df = factory.generate("contacts", n=50)
        assert df["consentement_rgpd"].dtype == bool or \
               set(df["consentement_rgpd"].unique()).issubset({True, False})

    def test_pays_france(self, factory):
        """Le pays est toujours FR."""
        df = factory.generate("contacts", n=20)
        assert (df["pays"] == "FR").all()

    def test_flag_synthetic(self, factory):
        """Le flag _synthetic est True pour tous les contacts."""
        df = factory.generate("contacts", n=20)
        assert (df["_synthetic"] == True).all()

    def test_mobile_format(self, factory):
        """Le mobile commence par 06."""
        df = factory.generate("contacts", n=20)
        assert df["mobile"].str.startswith("06").all()

    def test_retention_jours_valides(self, factory):
        """La rétention est 365, 730 ou 1095 jours."""
        df = factory.generate("contacts", n=50)
        assert set(df["retention_jours"].unique()).issubset({365, 730, 1095})

    def test_contact_lie_a_entreprise(self, contact_gen):
        """Un contact avec company_id est correctement lié."""
        company_id = "test-company-123"
        contact = contact_gen.generate_one(company_id=company_id)
        assert contact["company_id"] == company_id


# ══════════════════════════════════════════════════════════════════════════════
# 5. AUDIT EVENTS — Cohérence
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditEvents:

    def test_event_ids_uniques(self, factory):
        df = factory.generate("audit_events", n=100)
        assert df["event_id"].nunique() == 100

    def test_actions_valides(self, factory):
        """Les actions sont dans la liste autorisée."""
        df = factory.generate("audit_events", n=100)
        assert set(df["action"].unique()).issubset(set(ACTIONS_AUDIT))

    def test_succes_booleen(self, factory):
        """Le champ succes est un booléen."""
        df = factory.generate("audit_events", n=50)
        assert set(df["succes"].unique()).issubset({True, False})

    def test_taux_echec(self, factory):
        """Avec failure_rate=0.1 → environ 10% d'échecs."""
        df = factory.generate("audit_events", n=200, failure_rate=0.1)
        echec_rate = (~df["succes"]).mean()
        # Tolérance large car aléatoire
        assert 0.05 <= echec_rate <= 0.20

    def test_trie_par_timestamp(self, factory):
        """Les audit events sont triés par timestamp."""
        df = factory.generate("audit_events", n=50)
        timestamps = list(df["timestamp_ms"])
        assert timestamps == sorted(timestamps)

    def test_flag_synthetic(self, factory):
        """Le flag _synthetic est présent."""
        df = factory.generate("audit_events", n=10)
        assert "_synthetic" in df.columns
        assert (df["_synthetic"] == True).all()

    def test_failure_force(self, audit_gen):
        """force_failure=True → succes=False."""
        record = audit_gen.generate_one(force_failure=True)
        assert record["succes"] is False
        assert record["severite"] == "ERROR"


# ══════════════════════════════════════════════════════════════════════════════
# 6. ENTREPRISES PME — Cohérence
# ══════════════════════════════════════════════════════════════════════════════

class TestEntreprises:

    def test_entreprise_ids_uniques(self, factory):
        df = factory.generate("entreprises", n=20)
        assert df["entreprise_id"].nunique() == 20

    def test_siret_14_chiffres(self, factory):
        """Le SIRET fait exactement 14 chiffres."""
        df = factory.generate("entreprises", n=10)
        assert (df["siret"].str.len() == 14).all()
        assert df["siret"].str.isdigit().all()

    def test_siren_9_chiffres(self, factory):
        """Le SIREN fait exactement 9 chiffres."""
        df = factory.generate("entreprises", n=10)
        assert (df["siren"].str.len() == 9).all()

    def test_formes_juridiques_valides(self, factory):
        """Les formes juridiques sont valides."""
        formes_valides = {"SARL", "SAS", "SASU", "EURL", "SA", "EI"}
        df = factory.generate("entreprises", n=50)
        assert set(df["forme_juridique"].unique()).issubset(formes_valides)

    def test_iban_commence_par_fr76(self, factory):
        """L'IBAN commence par FR76."""
        df = factory.generate("entreprises", n=10)
        assert df["iban_principal"].str.startswith("FR76").all()

    def test_plans_valides(self, factory):
        """Les plans sont starter, pro ou enterprise."""
        plans_valides = {"starter", "pro", "enterprise"}
        df = factory.generate("entreprises", n=50)
        assert set(df["plan"].unique()).issubset(plans_valides)

    def test_score_risque_entre_0_et_1(self, factory):
        df = factory.generate("entreprises", n=50)
        assert (df["score_risque"] >= 0).all()
        assert (df["score_risque"] <= 1).all()

    def test_ca_annuel_positif(self, factory):
        df = factory.generate("entreprises", n=20)
        assert (df["ca_annuel_eur"] > 0).all()

    def test_flag_synthetic(self, factory):
        df = factory.generate("entreprises", n=10)
        assert (df["_synthetic"] == True).all()


# ══════════════════════════════════════════════════════════════════════════════
# 7. SAUVEGARDE
# ══════════════════════════════════════════════════════════════════════════════

class TestSauvegarde:

    def test_save_parquet(self, factory, tmp_path):
        """Sauvegarder en Parquet → fichier créé."""
        df = factory.generate("transactions", n=10)
        path = str(tmp_path / "test.parquet")
        result = factory.save(df, path)
        assert Path(path).exists()
        assert result == Path(path)

    def test_save_csv(self, factory, tmp_path):
        """Sauvegarder en CSV → fichier créé."""
        df = factory.generate("transactions", n=10)
        path = str(tmp_path / "test.csv")
        factory.save(df, path)
        assert Path(path).exists()
        # Vérifier que le CSV est lisible
        df_reload = pd.read_csv(path)
        assert len(df_reload) == 10

    def test_save_json(self, factory, tmp_path):
        """Sauvegarder en JSON → fichier créé."""
        df = factory.generate("transactions", n=10)
        path = str(tmp_path / "test.json")
        factory.save(df, path)
        assert Path(path).exists()

    def test_save_format_auto_parquet(self, factory, tmp_path):
        """Détection automatique du format .parquet."""
        df = factory.generate("transactions", n=10)
        path = str(tmp_path / "test.parquet")
        factory.save(df, path, fmt="auto")
        assert Path(path).exists()

    def test_save_format_auto_csv(self, factory, tmp_path):
        """Détection automatique du format .csv."""
        df = factory.generate("transactions", n=10)
        path = str(tmp_path / "test.csv")
        factory.save(df, path, fmt="auto")
        assert Path(path).exists()

    def test_save_cree_dossier_parent(self, factory, tmp_path):
        """save() crée le dossier parent si nécessaire."""
        df = factory.generate("transactions", n=5)
        path = str(tmp_path / "sous_dossier" / "data.parquet")
        factory.save(df, path)
        assert Path(path).exists()

    def test_save_format_inconnu_leve_erreur(self, factory, tmp_path):
        """Format non supporté → ValueError."""
        df = factory.generate("transactions", n=5)
        path = str(tmp_path / "test.xlsx")
        with pytest.raises(ValueError, match="Format non supporté"):
            factory.save(df, path, fmt="xlsx")

    def test_parquet_roundtrip(self, factory, tmp_path):
        """Écrire puis relire en Parquet → données identiques."""
        df = factory.generate("transactions", n=20)
        path = str(tmp_path / "roundtrip.parquet")
        factory.save(df, path)
        df_reload = pd.read_parquet(path)
        assert len(df_reload) == len(df)
        assert list(df_reload.columns) == list(df.columns)


# ══════════════════════════════════════════════════════════════════════════════
# 8. DESCRIBE
# ══════════════════════════════════════════════════════════════════════════════

class TestDescribe:

    def test_describe_retourne_string(self, factory):
        df = factory.generate("transactions", n=10)
        result = factory.describe(df, schema_name="transactions")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_describe_contient_nom_schema(self, factory):
        df = factory.generate("transactions", n=10)
        result = factory.describe(df, schema_name="transactions")
        assert "transactions" in result

    def test_describe_contient_nombre_lignes(self, factory):
        df = factory.generate("transactions", n=42)
        result = factory.describe(df, schema_name="transactions")
        assert "42" in result


# ══════════════════════════════════════════════════════════════════════════════
# 9. UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

class TestUtilitaires:

    def test_audit_message_login_succes(self):
        msg = _audit_message("LOGIN", "API", "api-001", True)
        assert "Connexion réussie" in msg
        assert "API:api-001" in msg

    def test_audit_message_login_echec(self):
        msg = _audit_message("LOGIN", "API", "api-001", False)
        assert "Échec de connexion" in msg

    def test_audit_message_read_echec(self):
        msg = _audit_message("READ", "DOC", "doc-001", False)
        assert "Accès refusé" in msg

    def test_audit_message_action_inconnue(self):
        msg = _audit_message("ACTION_INCONNUE", "RES", "res-001", True)
        assert "Action" in msg

    def test_constantes_non_vides(self):
        """Les constantes métier sont toutes non vides."""
        assert len(SECTEURS_PME) > 0
        assert len(BANQUES_FR) > 0
        assert len(VILLES_FR) > 0
        assert len(MOYENS_PAIEMENT) > 0
        assert len(STATUTS_TX) > 0
        assert len(ACTIONS_AUDIT) > 0

    def test_villes_fr_structure(self):
        """Chaque ville est un tuple (nom, departement)."""
        for ville in VILLES_FR:
            assert len(ville) == 2
            assert isinstance(ville[0], str)
            assert isinstance(ville[1], str)

    def test_base_generator_iban(self):
        """L'IBAN généré commence par FR76."""
        gen = BaseGenerator(locale="fr_FR", seed=42)
        iban = gen._iban_fr()
        assert iban.startswith("FR76")
        assert len(iban) == 27  # FR76 + 23 chiffres

    def test_base_generator_siret(self):
        """Le SIRET généré fait 14 chiffres."""
        gen = BaseGenerator(locale="fr_FR", seed=42)
        siret = gen._siret()
        assert len(siret) == 14
        assert siret.isdigit()

    def test_base_generator_naf_code(self):
        """Le code NAF est dans la liste."""
        naf_valides = {"4711F", "5610A", "6201Z", "4120A", "8621Z",
                       "6820B", "4941A", "7022Z", "8559A", "5630Z"}
        gen = BaseGenerator(locale="fr_FR", seed=42)
        naf = gen._naf_code()
        assert naf in naf_valides