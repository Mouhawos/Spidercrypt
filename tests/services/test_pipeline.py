"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT — Tests Service Pipeline                              ║
║   Couvre : crypto, PII, chiffrement colonnes, audit, edge cases            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Lancer :
    pytest tests/services/test_pipeline.py -v
    pytest tests/services/test_pipeline.py -v --cov=services.pipeline_service
"""

import base64
import hashlib
import os
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from services.pipeline_service import (
    SpidercryptCrypto,
    SpidercryptPipeline,
    AvroCodec,
    AVRO_SCHEMAS,
    generate_master_key,
)


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def master_key() -> str:
    """Génère une clé maître valide pour les tests."""
    return base64.b64encode(os.urandom(32)).decode()


@pytest.fixture
def crypto(master_key) -> SpidercryptCrypto:
    """Instance SpidercryptCrypto avec clé aléatoire."""
    return SpidercryptCrypto(master_key)


@pytest.fixture
def pipeline(master_key) -> SpidercryptPipeline:
    """Instance SpidercryptPipeline avec clé aléatoire."""
    return SpidercryptPipeline(master_key_b64=master_key)


@pytest.fixture
def df_avec_pii() -> pd.DataFrame:
    """DataFrame avec colonnes PII typiques."""
    return pd.DataFrame([
        {
            "transaction_id": "TX001",
            "email":          "alice@pme.fr",
            "phone":          "0612345678",
            "montant":        9999,
            "statut":         "COMPLETED",
        },
        {
            "transaction_id": "TX002",
            "email":          "bob@startup.io",
            "phone":          "0698765432",
            "montant":        4500,
            "statut":         "PENDING",
        },
    ])


@pytest.fixture
def df_sans_pii() -> pd.DataFrame:
    """DataFrame sans colonnes PII."""
    return pd.DataFrame([
        {"transaction_id": "TX001", "montant": 9999,  "statut": "COMPLETED"},
        {"transaction_id": "TX002", "montant": 4500,  "statut": "PENDING"},
        {"transaction_id": "TX003", "montant": 12000, "statut": "FAILED"},
    ])


# ══════════════════════════════════════════════════════════════════════════════
# 1. CRYPTO — SpidercryptCrypto
# ══════════════════════════════════════════════════════════════════════════════

class TestSpidercryptCrypto:

    def test_encrypt_decrypt_roundtrip_string(self, crypto):
        """Chiffrer puis déchiffrer une chaîne → données identiques."""
        original = "alice@pme.fr"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted.decode("utf-8") == original

    def test_encrypt_decrypt_roundtrip_bytes(self, crypto):
        """Chiffrer puis déchiffrer des bytes → données identiques."""
        original = b"donnees_sensibles_12345"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_encrypt_produit_bytes(self, crypto):
        """Le résultat du chiffrement est toujours des bytes."""
        result = crypto.encrypt("test")
        assert isinstance(result, bytes)

    def test_encrypt_different_a_chaque_fois(self, crypto):
        """Deux chiffrements du même texte → résultats différents (nonce aléatoire)."""
        texte = "alice@pme.fr"
        enc1 = crypto.encrypt(texte)
        enc2 = crypto.encrypt(texte)
        assert enc1 != enc2

    def test_decrypt_different_donne_meme_resultat(self, crypto):
        """Deux chiffrements différents → même plaintext après déchiffrement."""
        texte = "alice@pme.fr"
        enc1 = crypto.encrypt(texte)
        enc2 = crypto.encrypt(texte)
        assert crypto.decrypt(enc1).decode() == crypto.decrypt(enc2).decode()

    def test_taille_ciphertext(self, crypto):
        """Le ciphertext est plus grand que le plaintext (nonce + tag)."""
        plaintext = "test"
        encrypted = crypto.encrypt(plaintext)
        assert len(encrypted) > len(plaintext.encode())

    def test_nonce_inclus_dans_ciphertext(self, crypto):
        """Les 12 premiers bytes sont le nonce."""
        encrypted = crypto.encrypt("test")
        assert len(encrypted) >= SpidercryptCrypto.NONCE_SIZE

    def test_aad_roundtrip(self, crypto):
        """Chiffrement avec AAD → déchiffrement avec même AAD."""
        plaintext = "données_sensibles"
        aad = b"spidercrypt"
        encrypted = crypto.encrypt(plaintext, aad)
        decrypted = crypto.decrypt(encrypted, aad)
        assert decrypted.decode() == plaintext

    def test_mauvaise_cle_echoue(self, master_key):
        """Déchiffrer avec une mauvaise clé → exception."""
        crypto1 = SpidercryptCrypto(master_key)
        autre_key = base64.b64encode(os.urandom(32)).decode()
        crypto2 = SpidercryptCrypto(autre_key)
        encrypted = crypto1.encrypt("secret")
        with pytest.raises(Exception):
            crypto2.decrypt(encrypted)

    def test_cle_invalide_trop_courte(self):
        """Clé trop courte → ValueError."""
        cle_courte = base64.b64encode(b"trop_court").decode()
        with pytest.raises(ValueError, match="32 bytes"):
            SpidercryptCrypto(cle_courte)

    def test_generate_key_b64_longueur(self):
        """La clé générée fait bien 32 bytes en base64."""
        key = SpidercryptCrypto.generate_key_b64()
        raw = base64.b64decode(key)
        assert len(raw) == 32

    def test_generate_key_b64_unique(self):
        """Deux clés générées sont différentes."""
        key1 = SpidercryptCrypto.generate_key_b64()
        key2 = SpidercryptCrypto.generate_key_b64()
        assert key1 != key2

    def test_encrypt_valeurs_vides(self, crypto):
        """Chiffrer une chaîne vide → fonctionne sans erreur."""
        encrypted = crypto.encrypt("")
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == b""

    def test_encrypt_texte_long(self, crypto):
        """Chiffrer un texte long → roundtrip correct."""
        long_text = "a" * 10_000
        encrypted = crypto.encrypt(long_text)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted.decode() == long_text


# ══════════════════════════════════════════════════════════════════════════════
# 2. AVRO CODEC
# ══════════════════════════════════════════════════════════════════════════════

class TestAvroCodec:

    def test_schema_connu_fonctionne(self):
        """Instancier avec un schéma connu → pas d'erreur."""
        codec = AvroCodec("transactions")
        assert codec.schema_name == "transactions"

    def test_schema_inconnu_leve_erreur(self):
        """Schéma inconnu → ValueError."""
        with pytest.raises(ValueError, match="Schéma inconnu"):
            AvroCodec("schema_inexistant")

    def test_tous_les_schemas_disponibles(self):
        """Tous les schémas dans AVRO_SCHEMAS sont instanciables."""
        for schema_name in AVRO_SCHEMAS:
            codec = AvroCodec(schema_name)
            assert codec.schema_name == schema_name

    def test_serialize_deserialize_audit_events(self):
        """Sérialiser puis désérialiser des audit_events → données identiques."""
        codec = AvroCodec("audit_events")
        records = [
            {
                "event_id":      "evt-001",
                "actor_id":      "usr_0042",
                "action":        "LOGIN",
                "resource_type": "API",
                "resource_id":   "api-001",
                "ip_address":    "192.168.1.1",
                "success":       True,
                "details":       None,
            }
        ]
        serialized   = codec.serialize_batch(records)
        deserialized = list(codec.deserialize_batch(serialized))
        assert len(deserialized) == 1
        assert deserialized[0]["event_id"]  == "evt-001"
        assert deserialized[0]["actor_id"]  == "usr_0042"
        assert deserialized[0]["success"]   is True

    def test_serialize_produit_bytes(self):
        """La sérialisation produit des bytes."""
        codec = AvroCodec("audit_events")
        records = [{
            "event_id": "e1", "actor_id": "u1", "action": "READ",
            "resource_type": "DOC", "resource_id": "d1",
            "ip_address": None, "success": True, "details": None,
        }]
        result = codec.serialize_batch(records)
        assert isinstance(result, bytes)
        assert len(result) > 0


# ══════════════════════════════════════════════════════════════════════════════
# 3. PIPELINE — Initialisation
# ══════════════════════════════════════════════════════════════════════════════

class TestPipelineInit:

    def test_init_avec_cle_valide(self, master_key):
        """Initialisation avec clé valide → pas d'erreur."""
        pipeline = SpidercryptPipeline(master_key_b64=master_key)
        assert pipeline.crypto is not None

    def test_init_sans_cle_leve_erreur(self, monkeypatch):
        """Sans clé → ValueError."""
        monkeypatch.delenv("SPIDERCRYPT_MASTER_KEY", raising=False)
        with pytest.raises(ValueError):
            SpidercryptPipeline(master_key_b64=None)

    def test_init_depuis_variable_env(self, master_key, monkeypatch):
        """Clé depuis variable d'environnement → fonctionne."""
        monkeypatch.setenv("SPIDERCRYPT_MASTER_KEY", master_key)
        pipeline = SpidercryptPipeline()
        assert pipeline.crypto is not None

    def test_audit_log_vide_au_demarrage(self, pipeline):
        """Le log d'audit est vide au démarrage."""
        assert pipeline._audit_log == []


# ══════════════════════════════════════════════════════════════════════════════
# 4. CHIFFREMENT PII
# ══════════════════════════════════════════════════════════════════════════════

class TestEncryptPiiColumns:

    def test_colonnes_pii_chiffrees(self, pipeline, df_avec_pii):
        """Les colonnes PII sont remplacées par leurs versions chiffrées."""
        result = pipeline.encrypt_pii_columns(df_avec_pii)
        assert "email" not in result.columns
        assert "phone" not in result.columns
        assert "email_enc" in result.columns
        assert "phone_enc" in result.columns

    def test_colonnes_non_pii_intactes(self, pipeline, df_avec_pii):
        """Les colonnes non-PII ne sont pas modifiées."""
        result = pipeline.encrypt_pii_columns(df_avec_pii)
        assert "transaction_id" in result.columns
        assert "montant" in result.columns
        assert "statut" in result.columns

    def test_valeurs_chiffrees_sont_bytes(self, pipeline, df_avec_pii):
        """Les valeurs chiffrées sont des bytes."""
        result = pipeline.encrypt_pii_columns(df_avec_pii)
        for val in result["email_enc"]:
            assert isinstance(val, bytes)

    def test_chiffrement_reversible(self, pipeline, df_avec_pii):
         result = pipeline.encrypt_pii_columns(df_avec_pii)
         original_email = "alice@pme.fr"
         encrypted_email = result["email_enc"].iloc[0]
         decrypted = pipeline.crypto.decrypt(encrypted_email, aad=b"spidercrypt") # ← cette ligne
         assert decrypted.decode() == original_email

    def test_strategie_hash(self, pipeline, df_avec_pii):
        """Stratégie hash → colonne remplacée par SHA-256."""
        result = pipeline.encrypt_pii_columns(df_avec_pii, strategy="hash")
        assert "email" in result.columns
        assert "email_enc" not in result.columns
        # Vérifier que c'est bien un SHA-256 (64 caractères hex)
        hash_val = result["email"].iloc[0]
        assert len(hash_val) == 64
        assert hash_val == hashlib.sha256("alice@pme.fr".encode()).hexdigest()

    def test_strategie_drop(self, pipeline, df_avec_pii):
        """Stratégie drop → colonnes PII supprimées."""
        result = pipeline.encrypt_pii_columns(df_avec_pii, strategy="drop")
        assert "email" not in result.columns
        assert "phone" not in result.columns
        assert "email_enc" not in result.columns

    def test_sans_colonnes_pii(self, pipeline, df_sans_pii):
        """DataFrame sans PII → retourné tel quel."""
        result = pipeline.encrypt_pii_columns(df_sans_pii)
        assert list(result.columns) == list(df_sans_pii.columns)

    def test_colonnes_explicites(self, pipeline, df_avec_pii):
        """On peut spécifier explicitement les colonnes à chiffrer."""
        result = pipeline.encrypt_pii_columns(
            df_avec_pii,
            columns=["email"],
        )
        assert "email" not in result.columns
        assert "email_enc" in result.columns
        assert "phone" in result.columns  # pas chiffré car non spécifié

    def test_dataframe_original_non_modifie(self, pipeline, df_avec_pii):
        """Le DataFrame original n'est pas modifié (copie)."""
        colonnes_avant = list(df_avec_pii.columns)
        pipeline.encrypt_pii_columns(df_avec_pii)
        assert list(df_avec_pii.columns) == colonnes_avant

    def test_audit_log_mis_a_jour(self, pipeline, df_avec_pii):
        """Après chiffrement PII → log d'audit mis à jour."""
        pipeline.encrypt_pii_columns(df_avec_pii)
        assert len(pipeline._audit_log) == 1
        assert pipeline._audit_log[0]["action"] == "pii_protection"

    def test_valeurs_nulles_gerees(self, pipeline):
        """Les valeurs None/NaN ne causent pas d'erreur."""
        df = pd.DataFrame([
            {"email": "alice@pme.fr", "montant": 100},
            {"email": None,           "montant": 200},
        ])
        result = pipeline.encrypt_pii_columns(df)
        assert result["email_enc"].iloc[0] is not None
        assert result["email_enc"].iloc[1] is None


# ══════════════════════════════════════════════════════════════════════════════
# 5. CHIFFREMENT COLONNES SPECIFIQUES
# ══════════════════════════════════════════════════════════════════════════════

class TestEncryptColumns:

    def test_chiffrement_colonne_specifique(self, pipeline, df_sans_pii):
        """Chiffrer une colonne spécifique non-PII."""
        result = pipeline.encrypt_columns(df_sans_pii, columns=["montant"])
        assert "montant" not in result.columns
        assert "montant_enc" in result.columns

    def test_colonne_inexistante_ignoree(self, pipeline, df_sans_pii):
        """Colonne inexistante → ignorée sans erreur."""
        result = pipeline.encrypt_columns(df_sans_pii, columns=["colonne_inexistante"])
        assert list(result.columns) == list(df_sans_pii.columns)

    def test_plusieurs_colonnes(self, pipeline, df_sans_pii):
        """Chiffrer plusieurs colonnes en une fois."""
        result = pipeline.encrypt_columns(
            df_sans_pii,
            columns=["montant", "statut"],
        )
        assert "montant" not in result.columns
        assert "statut" not in result.columns
        assert "montant_enc" in result.columns
        assert "statut_enc" in result.columns


# ══════════════════════════════════════════════════════════════════════════════
# 6. HELPERS CRYPTO
# ══════════════════════════════════════════════════════════════════════════════

class TestHelpersCrypto:

    def test_is_missing_none(self, pipeline):
        """None → manquant."""
        assert pipeline._is_missing(None) is True

    def test_is_missing_nan(self, pipeline):
        """NaN → manquant."""
        import math
        assert pipeline._is_missing(float("nan")) is True

    def test_is_missing_valeur_presente(self, pipeline):
        """Valeur présente → pas manquant."""
        assert pipeline._is_missing("alice@pme.fr") is False
        assert pipeline._is_missing(0) is False
        assert pipeline._is_missing("") is False

    def test_is_missing_liste(self, pipeline):
        """Liste → pas manquant (pd.isna lève une erreur sur les listes)."""
        assert pipeline._is_missing([1, 2, 3]) is False

    def test_encrypt_value_none(self, pipeline):
        """_encrypt_value(None) → None."""
        assert pipeline._encrypt_value(None) is None

    def test_encrypt_value_string(self, pipeline):
        """_encrypt_value("test") → bytes."""
        result = pipeline._encrypt_value("test")
        assert isinstance(result, bytes)

    def test_hash_value_none(self, pipeline):
        """_hash_value(None) → None."""
        assert pipeline._hash_value(None) is None

    def test_hash_value_string(self, pipeline):
        """_hash_value("test") → SHA-256 hex."""
        result = pipeline._hash_value("test")
        assert result == hashlib.sha256("test".encode()).hexdigest()
        assert len(result) == 64

    def test_hash_value_deterministe(self, pipeline):
        """Même entrée → même hash."""
        assert pipeline._hash_value("alice") == pipeline._hash_value("alice")

    def test_hash_value_different(self, pipeline):
        """Entrées différentes → hashes différents."""
        assert pipeline._hash_value("alice") != pipeline._hash_value("bob")


# ══════════════════════════════════════════════════════════════════════════════
# 7. LECTURE / ÉCRITURE FICHIERS
# ══════════════════════════════════════════════════════════════════════════════

class TestLectureEcriture:

    def test_write_read_parquet_roundtrip(self, pipeline, df_sans_pii, tmp_path):
        """Écrire en Parquet puis lire → données identiques."""
        path = str(tmp_path / "test.parquet")
        pipeline.write_parquet(df_sans_pii, path)
        result = pipeline.read(path, fmt="parquet")
        assert len(result) == len(df_sans_pii)
        assert list(result.columns) == list(df_sans_pii.columns)

    def test_write_read_csv_roundtrip(self, pipeline, df_sans_pii, tmp_path):
        """Écrire en CSV puis lire → données identiques."""
        path = str(tmp_path / "test.csv")
        df_sans_pii.to_csv(path, index=False)
        result = pipeline.read(path, fmt="csv")
        assert len(result) == len(df_sans_pii)

    def test_read_format_auto_csv(self, pipeline, df_sans_pii, tmp_path):
        """Détection automatique du format CSV."""
        path = str(tmp_path / "test.csv")
        df_sans_pii.to_csv(path, index=False)
        result = pipeline.read(path)  # fmt="auto"
        assert len(result) == len(df_sans_pii)

    def test_read_format_auto_parquet(self, pipeline, df_sans_pii, tmp_path):
        """Détection automatique du format Parquet."""
        path = str(tmp_path / "test.parquet")
        pipeline.write_parquet(df_sans_pii, path)
        result = pipeline.read(path)  # fmt="auto"
        assert len(result) == len(df_sans_pii)

    def test_write_parquet_cree_dossier(self, pipeline, df_sans_pii, tmp_path):
        """write_parquet crée le dossier parent si nécessaire."""
        path = str(tmp_path / "sous_dossier" / "data.parquet")
        pipeline.write_parquet(df_sans_pii, path)
        assert Path(path).exists()

    def test_write_avro_encrypted_roundtrip(self, pipeline, tmp_path):
        """Chiffrer en Avro puis déchiffrer → données identiques."""
        output_dir = str(tmp_path / "avro_output")
        records = [
            {
                "event_id": "e1", "actor_id": "u1", "action": "LOGIN",
                "resource_type": "API", "resource_id": "r1",
                "ip_address": "192.168.1.1", "success": True, "details": None,
            }
        ]
        df = pd.DataFrame(records)
        pipeline.write_avro_encrypted(df, output_dir, schema_name="audit_events")
        result = pipeline.read_avro_encrypted(output_dir, schema_name="audit_events")
        assert len(result) == 1
        assert result["event_id"].iloc[0] == "e1"
        assert result["actor_id"].iloc[0] == "u1"

    def test_read_avro_encrypted_dossier_vide(self, pipeline, tmp_path):
        """Dossier sans fichiers .avroenc → FileNotFoundError."""
        empty_dir = str(tmp_path / "empty")
        Path(empty_dir).mkdir()
        with pytest.raises(FileNotFoundError):
            pipeline.read_avro_encrypted(empty_dir, schema_name="audit_events")


# ══════════════════════════════════════════════════════════════════════════════
# 8. RAPPORT D'AUDIT
# ══════════════════════════════════════════════════════════════════════════════

class TestRapportAudit:

    def test_rapport_structure(self, pipeline):
        """Le rapport d'audit contient les bonnes clés."""
        report = pipeline._generate_report(1.5)
        assert "pipeline" in report
        assert "version" in report
        assert "timestamp" in report
        assert "duration_s" in report
        assert "events" in report
        assert "summary" in report

    def test_rapport_duration(self, pipeline):
        """La durée est correctement enregistrée."""
        report = pipeline._generate_report(2.5)
        assert report["duration_s"] == 2.5

    def test_audit_log_apres_operations(self, pipeline, df_avec_pii):
        """Après plusieurs opérations → log d'audit complet."""
        pipeline.encrypt_pii_columns(df_avec_pii, strategy="encrypt")
        pipeline.encrypt_pii_columns(df_avec_pii, strategy="hash")
        assert len(pipeline._audit_log) == 2
        actions = [e["action"] for e in pipeline._audit_log]
        assert actions.count("pii_protection") == 2

    def test_save_report(self, pipeline, tmp_path):
        """Sauvegarder le rapport → fichier JSON créé."""
        path = str(tmp_path / "rapport" / "audit.json")
        pipeline.save_report(path)
        assert Path(path).exists()
        import json
        with open(path) as f:
            data = json.load(f)
        assert "pipeline" in data


# ══════════════════════════════════════════════════════════════════════════════
# 9. GENERATE MASTER KEY
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateMasterKey:

    def test_generate_key_valide(self):
        """La clé générée est utilisable par SpidercryptCrypto."""
        key = generate_master_key()
        crypto = SpidercryptCrypto(key)
        assert crypto is not None

    def test_generate_key_unique(self):
        """Deux clés générées sont différentes."""
        key1 = generate_master_key()
        key2 = generate_master_key()
        assert key1 != key2