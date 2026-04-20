"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         🕷️  SPIDERCRYPT ENTERPRISE — Pandas + Avro Pipeline                 ║
║   Traitement massif · Chiffrement · Schémas Avro · RGPD-ready              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Dépendances :
    pip install pandas fastavro cryptography pyarrow

Usage :
    from spidercrypt_pandas import SpidercryptPipeline
    pipeline = SpidercryptPipeline(master_key_b64="<votre_clé_base64>")
    pipeline.run("data/raw.csv", "data/secure/", schema_name="transactions")
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import fastavro
import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger("spidercrypt.pandas")

# ── Schémas Avro prédéfinis ───────────────────────────────────────────────────

AVRO_SCHEMAS: dict[str, dict] = {

    "transactions": {
        "type": "record",
        "name": "Transaction",
        "namespace": "spidercrypt.enterprise",
        "doc": "Enregistrement de transaction financière chiffré",
        "fields": [
            {"name": "transaction_id",  "type": "string"},
            {"name": "amount_cents",    "type": "long"},
            {"name": "currency",        "type": "string", "default": "EUR"},
            {"name": "merchant_id",     "type": "string"},
            {"name": "customer_hash",   "type": "string", "doc": "SHA-256 du customer_id"},
            {"name": "status",          "type": {"type": "enum", "name": "TxStatus",
                                                  "symbols": ["PENDING","COMPLETED","FAILED","REFUNDED"]}},
            {"name": "_encrypted",      "type": "boolean", "default": True},
            {"name": "_schema_version", "type": "string",  "default": "1.0.0"},
        ],
    },

    "audit_events": {
        "type": "record",
        "name": "AuditEvent",
        "namespace": "spidercrypt.enterprise",
        "doc": "Événement d'audit RGPD — immuable",
        "fields": [
            {"name": "event_id",         "type": "string"},
            {"name": "actor_id",         "type": "string"},
            {"name": "action",           "type": "string"},
            {"name": "resource_type",    "type": "string"},
            {"name": "resource_id",      "type": "string"},
            {"name": "ip_address",       "type": ["null", "string"], "default": None},
            {"name": "success",          "type": "boolean"},
            {"name": "details",          "type": ["null", "string"], "default": None},
        ],
    },

    "pme_contacts": {
        "type": "record",
        "name": "PmeContact",
        "namespace": "spidercrypt.enterprise",
        "doc": "Contacts PME — données personnelles chiffrées (RGPD Art.25)",
        "fields": [
            {"name": "contact_id",      "type": "string"},
            {"name": "company_id",      "type": "string"},
            {"name": "email_encrypted", "type": "bytes",  "doc": "Email chiffré ChaCha20-Poly1305"},
            {"name": "phone_encrypted", "type": ["null", "bytes"], "default": None},
            {"name": "name_encrypted",  "type": "bytes"},
            {"name": "role",            "type": "string"},
            {"name": "consent_gdpr",    "type": "boolean"},
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# CRYPTO LAYER — ChaCha20-Poly1305
# ══════════════════════════════════════════════════════════════════════════════

class SpidercryptCrypto:
    """
    Chiffrement AEAD ChaCha20-Poly1305.
    Format ciphertext : [nonce (12 bytes)] + [ciphertext+tag]
    """
    NONCE_SIZE = 12

    def __init__(self, master_key_b64: str):
        raw = base64.b64decode(master_key_b64)
        if len(raw) != 32:
            raise ValueError("La master key doit faire 32 bytes (256 bits)")
        self._cipher = ChaCha20Poly1305(raw)

    def encrypt(self, plaintext: str | bytes, aad: bytes | None = None) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        nonce = os.urandom(self.NONCE_SIZE)
        ct    = self._cipher.encrypt(nonce, plaintext, aad)
        return nonce + ct

    def decrypt(self, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        nonce = ciphertext[: self.NONCE_SIZE]
        ct    = ciphertext[self.NONCE_SIZE :]
        return self._cipher.decrypt(nonce, ct, aad)

    @staticmethod
    def generate_key_b64() -> str:
        return base64.b64encode(os.urandom(32)).decode()


# ══════════════════════════════════════════════════════════════════════════════
# AVRO CODEC
# ══════════════════════════════════════════════════════════════════════════════

class AvroCodec:
    """Sérialise / désérialise des records Avro en bytes."""

    def __init__(self, schema_name: str):
        if schema_name not in AVRO_SCHEMAS:
            raise ValueError(
                f"Schéma inconnu : '{schema_name}'. "
                f"Disponibles : {list(AVRO_SCHEMAS)}"
            )
        self.schema_name = schema_name
        self._parsed = fastavro.parse_schema(AVRO_SCHEMAS[schema_name])

    def serialize_batch(self, records: list[dict]) -> bytes:
        buf = io.BytesIO()
        fastavro.writer(buf, self._parsed, records)
        return buf.getvalue()

    def deserialize_batch(self, data: bytes) -> Iterator[dict]:
        buf = io.BytesIO(data)
        yield from fastavro.reader(buf)


# ══════════════════════════════════════════════════════════════════════════════
# SPIDERCRYPT PANDAS PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

class SpidercryptPipeline:
    """
    Pipeline Spidercrypt Enterprise — propulsé par Pandas (compatible tous CPUs).

    Fonctionnalités :
    - Chargement CSV, JSON, Parquet, Avro
    - Chiffrement colonne-par-colonne avec ChaCha20-Poly1305
    - Pseudonymisation automatique des PII (RGPD)
    - Écriture sécurisée (Parquet ou Avro chiffré)
    - Rapport d'audit
    """

    PII_COLUMNS = {
        "email", "mail", "phone", "telephone", "mobile",
        "name", "nom", "prenom", "firstname", "lastname",
        "address", "adresse", "ssn", "nir", "iban",
        "credit_card", "carte_bancaire", "ip_address", "ip",
    }

    def __init__(self, master_key_b64: str | None = None):
        if master_key_b64 is None:
            master_key_b64 = os.environ.get("SPIDERCRYPT_MASTER_KEY")
        if not master_key_b64:
            raise ValueError(
                "master_key_b64 requis ou variable SPIDERCRYPT_MASTER_KEY"
            )
        self.crypto = SpidercryptCrypto(master_key_b64)
        self._audit_log: list[dict] = []
        logger.info("✅ SpidercryptPipeline initialisé (Pandas)")

    # ── Helpers crypto ────────────────────────────────────────────────────────

    def _is_missing(self, value: Any) -> bool:
        """
        CORRECTION #3 — détection robuste de valeur manquante.
        pd.isna() lève une ValueError sur des objets non-scalaires (listes, dicts).
        On attrape l'exception pour traiter ces cas comme des valeurs présentes.
        """
        if value is None:
            return True
        try:
            return bool(pd.isna(value))
        except (TypeError, ValueError):
            return False

    def _encrypt_value(self, value: Any, aad: bytes = b"spidercrypt") -> bytes | None:
        if self._is_missing(value):
            return None
        return self.crypto.encrypt(str(value), aad)

    def _hash_value(self, value: Any) -> str | None:
        if self._is_missing(value):
            return None
        return hashlib.sha256(str(value).encode()).hexdigest()

    # ── Chiffrement DataFrame ─────────────────────────────────────────────────

    def encrypt_pii_columns(
        self,
        df: pd.DataFrame,
        columns: list[str] | None = None,
        strategy: str = "encrypt",  # "encrypt" | "hash" | "drop"
    ) -> pd.DataFrame:
        """
        Applique une stratégie de protection sur les colonnes PII.

        strategy:
          - "encrypt" : chiffre la valeur en bytes (réversible avec la clé)
          - "hash"    : SHA-256 (pseudonymisation irréversible)
          - "drop"    : supprime la colonne
        """
        df = df.copy()
        detected = columns or [
            c for c in df.columns
            if any(pii in c.lower() for pii in self.PII_COLUMNS)
        ]

        if not detected:
            logger.info("  Aucune colonne PII détectée")
            return df

        logger.info(f"  🔒 Colonnes PII [{strategy}] : {detected}")

        for col in detected:
            if col not in df.columns:
                continue
            if strategy == "encrypt":
                df[f"{col}_enc"] = df[col].apply(self._encrypt_value)
                df = df.drop(columns=[col])
            elif strategy == "hash":
                df[col] = df[col].apply(self._hash_value)
            elif strategy == "drop":
                df = df.drop(columns=[col])

        self._audit("pii_protection", {
            "columns": detected,
            "strategy": strategy,
            "count": len(detected),
        })
        return df

    def encrypt_columns(self, df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
        """Chiffre des colonnes spécifiques (non-PII)."""
        df = df.copy()
        for col in columns:
            if col in df.columns:
                df[f"{col}_enc"] = df[col].apply(self._encrypt_value)
                df = df.drop(columns=[col])
        return df

    # ── Lecture ───────────────────────────────────────────────────────────────

    def read(self, path: str, fmt: str = "auto") -> pd.DataFrame:
        """
        Lit des données depuis un fichier local.

        CORRECTION #4 — le format "avro" est maintenant reconnu explicitement.
        Auparavant, l'extension .avro tombait silencieusement dans le fallback
        "parquet", provoquant une erreur de lecture trompeuse.
        """
        if fmt == "auto":
            ext = Path(path).suffix.lower().lstrip(".")
            fmt = ext if ext in ("csv", "json", "parquet", "avro") else "parquet"

        if fmt == "csv":
            df = pd.read_csv(path)
        elif fmt == "json":
            df = pd.read_json(path)
        elif fmt == "parquet":
            df = pd.read_parquet(path)
        elif fmt == "avro":
            with open(path, "rb") as f:
                df = pd.DataFrame(list(fastavro.reader(f)))
        else:
            raise ValueError(f"Format non supporté : {fmt}")

        logger.info(f"  📂 Lu {len(df):,} lignes depuis {path} [{fmt}]")
        self._audit("read", {"path": path, "format": fmt, "rows": len(df)})
        return df

    # ── Écriture ──────────────────────────────────────────────────────────────

    def write_parquet(self, df: pd.DataFrame, path: str, compression: str = "snappy") -> None:
        """Écrit en Parquet compressé."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        df.to_parquet(path, compression=compression, index=False)
        logger.info(f"  ✅ Écrit Parquet → {path}")
        self._audit("write_parquet", {"path": path})

    def write_avro_encrypted(
        self,
        df: pd.DataFrame,
        output_dir: str,        # CORRECTION #2 — renommé output_dir pour clarté
        schema_name: str,
        batch_size: int = 10_000,
    ) -> None:
        """
        Sérialise en Avro + chiffre le payload avec ChaCha20-Poly1305.

        CORRECTION #2 — output_dir est désormais explicitement traité comme un
        dossier. mkdir(parents=True, exist_ok=True) était déjà présent mais le
        paramètre s'appelait "path", ce qui induisait en erreur les appelants
        qui passaient un chemin de fichier (ex: "out/data.avroenc").
        Un avertissement est émis si le chemin ressemble à un fichier.
        """
        out_path = Path(output_dir)
        if out_path.suffix:
            logger.warning(
                f"  ⚠️  write_avro_encrypted attend un dossier, pas un fichier. "
                f"  Le dossier '{out_path}' sera créé tel quel."
            )
        out_path.mkdir(parents=True, exist_ok=True)

        codec   = AvroCodec(schema_name)
        records = df.to_dict(orient="records")
        total   = len(records)
        chunks  = max(1, (total + batch_size - 1) // batch_size)

        logger.info(f"  📦 Avro+Encrypt : {total:,} lignes en {chunks} batch(s)")

        for i in range(chunks):
            chunk_records = records[i * batch_size : (i + 1) * batch_size]
            avro_bytes    = codec.serialize_batch(chunk_records)
            enc_bytes     = self.crypto.encrypt(avro_bytes, b"spidercrypt-avro")
            chunk_file    = out_path / f"part-{i:05d}.avroenc"
            chunk_file.write_bytes(enc_bytes)
            logger.info(f"    chunk {i+1}/{chunks} → {chunk_file.name} ({len(enc_bytes):,} bytes)")

        self._audit("write_avro_encrypted", {
            "path": output_dir, "schema": schema_name, "rows": total, "chunks": chunks,
        })

    def read_avro_encrypted(self, path: str, schema_name: str) -> pd.DataFrame:
        """Déchiffre et désérialise des fichiers .avroenc → DataFrame Pandas."""
        codec   = AvroCodec(schema_name)
        in_path = Path(path)
        files   = sorted(in_path.glob("*.avroenc"))

        if not files:
            raise FileNotFoundError(f"Aucun fichier .avroenc dans {path}")

        all_records = []
        for f in files:
            enc_bytes  = f.read_bytes()
            avro_bytes = self.crypto.decrypt(enc_bytes, b"spidercrypt-avro")
            all_records.extend(codec.deserialize_batch(avro_bytes))

        logger.info(f"  🔓 Déchiffré {len(all_records):,} records depuis {path}")
        return pd.DataFrame(all_records)

    # ── Pipeline complet ──────────────────────────────────────────────────────

    def run(
        self,
        input_path: str,
        output_path: str,
        schema_name: str = "transactions",
        pii_strategy: str = "encrypt",
        extra_encrypt_cols: list[str] | None = None,
        input_fmt: str = "auto",
        output_fmt: str = "parquet",  # "parquet" | "avro_encrypted"
    ) -> dict:
        """
        CORRECTION #5 — un avertissement est émis si schema_name est fourni
        mais que output_fmt vaut "parquet" (schema_name ignoré dans ce cas).
        """
        t0 = time.time()
        logger.info(f"\n🕷️  Spidercrypt Pipeline démarré")
        logger.info(f"   {input_path} → {output_path} [{schema_name}]")

        if output_fmt == "parquet" and schema_name != "transactions":
            logger.warning(
                f"  ⚠️  schema_name='{schema_name}' est ignoré en mode output_fmt='parquet'. "
                f"  Utilisez output_fmt='avro_encrypted' pour appliquer un schéma Avro."
            )

        df = self.read(input_path, fmt=input_fmt)
        df = self.encrypt_pii_columns(df, strategy=pii_strategy)

        if extra_encrypt_cols:
            df = self.encrypt_columns(df, extra_encrypt_cols)

        if output_fmt == "avro_encrypted":
            self.write_avro_encrypted(df, output_path, schema_name)
        else:
            self.write_parquet(df, output_path)

        duration = round(time.time() - t0, 2)
        report   = self._generate_report(duration)
        logger.info(f"\n✅ Pipeline terminé en {duration}s")
        return report

    # ── Rapport d'audit ───────────────────────────────────────────────────────

    def _audit(self, action: str, details: dict) -> None:
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action":    action,
            "details":   details,
        })

    def _generate_report(self, duration_s: float) -> dict:
        return {
            "pipeline":   "SpidercryptEnterprise",
            "version":    "3.0.0-pandas",
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "duration_s": duration_s,
            "events":     self._audit_log.copy(),
            "summary": {
                "total_events": len(self._audit_log),
                "actions":      list({e["action"] for e in self._audit_log}),
            },
        }

    def save_report(self, path: str) -> None:
        report = self._generate_report(0)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False))
        logger.info(f"  📋 Rapport sauvegardé → {path}")


# ══════════════════════════════════════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

def generate_master_key() -> str:
    key = SpidercryptCrypto.generate_key_b64()
    print(f"🔑 Nouvelle Master Key générée :")
    print(f"   {key}")
    print(f"   → Stocker dans SPIDERCRYPT_MASTER_KEY (jamais en clair dans le code!)")
    return key


# ══════════════════════════════════════════════════════════════════════════════
# EXEMPLE D'UTILISATION
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # 1. Générer une clé
    key = generate_master_key()

    # 2. Créer le pipeline
    pipeline = SpidercryptPipeline(master_key_b64=key)

    # 3. Données synthétiques
    # CORRECTION #1 — customer_hash est calculé dès la création du DataFrame,
    # car le schéma Avro "transactions" l'exige en tant que SHA-256 du customer_id.
    # Laisser ce champ vide provoquait une incohérence documentaire et une
    # confusion lors de l'export Avro (champ requis de type string).
    sample_data = pd.DataFrame([
        {
            "transaction_id": "TX001",
            "amount_cents": 9999,
            "currency": "EUR",
            "email": "alice@pme.fr",
            "phone": "0612345678",
            "status": "COMPLETED",
            "merchant_id": "M42",
            "customer_hash": hashlib.sha256("customer_001".encode()).hexdigest(),
        },
        {
            "transaction_id": "TX002",
            "amount_cents": 4500,
            "currency": "EUR",
            "email": "bob@startup.io",
            "phone": "0698765432",
            "status": "PENDING",
            "merchant_id": "M17",
            "customer_hash": hashlib.sha256("customer_002".encode()).hexdigest(),
        },
    ])

    print("\n📊 Données brutes :")
    print(sample_data.to_string())

    # 4. Chiffrer les PII
    df_secure = pipeline.encrypt_pii_columns(sample_data, strategy="encrypt")
    print("\n🔒 Données après chiffrement PII :")
    print(df_secure.to_string())

    # 5. Sauvegarder en Parquet
    Path("spidercrypt_output").mkdir(exist_ok=True)
    pipeline.write_parquet(df_secure, "spidercrypt_output/secure_data.parquet")

    # 6. Rapport
    pipeline.save_report("spidercrypt_output/audit.json")
    print("\n✅ Demo terminée — voir spidercrypt_output/")