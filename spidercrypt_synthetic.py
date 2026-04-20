"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT ENTERPRISE — Générateur de Données Synthétiques       ║
║   RGPD-ready · Réaliste · Cohérent · Multi-schémas · Pandas-compatible     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Génère des données synthétiques réalistes pour :
  - Tests et développement sans exposer de vraies données
  - Conformité RGPD Art.25 (privacy by design)
  - Benchmarks et démonstrations clients
  - Entraînement de modèles ML sans données sensibles

Dépendances :
    pip install faker pandas pyarrow fastavro

Usage :
    from spidercrypt_synthetic import SyntheticDataFactory
    factory = SyntheticDataFactory(locale="fr_FR", seed=42)
    df = factory.generate("transactions", n=10_000)
    factory.save(df, "data/synthetic_transactions.parquet")
"""

from __future__ import annotations

import hashlib
import json
import random
import string
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from faker import Faker

# ── Constantes métier France / PME ────────────────────────────────────────────

SECTEURS_PME = [
    "Boulangerie", "Restauration", "Commerce de détail", "BTP",
    "Informatique", "Conseil", "Transport", "Santé", "Immobilier",
    "Formation", "E-commerce", "Artisanat", "Agriculture", "Hôtellerie",
]

BANQUES_FR = [
    "BNP Paribas", "Crédit Agricole", "Société Générale", "LCL",
    "Caisse d'Épargne", "Banque Populaire", "CIC", "Crédit Mutuel",
    "La Banque Postale", "Boursorama", "Qonto", "Shine", "Revolut Business",
]

VILLES_FR = [
    ("Paris", "75"), ("Lyon", "69"), ("Marseille", "13"), ("Toulouse", "31"),
    ("Nice", "06"), ("Nantes", "44"), ("Strasbourg", "67"), ("Montpellier", "34"),
    ("Bordeaux", "33"), ("Lille", "59"), ("Rennes", "35"), ("Reims", "51"),
    ("Le Havre", "76"), ("Saint-Étienne", "42"), ("Toulon", "83"),
    ("Grenoble", "38"), ("Dijon", "21"), ("Angers", "49"), ("Nîmes", "30"),
    ("Villeurbanne", "69"), ("Laval", "53"), ("Clermont-Ferrand", "63"),
]

MOYENS_PAIEMENT = [
    "carte_visa", "carte_mastercard", "virement_sepa", "prélèvement",
    "chèque", "espèces", "paypal", "stripe", "lydia_pro",
]

STATUTS_TX = ["COMPLETED", "PENDING", "FAILED", "REFUNDED"]
STATUTS_TX_WEIGHTS = [0.78, 0.12, 0.06, 0.04]

SEVERITES = ["INFO", "WARNING", "ERROR", "CRITICAL"]
SEVERITES_WEIGHTS = [0.60, 0.25, 0.12, 0.03]

ACTIONS_AUDIT = [
    "LOGIN", "LOGOUT", "READ", "WRITE", "DELETE",
    "EXPORT", "IMPORT", "API_CALL", "KEY_ROTATE", "CONFIG_CHANGE",
]

ANOMALIE_PATTERNS = [
    "montant_suspect",
    "heure_inhabituelle",
    "pays_inhabituel",
    "frequence_elevee",
    "compte_nouveau",
]


# ══════════════════════════════════════════════════════════════════════════════
# GÉNÉRATEURS DE BASE
# ══════════════════════════════════════════════════════════════════════════════

class BaseGenerator:
    """Générateur de base avec Faker et seed reproductible."""

    def __init__(self, locale: str = "fr_FR", seed: int | None = None):
        self.fake = Faker(locale)
        self.seed = seed
        if seed is not None:
            Faker.seed(seed)
            random.seed(seed)

    def _weighted_choice(self, choices: list, weights: list):
        return random.choices(choices, weights=weights, k=1)[0]

    def _random_date(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> datetime:
        if start is None:
            start = datetime.now(timezone.utc) - timedelta(days=365)
        if end is None:
            end = datetime.now(timezone.utc)
        delta = end - start
        return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

    def _iban_fr(self) -> str:
        bban = "".join(random.choices(string.digits, k=23))
        return f"FR76{bban}"

    def _siret(self) -> str:
        return "".join(random.choices(string.digits, k=14))

    def _naf_code(self) -> str:
        codes = ["4711F", "5610A", "6201Z", "4120A", "8621Z",
                 "6820B", "4941A", "7022Z", "8559A", "5630Z"]
        return random.choice(codes)


# ══════════════════════════════════════════════════════════════════════════════
# GÉNÉRATEURS MÉTIER
# ══════════════════════════════════════════════════════════════════════════════

class TransactionGenerator(BaseGenerator):
    """Génère des transactions financières réalistes pour PME françaises."""

    def generate_one(self, inject_anomaly: bool = False) -> dict:
        ville, dept = random.choice(VILLES_FR)
        ts = self._random_date()

        montant_base = max(1, int(random.lognormvariate(6.5, 1.2)))
        montant_cents = montant_base * 100
        statut = self._weighted_choice(STATUTS_TX, STATUTS_TX_WEIGHTS)

        record = {
            "transaction_id":  str(uuid.uuid4()),
            "timestamp_ms":    int(ts.timestamp() * 1000),
            "timestamp_iso":   ts.isoformat(),
            "montant_cents":   montant_cents,
            "montant_eur":     round(montant_cents / 100, 2),
            "devise":          "EUR",
            "moyen_paiement":  random.choice(MOYENS_PAIEMENT),
            "statut":          statut,
            "marchand_id":     f"M{random.randint(1000, 9999)}",
            "marchand_nom":    self.fake.company(),
            "secteur":         random.choice(SECTEURS_PME),
            "client_hash":     hashlib.sha256(self.fake.email().encode()).hexdigest(),
            "ville":           ville,
            "departement":     dept,
            "banque":          random.choice(BANQUES_FR),
            "ip_hash":         hashlib.sha256(self.fake.ipv4_private().encode()).hexdigest(),
            "est_anomalie":    False,
            "type_anomalie":   None,
            "risque_score":    round(random.betavariate(1, 9), 3),
        }

        if inject_anomaly:
            pattern = random.choice(ANOMALIE_PATTERNS)
            record["est_anomalie"]  = True
            record["type_anomalie"] = pattern
            record["risque_score"]  = round(random.uniform(0.7, 0.99), 3)

            if pattern == "montant_suspect":
                record["montant_cents"] = random.randint(500_000, 2_000_000)
                record["montant_eur"]   = record["montant_cents"] / 100
            elif pattern == "heure_inhabituelle":
                ts_nuit = ts.replace(hour=random.randint(2, 4))
                record["timestamp_ms"]  = int(ts_nuit.timestamp() * 1000)
                record["timestamp_iso"] = ts_nuit.isoformat()
            elif pattern == "frequence_elevee":
                record["risque_score"] = 0.95
            elif pattern == "compte_nouveau":
                record["montant_cents"] = random.randint(500_000, 800_000)
                record["montant_eur"]   = record["montant_cents"] / 100

        return record

    def generate_batch(self, n: int, anomaly_rate: float = 0.03, **kwargs) -> list[dict]:
        n_anomalies = max(1, int(n * anomaly_rate))
        anomaly_indices = set(random.sample(range(n), min(n_anomalies, n)))
        return [self.generate_one(inject_anomaly=(i in anomaly_indices)) for i in range(n)]


class ContactPMEGenerator(BaseGenerator):
    """Génère des contacts PME avec données personnelles synthétiques."""

    def generate_one(self, company_id: str | None = None) -> dict:
        genre  = random.choice(["M", "F"])
        prenom = self.fake.first_name_male() if genre == "M" else self.fake.first_name_female()
        nom    = self.fake.last_name()
        email  = f"{prenom.lower()}.{nom.lower()}@{self.fake.domain_name()}"
        ts     = self._random_date()

        roles = ["PDG", "DG", "DAF", "DSI", "Responsable Achats",
                 "Comptable", "Commercial", "RH", "Juriste", "Assistant(e)"]

        return {
            "contact_id":        str(uuid.uuid4()),
            "company_id":        company_id or str(uuid.uuid4()),
            "civilite":          "M." if genre == "M" else "Mme",
            "prenom":            prenom,
            "nom":               nom,
            "email":             email,
            "telephone":         self.fake.phone_number(),
            "mobile":            f"06{random.randint(10000000, 99999999)}",
            "poste":             random.choice(roles),
            "adresse":           self.fake.street_address(),
            "code_postal":       self.fake.postcode(),
            "ville":             random.choice(VILLES_FR)[0],
            "pays":              "FR",
            "langue":            random.choice(["fr", "fr", "fr", "en"]),
            "consentement_rgpd": random.choices([True, False], weights=[0.85, 0.15])[0],
            "date_consentement": ts.isoformat(),
            "retention_jours":   random.choice([365, 730, 1095]),
            "cree_le":           ts.isoformat(),
            "actif":             random.choices([True, False], weights=[0.9, 0.1])[0],
            "_synthetic":        True,
        }

    def generate_batch(self, n: int, **kwargs) -> list[dict]:
        n_companies = max(1, n // random.randint(3, 8))
        company_ids = [str(uuid.uuid4()) for _ in range(n_companies)]
        return [self.generate_one(company_id=random.choice(company_ids)) for _ in range(n)]


class AuditEventGenerator(BaseGenerator):
    """Génère des événements d'audit système réalistes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_pool = [str(uuid.uuid4()) for _ in range(50)]
        self._resource_pool = {
            "API_KEY":      [f"key_{i:04d}" for i in range(20)],
            "DOCUMENT":     [f"doc_{uuid.uuid4().hex[:8]}" for _ in range(100)],
            "USER_ACCOUNT": [f"usr_{i:04d}" for i in range(200)],
            "CONFIG":       ["security", "smtp", "integrations", "billing"],
            "EXPORT":       [f"export_{i:04d}" for i in range(30)],
        }

    def generate_one(self, force_failure: bool = False) -> dict:
        ts            = self._random_date()
        action        = random.choice(ACTIONS_AUDIT)
        resource_type = random.choice(list(self._resource_pool.keys()))
        resource_id   = random.choice(self._resource_pool[resource_type])
        success       = False if force_failure else random.choices([True, False], weights=[0.94, 0.06])[0]
        severite      = "ERROR" if not success else self._weighted_choice(SEVERITES, SEVERITES_WEIGHTS)

        return {
            "event_id":      str(uuid.uuid4()),
            "timestamp_ms":  int(ts.timestamp() * 1000),
            "timestamp_iso": ts.isoformat(),
            "acteur_id":     random.choice(self._user_pool),
            "acteur_type":   random.choice(["USER", "USER", "API_KEY", "SYSTEM"]),
            "action":        action,
            "resource_type": resource_type,
            "resource_id":   resource_id,
            "succes":        success,
            "severite":      severite,
            "ip_address":    self.fake.ipv4_public(),
            "user_agent":    self.fake.user_agent(),
            "duree_ms":      random.randint(5, 2000),
            "message":       _audit_message(action, resource_type, resource_id, success),
            "session_id":    hashlib.md5(f"{random.random()}".encode()).hexdigest()[:16],
            "_synthetic":    True,
        }

    def generate_batch(self, n: int, failure_rate: float = 0.06, **kwargs) -> list[dict]:
        n_failures = max(1, int(n * failure_rate))
        failure_indices = set(random.sample(range(n), min(n_failures, n)))
        records = [self.generate_one(force_failure=(i in failure_indices)) for i in range(n)]
        records.sort(key=lambda r: r["timestamp_ms"])
        return records


class EntreprisePMEGenerator(BaseGenerator):
    """Génère des profils d'entreprises PME françaises complets."""

    def generate_one(self) -> dict:
        ville, dept = random.choice(VILLES_FR)
        n_employes  = random.choices(
            ["1-9", "10-49", "50-249"],
            weights=[0.60, 0.30, 0.10]
        )[0]
        ca_tranches = {
            "1-9":    (50_000, 500_000),
            "10-49":  (500_000, 10_000_000),
            "50-249": (10_000_000, 50_000_000),
        }
        ca_min, ca_max = ca_tranches[n_employes]
        ca = random.randint(ca_min, ca_max)
        creation = self._random_date(
            start=datetime(2000, 1, 1, tzinfo=timezone.utc),
            end=datetime(2023, 12, 31, tzinfo=timezone.utc),
        )

        return {
            "entreprise_id":             str(uuid.uuid4()),
            "siret":                     self._siret(),
            "siren":                     self._siret()[:9],
            "raison_sociale":            self.fake.company(),
            "forme_juridique":           random.choice(["SARL", "SAS", "SASU", "EURL", "SA", "EI"]),
            "secteur_naf":               random.choice(SECTEURS_PME),
            "code_naf":                  self._naf_code(),
            "adresse":                   self.fake.street_address(),
            "code_postal":               self.fake.postcode(),
            "ville":                     ville,
            "departement":               dept,
            "pays":                      "FR",
            "telephone":                 self.fake.phone_number(),
            "email_contact":             self.fake.company_email(),
            "site_web":                  f"https://www.{self.fake.domain_name()}",
            "n_employes":                n_employes,
            "ca_annuel_eur":             ca,
            "banque_principale":         random.choice(BANQUES_FR),
            "iban_principal":            self._iban_fr(),
            "date_creation":             creation.isoformat(),
            "client_spidercrypt_depuis": self._random_date(
                start=datetime(2023, 1, 1, tzinfo=timezone.utc)
            ).isoformat(),
            "plan":                      random.choices(
                                             ["starter", "pro", "enterprise"],
                                             weights=[0.5, 0.35, 0.15]
                                         )[0],
            "score_risque":              round(random.betavariate(2, 5), 3),
            "_synthetic":                True,
        }

    def generate_batch(self, n: int, **kwargs) -> list[dict]:
        return [self.generate_one() for _ in range(n)]


# ══════════════════════════════════════════════════════════════════════════════
# FACTORY PRINCIPALE
# ══════════════════════════════════════════════════════════════════════════════

REGISTRY: dict[str, type] = {
    "transactions": TransactionGenerator,
    "contacts":     ContactPMEGenerator,
    "audit_events": AuditEventGenerator,
    "entreprises":  EntreprisePMEGenerator,
}


class SyntheticDataFactory:
    """
    Point d'entrée principal pour la génération de données synthétiques.

    Usage :
        factory = SyntheticDataFactory(locale="fr_FR", seed=42)

        # Générer un DataFrame Pandas
        df = factory.generate("transactions", n=10_000)

        # Sauvegarder
        factory.save(df, "data/transactions.parquet")
        factory.save(df, "data/transactions.csv")

        # Générer plusieurs datasets liés
        datasets = factory.generate_suite(n_entreprises=100, n_contacts_per=5)
    """

    def __init__(self, locale: str = "fr_FR", seed: int | None = 42):
        self.locale = locale
        self.seed   = seed
        self._generators: dict[str, BaseGenerator] = {}

    def _get_generator(self, schema_name: str) -> BaseGenerator:
        if schema_name not in self._generators:
            cls = REGISTRY.get(schema_name)
            if cls is None:
                raise ValueError(
                    f"Schéma inconnu : '{schema_name}'. "
                    f"Disponibles : {list(REGISTRY)}"
                )
            self._generators[schema_name] = cls(locale=self.locale, seed=self.seed)
        return self._generators[schema_name]

    def generate(self, schema_name: str, n: int = 1000, **kwargs) -> pd.DataFrame:
        """Génère n enregistrements et retourne un DataFrame Pandas."""
        t0      = time.time()
        gen     = self._get_generator(schema_name)
        records = gen.generate_batch(n, **kwargs)
        df      = pd.DataFrame(records)
        duration = round(time.time() - t0, 3)
        print(
            f"✅ {schema_name} : {n:,} enregistrements générés "
            f"en {duration}s — {df.shape[1]} colonnes"
        )
        return df

    def save(self, df: pd.DataFrame, path: str, fmt: str = "auto") -> Path:
        """
        Sauvegarde le DataFrame dans le format spécifié.
        fmt : auto | parquet | csv | json
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "auto":
            fmt = p.suffix.lstrip(".").lower()
            if fmt not in ("parquet", "csv", "json"):
                fmt = "parquet"

        if fmt == "parquet":
            df.to_parquet(p, compression="snappy", index=False)
        elif fmt == "csv":
            df.to_csv(p, index=False)
        elif fmt == "json":
            df.to_json(p, orient="records", force_ascii=False, indent=2)
        else:
            raise ValueError(f"Format non supporté : {fmt}")

        size_kb = round(p.stat().st_size / 1024, 1)
        print(f"  💾 Sauvegardé → {p}  ({size_kb} Ko, {fmt})")
        return p

    def generate_suite(
        self,
        n_entreprises: int = 50,
        n_contacts_per: int = 5,
        n_transactions: int = 10_000,
        n_audit_events: int = 5_000,
        output_dir: str = "synthetic_data",
    ) -> dict[str, pd.DataFrame]:
        """
        Génère un jeu de données complet et cohérent pour une démo PME.
        Les contacts et transactions sont liés aux entreprises générées.
        """
        print(f"\n🕷️  SpiderCrypt — Génération suite synthétique complète")
        print(f"   {n_entreprises} entreprises · {n_contacts_per} contacts/entreprise")
        print(f"   {n_transactions} transactions · {n_audit_events} événements d'audit\n")

        out = Path(output_dir)

        # 1. Entreprises
        df_ent = self.generate("entreprises", n=n_entreprises)
        self.save(df_ent, out / "entreprises.parquet")

        # 2. Contacts liés aux entreprises
        contact_gen = ContactPMEGenerator(locale=self.locale, seed=self.seed)
        company_ids = df_ent["entreprise_id"].tolist()
        contacts = []
        for cid in company_ids:
            for _ in range(n_contacts_per):
                contacts.append(contact_gen.generate_one(company_id=cid))
        df_contacts = pd.DataFrame(contacts)
        self.save(df_contacts, out / "contacts.parquet")

        # 3. Transactions
        df_tx = self.generate("transactions", n=n_transactions, anomaly_rate=0.03)
        self.save(df_tx, out / "transactions.parquet")

        # 4. Audit events
        df_audit = self.generate("audit_events", n=n_audit_events, failure_rate=0.06)
        self.save(df_audit, out / "audit_events.parquet")

        # 5. Rapport de génération
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "locale":       self.locale,
            "seed":         self.seed,
            "datasets": {
                "entreprises":  {"rows": len(df_ent),      "cols": df_ent.shape[1]},
                "contacts":     {"rows": len(df_contacts),  "cols": df_contacts.shape[1]},
                "transactions": {"rows": len(df_tx),        "cols": df_tx.shape[1]},
                "audit_events": {"rows": len(df_audit),     "cols": df_audit.shape[1]},
            },
            "disclaimer": (
                "DONNÉES 100% SYNTHÉTIQUES — générées par Spidercrypt Enterprise. "
                "Aucune donnée personnelle réelle. Conforme RGPD Art.25."
            ),
        }
        report_path = out / "generation_report.json"
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"\n  📋 Rapport → {report_path}")

        total_rows = sum(d["rows"] for d in report["datasets"].values())
        print(f"\n✅ Suite générée : {total_rows:,} enregistrements au total")
        print(f"   Dossier : {out.resolve()}\n")

        return {
            "entreprises":  df_ent,
            "contacts":     df_contacts,
            "transactions": df_tx,
            "audit_events": df_audit,
        }

    def describe(self, df: pd.DataFrame, schema_name: str = "") -> str:
        """Résumé statistique rapide du DataFrame généré."""
        lines = [
            f"{'─'*60}",
            f"  Dataset synthétique : {schema_name or 'inconnu'}",
            f"  {df.shape[0]:,} lignes × {df.shape[1]} colonnes",
            f"{'─'*60}",
        ]
        for col in df.columns[:20]:
            dtype  = df[col].dtype
            nulls  = df[col].isna().sum()
            uniq   = df[col].nunique()
            sample = str(df[col].iloc[0])[:40]
            lines.append(
                f"  {col:<30} [{dtype}]  "
                f"uniq={uniq:<6} nulls={nulls:<4} ex: {sample}"
            )
        if df.shape[1] > 20:
            lines.append(f"  … ({df.shape[1] - 20} colonnes supplémentaires)")
        lines.append(f"{'─'*60}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

def _audit_message(action: str, resource_type: str, resource_id: str, success: bool) -> str:
    verb = {
        "LOGIN":         ("Connexion réussie", "Échec de connexion"),
        "LOGOUT":        ("Déconnexion", "Erreur déconnexion"),
        "READ":          ("Lecture", "Accès refusé"),
        "WRITE":         ("Écriture réussie", "Erreur écriture"),
        "DELETE":        ("Suppression", "Suppression refusée"),
        "EXPORT":        ("Export effectué", "Export échoué"),
        "IMPORT":        ("Import réussi", "Erreur import"),
        "API_CALL":      ("Appel API", "Erreur API"),
        "KEY_ROTATE":    ("Rotation clé effectuée", "Erreur rotation clé"),
        "CONFIG_CHANGE": ("Configuration modifiée", "Modification refusée"),
    }.get(action, ("Action", "Erreur"))

    msg = verb[0] if success else verb[1]
    return f"{msg} — {resource_type}:{resource_id}"


# ══════════════════════════════════════════════════════════════════════════════
# CLI / DÉMO
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    print("🕷️  Spidercrypt — Générateur de Données Synthétiques\n")

    factory = SyntheticDataFactory(locale="fr_FR", seed=42)

    # Générer la suite complète
    datasets = factory.generate_suite(
        n_entreprises=20,
        n_contacts_per=4,
        n_transactions=500,
        n_audit_events=200,
        output_dir="spidercrypt_synthetic",
    )

    # Afficher un résumé de chaque dataset
    for name, df in datasets.items():
        print(factory.describe(df, schema_name=name))
        print()