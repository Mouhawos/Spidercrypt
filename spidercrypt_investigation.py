"""
╔══════════════════════════════════════════════════════════════════════════════╗
║      🕷️  SPIDERCRYPT ENTERPRISE — Parcours d'Investigation                  ║
║   Timeline · Corrélation · Détection anomalies · Rapport RGPD automatique  ║
╚══════════════════════════════════════════════════════════════════════════════╝

Dépendances :
    pip install pandas pyarrow pynacl

Usage :
    from spidercrypt_investigation import InvestigationEngine
    engine = InvestigationEngine()
    engine.load_audit_events("data/audit_events.parquet")
    engine.load_transactions("data/transactions.parquet")
    report = engine.investigate(actor_id="usr_0042", days_back=30)
    engine.save_report(report, "rapports/investigation.json")
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd

# ── Optionnel : PyNaCl pour signature Ed25519 ─────────────────────────────────
try:
    import nacl.signing
    import nacl.encoding
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


# ══════════════════════════════════════════════════════════════════════════════
# MODÈLES DE DONNÉES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TimelineEvent:
    event_id:      str
    timestamp_iso: str
    timestamp_ms:  int
    source:        str
    category:      str
    action:        str
    actor_id:      str
    resource:      str
    succes:        bool
    severite:      str
    risque_score:  float
    details:       dict      = field(default_factory=dict)
    flags:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnomalySignal:
    signal_id:      str
    detected_at:    str
    type_anomalie:  str
    severite:       str
    score:          float
    events_count:   int
    actor_id:       str
    description:    str
    recommandation: str
    event_ids:      list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InvestigationReport:
    report_id:         str
    generated_at:      str
    investigator:      str
    subject:           dict
    summary:           dict
    timeline:          list[dict]
    anomalies:         list[dict]
    statistics:        dict
    risk_assessment:   dict
    recommendations:   list[str]
    graph_summary:     dict
    signature_ed25519: str | None
    signature_hash:    str | None

    def to_dict(self) -> dict:
        return asdict(self)

    def risk_level(self) -> str:
        """
        CORRECTION #6 — on lit directement le niveau calculé par _assess_risk
        plutôt que de dupliquer les seuils (0.8/0.6/0.35) ici.
        Auparavant, toute divergence entre les deux copies des seuils produisait
        un niveau affiché différent du niveau stocké dans risk_assessment["niveau"].
        """
        return self.risk_assessment.get("niveau", "FAIBLE")


# ══════════════════════════════════════════════════════════════════════════════
# RÈGLES DE DÉTECTION
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DetectionRule:
    name:           str
    description:    str
    severite:       str
    score:          float
    recommandation: str

DETECTION_RULES = [
    DetectionRule("brute_force_login",           "Plus de 5 échecs de connexion en moins de 10 minutes",                 "CRITICAL", 0.90, "Bloquer le compte immédiatement et alerter l'utilisateur par email sécurisé."),
    DetectionRule("privilege_escalation",        "Modification de configuration après une connexion inhabituelle",        "CRITICAL", 0.85, "Auditer les droits accordés et révoquer si non autorisé. Contacter le DSI."),
    DetectionRule("mass_data_export",            "Plus de 10 exports de données en moins d'une heure",                   "ERROR",    0.80, "Suspendre les exports, vérifier le contexte métier et notifier le DPO."),
    DetectionRule("off_hours_activity",          "Activité significative en dehors des heures ouvrables (22h–6h)",       "WARNING",  0.55, "Confirmer avec l'utilisateur si l'activité était légitime."),
    DetectionRule("anomalous_transaction_volume","Volume de transactions anormal",                                        "ERROR",    0.75, "Geler les transactions suspectes et lancer une vérification manuelle."),
    DetectionRule("high_value_transaction",      "Transaction >10 000 € par un acteur sans historique",                  "ERROR",    0.70, "Validation manuelle obligatoire avant exécution (DSP2 / AML)."),
    DetectionRule("api_key_rotation_anomaly",    "Rotation de clé API suivie d'un appel suspect",                        "ERROR",    0.78, "Révoquer la nouvelle clé et auditer les appels effectués avec elle."),
    DetectionRule("impossible_travel",           "Connexions depuis des IPs géographiquement incompatibles (<1h d'écart)","CRITICAL", 0.92, "Forcer une ré-authentification MFA et notifier l'utilisateur."),
    DetectionRule("repeated_access_denied",      "Plus de 3 accès refusés à des ressources sensibles en 30 minutes",    "WARNING",  0.60, "Vérifier les droits de l'utilisateur et inspecter les ressources ciblées."),
    DetectionRule("dormant_account_activation",  "Compte inactif depuis >90 jours soudainement actif",                  "WARNING",  0.65, "Vérifier avec le responsable RH si le compte est encore valide."),
]

RULES_BY_NAME = {r.name: r for r in DETECTION_RULES}


# ══════════════════════════════════════════════════════════════════════════════
# MOTEUR D'INVESTIGATION
# ══════════════════════════════════════════════════════════════════════════════

class InvestigationEngine:
    """Moteur principal d'investigation Spidercrypt Enterprise (Pandas)."""

    def __init__(self, signing_key_b64: str | None = None):
        self._df_audit:    pd.DataFrame | None = None
        self._df_tx:       pd.DataFrame | None = None
        self._signing_key = None

        if signing_key_b64 and HAS_NACL:
            raw = base64.b64decode(signing_key_b64)
            self._signing_key = nacl.signing.SigningKey(raw)
        elif signing_key_b64 and not HAS_NACL:
            print("⚠️  PyNaCl non installé — signatures Ed25519 désactivées")

    # ── Chargement ────────────────────────────────────────────────────────────

    def load_audit_events(self, path: str | pd.DataFrame) -> "InvestigationEngine":
        self._df_audit = self._load(path)
        print(f"  📂 Audit events : {len(self._df_audit):,} événements chargés")
        return self

    def load_transactions(self, path: str | pd.DataFrame) -> "InvestigationEngine":
        self._df_tx = self._load(path)
        print(f"  📂 Transactions : {len(self._df_tx):,} transactions chargées")
        return self

    def _load(self, source: str | pd.DataFrame) -> pd.DataFrame:
        if isinstance(source, pd.DataFrame):
            return source.copy()
        p = Path(source)
        ext = p.suffix.lower()
        if ext == ".parquet": return pd.read_parquet(p)
        if ext == ".csv":     return pd.read_csv(p)
        if ext == ".json":    return pd.read_json(p)
        raise ValueError(f"Format non supporté : {ext}")

    # ── Calcul de la fenêtre temporelle ───────────────────────────────────────

    def _compute_time_window(self, days_back: int) -> tuple[int, int]:
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        max_ts: list[int] = []
        for df in (self._df_audit, self._df_tx):
            if df is not None and "timestamp_ms" in df.columns:
                m = int(df["timestamp_ms"].max())
                if m > 0:
                    max_ts.append(m)

        if not max_ts:
            return int((datetime.now(timezone.utc) - timedelta(days=days_back)).timestamp() * 1000), now_ms

        data_max_ms = max(max_ts)
        seven_days_ms = 7 * 24 * 3600 * 1000
        if now_ms - data_max_ms < seven_days_ms:
            anchor_ms = now_ms
        else:
            anchor_ms = data_max_ms
            lag_days = round((now_ms - data_max_ms) / (24 * 3600 * 1000))
            print(f"  ℹ️  Données décalées de ~{lag_days}j — fenêtre ancrée sur le dernier timestamp connu")

        since_ms = anchor_ms - days_back * 24 * 3600 * 1000
        return since_ms, anchor_ms

    # ── Investigation principale ──────────────────────────────────────────────

    def investigate(
        self,
        actor_id: str | None = None,
        resource_id: str | None = None,
        days_back: int = 30,
        investigator_name: str = "SpidercryptEnterprise/2.0",
    ) -> InvestigationReport:
        t0  = time.time()
        now = datetime.now(timezone.utc)

        since_ms, until_ms = self._compute_time_window(days_back)

        print(f"\n🔍 Investigation démarrée")
        print(f"   Sujet   : {actor_id or resource_id or 'global'}")
        print(f"   Période : {days_back} derniers jours")
        print(f"   Fenêtre : {datetime.fromtimestamp(since_ms/1000, tz=timezone.utc).strftime('%Y-%m-%d')} "
              f"→ {datetime.fromtimestamp(until_ms/1000, tz=timezone.utc).strftime('%Y-%m-%d')}")

        timeline  = self._build_timeline(actor_id, resource_id, since_ms, until_ms)
        print(f"  ⏱  Timeline : {len(timeline)} événements")

        if len(timeline) == 0:
            self._diagnose_empty_timeline(actor_id, resource_id, since_ms, until_ms)

        anomalies = self._detect_anomalies(timeline, actor_id or "")
        print(f"  🚨 Anomalies : {len(anomalies)} signaux détectés")

        stats           = self._compute_statistics(timeline)
        risk            = self._assess_risk(anomalies, stats)
        recommendations = self._build_recommendations(anomalies, risk)
        graph_summary   = self._build_graph_summary(timeline)

        # CORRECTION #5 — summary est construit APRÈS _assess_risk, de sorte
        # que risk["niveau"] soit disponible avant la signature. Auparavant,
        # _sign_report pouvait couvrir un summary partiellement incomplet.
        summary = {
            "total_events":     len(timeline),
            "anomalies_count":  len(anomalies),
            "risk_level":       risk.get("niveau", "FAIBLE"),
            "risk_score":       risk.get("score_global", 0.0),
            "critical_signals": sum(1 for a in anomalies if a.severite == "CRITICAL"),
        }

        report = InvestigationReport(
            report_id=    str(uuid.uuid4()),
            generated_at= now.isoformat(),
            investigator= investigator_name,
            subject={
                "actor_id":    actor_id,
                "resource_id": resource_id,
                "days_back":   days_back,
                "since":       datetime.fromtimestamp(since_ms / 1000, tz=timezone.utc).isoformat(),
                "until":       datetime.fromtimestamp(until_ms / 1000, tz=timezone.utc).isoformat(),
            },
            summary=         summary,
            timeline=        [e.to_dict() for e in timeline],
            anomalies=       [a.to_dict() for a in anomalies],
            statistics=      stats,
            risk_assessment= risk,
            recommendations= recommendations,
            graph_summary=   graph_summary,
            signature_ed25519= None,
            signature_hash=    None,
        )

        self._sign_report(report)

        duration = round(time.time() - t0, 2)
        print(f"\n✅ Investigation terminée en {duration}s")
        print(f"   Risque    : {report.risk_level()} (score {risk.get('score_global', 0):.2f})")
        print(f"   Report ID : {report.report_id}")
        return report

    # ── Diagnostic timeline vide ──────────────────────────────────────────────

    def _diagnose_empty_timeline(
        self,
        actor_id: str | None,
        resource_id: str | None,
        since_ms: int,
        until_ms: int,
    ) -> None:
        print("\n  ⚠️  Timeline vide — diagnostic :")

        if self._df_audit is not None and "timestamp_ms" in self._df_audit.columns:
            ts_min = self._df_audit["timestamp_ms"].min()
            ts_max = self._df_audit["timestamp_ms"].max()
            print(f"     audit_events : timestamps [{ts_min} → {ts_max}]")
            print(f"     fenêtre      : [{since_ms} → {until_ms}]")
            in_window = self._df_audit[
                (self._df_audit["timestamp_ms"] >= since_ms) &
                (self._df_audit["timestamp_ms"] <= until_ms)
            ]
            print(f"     événements dans la fenêtre : {len(in_window)}")

            if actor_id and "acteur_id" in self._df_audit.columns:
                actor_events = self._df_audit[self._df_audit["acteur_id"] == actor_id]
                print(f"     événements pour l'acteur '{actor_id}' (toutes dates) : {len(actor_events)}")
                if len(actor_events) == 0:
                    sample = self._df_audit["acteur_id"].unique()[:5].tolist()
                    print(f"     → acteur_id introuvable. Exemples valides : {sample}")

    # ── Timeline ──────────────────────────────────────────────────────────────

    def _build_timeline(
        self,
        actor_id: str | None,
        resource_id: str | None,
        since_ms: int,
        until_ms: int,
    ) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []

        if self._df_audit is not None:
            df = self._df_audit.copy()
            if "timestamp_ms" in df.columns:
                df = df[(df["timestamp_ms"] >= since_ms) & (df["timestamp_ms"] <= until_ms)]
            if actor_id and "acteur_id" in df.columns:
                df = df[df["acteur_id"] == actor_id]
            if resource_id and "resource_id" in df.columns:
                df = df[df["resource_id"] == resource_id]
            for row in df.to_dict(orient="records"):
                events.append(self._audit_row_to_event(row))

        if self._df_tx is not None:
            df = self._df_tx.copy()
            if "timestamp_ms" in df.columns:
                df = df[(df["timestamp_ms"] >= since_ms) & (df["timestamp_ms"] <= until_ms)]
            # CORRECTION #2 — les transactions sont liées à un acteur utilisateur
            # via "acteur_id" (s'il existe) plutôt que "marchand_id".
            # Filtrer par marchand_id==actor_id revient à ne jamais corréler les
            # transactions d'un utilisateur avec sa timeline d'audit.
            # On tente d'abord "acteur_id", puis "marchand_id" en fallback.
            if actor_id:
                if "acteur_id" in df.columns:
                    df = df[df["acteur_id"] == actor_id]
                elif "marchand_id" in df.columns:
                    df = df[df["marchand_id"] == actor_id]
            for row in df.to_dict(orient="records"):
                events.append(self._tx_row_to_event(row))

        events.sort(key=lambda e: e.timestamp_ms)
        return events

    def _audit_row_to_event(self, row: dict) -> TimelineEvent:
        succes   = bool(row.get("succes", True))
        action   = str(row.get("action", "UNKNOWN"))
        severite = str(row.get("severite", "INFO"))
        ts_ms    = int(row.get("timestamp_ms", 0))
        ts_iso   = str(row.get("timestamp_iso") or datetime.fromtimestamp(
            ts_ms / 1000, tz=timezone.utc).isoformat())

        flags = []
        if not succes:
            flags.append("ECHEC")
        if severite in ("ERROR", "CRITICAL"):
            flags.append("ALERTE_SECURITE")
        try:
            heure = datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).hour
            if heure >= 22 or heure < 6:
                flags.append("HEURE_INHABITUELLE")
        except Exception:
            pass

        return TimelineEvent(
            event_id=      str(row.get("event_id", uuid.uuid4())),
            timestamp_iso= ts_iso,
            timestamp_ms=  ts_ms,
            source=        "audit",
            category=      _categorize_action(action),
            action=        action,
            actor_id=      str(row.get("acteur_id", "")),
            resource=      f"{row.get('resource_type','')}:{row.get('resource_id','')}",
            succes=        succes,
            severite=      severite,
            risque_score=  0.8 if not succes else 0.1,
            details={k: v for k, v in row.items()
                     if k not in ("event_id","timestamp_ms","timestamp_iso",
                                  "acteur_id","action","succes","severite")},
            flags=flags,
        )

    def _tx_row_to_event(self, row: dict) -> TimelineEvent:
        montant  = float(row.get("montant_eur", 0) or 0)
        statut   = str(row.get("statut", "UNKNOWN"))
        est_anom = bool(row.get("est_anomalie", False))
        risque   = float(row.get("risque_score", 0.0) or 0)

        flags = []
        if est_anom:
            flags.append(f"ANOMALIE_{str(row.get('type_anomalie','')).upper()}")
        if montant > 10_000:
            flags.append("MONTANT_ELEVE")
        if statut == "FAILED":
            flags.append("TRANSACTION_ECHOUEE")

        return TimelineEvent(
            event_id=      str(row.get("transaction_id", uuid.uuid4())),
            timestamp_iso= str(row.get("timestamp_iso", "")),
            timestamp_ms=  int(row.get("timestamp_ms", 0)),
            source=        "transaction",
            category=      "payment",
            action=        f"TRANSACTION_{statut}",
            actor_id=      str(row.get("acteur_id", row.get("marchand_id", ""))),
            resource=      f"TX:{row.get('transaction_id','')}",
            succes=        statut == "COMPLETED",
            severite=      "ERROR" if est_anom else ("WARNING" if statut == "FAILED" else "INFO"),
            risque_score=  risque,
            details={
                "montant_eur": montant,
                "devise":      str(row.get("devise", "EUR")),
                "moyen":       str(row.get("moyen_paiement", "")),
                "secteur":     str(row.get("secteur", "")),
                "ville":       str(row.get("ville", "")),
            },
            flags=flags,
        )

    # ── Détection d'anomalies ─────────────────────────────────────────────────

    def _detect_anomalies(self, timeline: list[TimelineEvent], actor_id: str) -> list[AnomalySignal]:
        anomalies: list[AnomalySignal] = []
        anomalies += self._detect_brute_force(timeline, actor_id)
        anomalies += self._detect_mass_export(timeline, actor_id)
        anomalies += self._detect_off_hours(timeline, actor_id)
        anomalies += self._detect_high_value_tx(timeline, actor_id)
        anomalies += self._detect_access_denied_pattern(timeline, actor_id)
        anomalies += self._detect_config_after_login(timeline, actor_id)
        anomalies.sort(key=lambda a: a.score, reverse=True)
        return anomalies

    def _detect_brute_force(self, timeline: list[TimelineEvent], actor_id: str) -> list[AnomalySignal]:
        """
        CORRECTION #1 — on ne retourne plus dès la première itération.
        On parcourt toutes les fenêtres possibles et on retourne le signal
        couvrant la fenêtre la plus dense (max events_count).
        Auparavant, si le premier événement ne déclenchait pas la règle,
        la boucle continuait mais retournait [] sans inspecter les suivants.
        """
        login_fails = [e for e in timeline if e.action == "LOGIN" and not e.succes]
        if len(login_fails) < 5:
            return []
        window_ms  = 10 * 60 * 1000
        best: list[TimelineEvent] = []
        for evt in login_fails:
            window = [e for e in login_fails if 0 <= e.timestamp_ms - evt.timestamp_ms <= window_ms]
            if len(window) >= 5 and len(window) > len(best):
                best = window
        if not best:
            return []
        rule = RULES_BY_NAME["brute_force_login"]
        return [AnomalySignal(
            signal_id=str(uuid.uuid4()), detected_at=datetime.now(timezone.utc).isoformat(),
            type_anomalie=rule.name, severite=rule.severite, score=rule.score,
            events_count=len(best), actor_id=actor_id,
            description=f"{len(best)} échecs de connexion en 10 min",
            recommandation=rule.recommandation, event_ids=[e.event_id for e in best],
        )]

    def _detect_mass_export(self, timeline: list[TimelineEvent], actor_id: str) -> list[AnomalySignal]:
        """CORRECTION #1 — même correctif que _detect_brute_force."""
        exports = [e for e in timeline if e.action == "EXPORT"]
        if len(exports) < 10:
            return []
        window_ms = 60 * 60 * 1000
        best: list[TimelineEvent] = []
        for evt in exports:
            window = [e for e in exports if 0 <= e.timestamp_ms - evt.timestamp_ms <= window_ms]
            if len(window) >= 10 and len(window) > len(best):
                best = window
        if not best:
            return []
        rule = RULES_BY_NAME["mass_data_export"]
        return [AnomalySignal(
            signal_id=str(uuid.uuid4()), detected_at=datetime.now(timezone.utc).isoformat(),
            type_anomalie=rule.name, severite=rule.severite,
            score=min(0.99, rule.score + len(best) * 0.01),
            events_count=len(best), actor_id=actor_id,
            description=f"{len(best)} exports en 1h — possible exfiltration",
            recommandation=rule.recommandation, event_ids=[e.event_id for e in best],
        )]

    def _detect_off_hours(self, timeline: list[TimelineEvent], actor_id: str) -> list[AnomalySignal]:
        """
        CORRECTION #4 — on exige que les événements hors-heures soient concentrés
        dans une fenêtre de 24h (pas juste dispersés sur 30 jours).
        Auparavant, 3 événements espacés de 10 jours déclenchaient quand même
        l'anomalie, ce qui générait de nombreux faux positifs.
        """
        off_hours = [e for e in timeline if "HEURE_INHABITUELLE" in e.flags]
        if len(off_hours) < 3:
            return []
        # Chercher la fenêtre de 24h contenant le plus d'événements hors-heures
        window_ms = 24 * 60 * 60 * 1000
        best: list[TimelineEvent] = []
        for evt in off_hours:
            window = [e for e in off_hours if 0 <= e.timestamp_ms - evt.timestamp_ms <= window_ms]
            if len(window) >= 3 and len(window) > len(best):
                best = window
        if not best:
            return []
        rule = RULES_BY_NAME["off_hours_activity"]
        return [AnomalySignal(
            signal_id=str(uuid.uuid4()), detected_at=datetime.now(timezone.utc).isoformat(),
            type_anomalie=rule.name, severite=rule.severite, score=rule.score,
            events_count=len(best), actor_id=actor_id,
            description=f"{len(best)} événements hors heures ouvrables (22h–6h) en 24h",
            recommandation=rule.recommandation, event_ids=[e.event_id for e in best[:20]],
        )]

    def _detect_high_value_tx(self, timeline: list[TimelineEvent], actor_id: str) -> list[AnomalySignal]:
        high_val = [e for e in timeline if e.source == "transaction" and e.details.get("montant_eur", 0) > 10_000]
        if not high_val:
            return []
        rule  = RULES_BY_NAME["high_value_transaction"]
        total = sum(e.details.get("montant_eur", 0) for e in high_val)
        return [AnomalySignal(
            signal_id=str(uuid.uuid4()), detected_at=datetime.now(timezone.utc).isoformat(),
            type_anomalie=rule.name, severite=rule.severite, score=rule.score,
            events_count=len(high_val), actor_id=actor_id,
            description=f"{len(high_val)} transactions >10 000€ — total {total:,.2f}€",
            recommandation=rule.recommandation, event_ids=[e.event_id for e in high_val],
        )]

    def _detect_access_denied_pattern(self, timeline: list[TimelineEvent], actor_id: str) -> list[AnomalySignal]:
        """CORRECTION #1 — même correctif que _detect_brute_force."""
        denied = [e for e in timeline if not e.succes and e.action in ("READ","WRITE","DELETE","EXPORT")]
        if len(denied) < 3:
            return []
        window_ms = 30 * 60 * 1000
        best: list[TimelineEvent] = []
        for evt in denied:
            window = [e for e in denied if 0 <= e.timestamp_ms - evt.timestamp_ms <= window_ms]
            if len(window) >= 3 and len(window) > len(best):
                best = window
        if not best:
            return []
        rule = RULES_BY_NAME["repeated_access_denied"]
        return [AnomalySignal(
            signal_id=str(uuid.uuid4()), detected_at=datetime.now(timezone.utc).isoformat(),
            type_anomalie=rule.name, severite=rule.severite, score=rule.score,
            events_count=len(best), actor_id=actor_id,
            description=f"{len(best)} accès refusés en 30 min",
            recommandation=rule.recommandation, event_ids=[e.event_id for e in best],
        )]

    def _detect_config_after_login(self, timeline: list[TimelineEvent], actor_id: str) -> list[AnomalySignal]:
        signals = []
        logins  = [e for e in timeline if e.action == "LOGIN" and "HEURE_INHABITUELLE" in e.flags]
        configs = [e for e in timeline if e.action == "CONFIG_CHANGE"]
        for login in logins:
            window_ms = 5 * 60 * 1000
            close = [c for c in configs if 0 <= c.timestamp_ms - login.timestamp_ms <= window_ms]
            if close:
                rule = RULES_BY_NAME["privilege_escalation"]
                signals.append(AnomalySignal(
                    signal_id=str(uuid.uuid4()), detected_at=datetime.now(timezone.utc).isoformat(),
                    type_anomalie=rule.name, severite=rule.severite, score=rule.score,
                    events_count=len(close) + 1, actor_id=actor_id,
                    description="Config modifiée <5min après connexion nocturne suspecte",
                    recommandation=rule.recommandation,
                    event_ids=[login.event_id] + [c.event_id for c in close],
                ))
        return signals

    # ── Statistiques ──────────────────────────────────────────────────────────

    def _compute_statistics(self, timeline: list[TimelineEvent]) -> dict:
        if not timeline:
            return {}
        sources = defaultdict(int); categories = defaultdict(int)
        severites = defaultdict(int); actions = defaultdict(int)
        echecs = 0; total_risque = 0.0; montants_tx = []

        for e in timeline:
            sources[e.source] += 1; categories[e.category] += 1
            severites[e.severite] += 1; actions[e.action] += 1
            total_risque += e.risque_score
            if not e.succes: echecs += 1
            if e.source == "transaction":
                m = e.details.get("montant_eur", 0)
                if m > 0: montants_tx.append(m)

        tx_stats = {}
        if montants_tx:
            # CORRECTION #3 — médiane correcte pour les listes de taille paire.
            # montants_tx[n // 2] est biaisé : pour n=4, on prend l'index 2
            # (3e valeur) au lieu de la moyenne des valeurs aux indices 1 et 2.
            montants_tx.sort()
            n = len(montants_tx)
            if n % 2 == 1:
                median = montants_tx[n // 2]
            else:
                median = (montants_tx[n // 2 - 1] + montants_tx[n // 2]) / 2
            tx_stats = {
                "count":   n,
                "total":   round(sum(montants_tx), 2),
                "moyenne": round(sum(montants_tx) / n, 2),
                "median":  round(median, 2),
                "max":     max(montants_tx),
                "min":     min(montants_tx),
            }

        return {
            "total_events":   len(timeline),
            "echecs":         echecs,
            "taux_echec_pct": round(echecs / len(timeline) * 100, 1),
            "risque_moyen":   round(total_risque / len(timeline), 3),
            "par_source":     dict(sources), "par_categorie": dict(categories),
            "par_severite":   dict(severites),
            "top_actions":    dict(sorted(actions.items(), key=lambda x: -x[1])[:10]),
            "transactions":   tx_stats,
            "periode": {"debut": timeline[0].timestamp_iso, "fin": timeline[-1].timestamp_iso},
        }

    def _assess_risk(self, anomalies: list[AnomalySignal], stats: dict) -> dict:
        if not anomalies:
            score = min(0.3, stats.get("taux_echec_pct", 0) / 100)
        else:
            max_score = max(a.score for a in anomalies)
            avg_score = sum(a.score for a in anomalies) / len(anomalies)
            score = min(0.99, max_score * 0.7 + avg_score * 0.3 + min(0.1, len(anomalies) * 0.02))

        if score >= 0.8:    niveau = "CRITIQUE"
        elif score >= 0.6:  niveau = "ÉLEVÉ"
        elif score >= 0.35: niveau = "MODÉRÉ"
        else:               niveau = "FAIBLE"

        return {
            "score_global":     round(score, 3), "niveau": niveau,
            "anomalies_total":  len(anomalies),
            "critiques":        sum(1 for a in anomalies if a.severite == "CRITICAL"),
            "erreurs":          sum(1 for a in anomalies if a.severite == "ERROR"),
            "taux_echec_pct":   stats.get("taux_echec_pct", 0),
            "risque_moyen_evt": stats.get("risque_moyen", 0),
        }

    def _build_recommendations(self, anomalies: list[AnomalySignal], risk: dict) -> list[str]:
        recs = []; seen = set()
        for a in anomalies:
            if a.recommandation not in seen:
                recs.append(f"[{a.severite}] {a.recommandation}"); seen.add(a.recommandation)
        niveau = risk.get("niveau", "FAIBLE")
        if niveau == "CRITIQUE":
            recs.insert(0, "[URGENT] Escalader immédiatement au RSSI et au DPO.")
            recs.append("Documenter l'incident pour notification CNIL si données personnelles impliquées.")
        elif niveau == "ÉLEVÉ":
            recs.append("Planifier un audit de sécurité complet sous 48h.")
        elif niveau == "MODÉRÉ":
            recs.append("Surveiller l'activité de cet acteur pendant 7 jours.")
        recs.append("Conserver ce rapport pendant au moins 3 ans (conformité RGPD Art.30).")
        return recs

    def _build_graph_summary(self, timeline: list[TimelineEvent]) -> dict:
        actors = defaultdict(int); resources = defaultdict(int); edges = defaultdict(int)
        for e in timeline:
            actors[e.actor_id] += 1; resources[e.resource] += 1
            edges[(e.actor_id, e.resource)] += 1
        return {
            "total_actors":    len(actors), "total_resources": len(resources), "total_edges": len(edges),
            "top_actors":      [{"id": a, "events": n} for a, n in sorted(actors.items(), key=lambda x: -x[1])[:10]],
            "top_resources":   [{"id": r, "events": n} for r, n in sorted(resources.items(), key=lambda x: -x[1])[:10]],
            "top_relations":   [{"actor": a, "resource": r, "count": n}
                                for (a, r), n in sorted(edges.items(), key=lambda x: -x[1])[:10]],
        }

    def _sign_report(self, report: InvestigationReport) -> None:
        content = json.dumps({
            "report_id": report.report_id, "generated_at": report.generated_at,
            "summary": report.summary, "anomalies": report.anomalies,
        }, sort_keys=True, ensure_ascii=False).encode("utf-8")
        report.signature_hash = hashlib.sha256(content).hexdigest()
        if self._signing_key and HAS_NACL:
            signed = self._signing_key.sign(content)
            report.signature_ed25519 = base64.b64encode(signed.signature).decode()

    def save_report(self, report: InvestigationReport, path: str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        size_kb = round(p.stat().st_size / 1024, 1)
        print(f"\n  💾 Rapport sauvegardé → {p}  ({size_kb} Ko)")
        print(f"     SHA-256 : {report.signature_hash}")
        return p

    def print_summary(self, report: InvestigationReport) -> None:
        lvl   = report.risk_level()
        icons = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "MODÉRÉ": "🟡", "FAIBLE": "🟢"}
        score = report.risk_assessment.get("score_global", 0)
        print(f"\n{'═'*60}")
        print(f"  🕷️  RAPPORT D'INVESTIGATION SPIDERCRYPT")
        print(f"{'═'*60}")
        print(f"  ID         : {report.report_id}")
        print(f"  Généré le  : {report.generated_at}")
        print(f"  Sujet      : {report.subject.get('actor_id') or report.subject.get('resource_id')}")
        print(f"  Période    : {report.subject.get('days_back')} jours")
        print(f"{'─'*60}")
        print(f"  {icons.get(lvl,'⚪')} Niveau de risque : {lvl}  (score {score:.2f})")
        print(f"  Événements analysés  : {report.summary.get('total_events', 0):,}")
        print(f"  Anomalies détectées  : {report.summary.get('anomalies_count', 0)}")
        print(f"  Signaux critiques    : {report.summary.get('critical_signals', 0)}")
        if report.anomalies:
            print(f"{'─'*60}")
            print(f"  🚨 ANOMALIES :")
            for a in report.anomalies[:5]:
                sev_icon = {"CRITICAL": "🔴", "ERROR": "🟠", "WARNING": "🟡"}.get(a["severite"], "⚪")
                print(f"    {sev_icon} [{a['severite']}] {a['type_anomalie']} — score {a['score']:.2f}")
                print(f"       {a['description']}")
        print(f"{'─'*60}")
        print(f"  📋 RECOMMANDATIONS :")
        for rec in report.recommendations[:4]:
            print(f"    → {rec}")
        print(f"{'═'*60}\n")

    @staticmethod
    def generate_signing_key() -> tuple[str, str]:
        if not HAS_NACL:
            raise ImportError("pip install pynacl")
        sk = nacl.signing.SigningKey.generate()
        sk_b64 = base64.b64encode(bytes(sk)).decode()
        vk_b64 = base64.b64encode(bytes(sk.verify_key)).decode()
        print(f"🔑 Clé de signature (privée) : {sk_b64}")
        print(f"🔓 Clé de vérification (pub) : {vk_b64}")
        return sk_b64, vk_b64


# ══════════════════════════════════════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

def _categorize_action(action: str) -> str:
    return {
        "LOGIN": "auth", "LOGOUT": "auth",
        "READ": "data_access", "WRITE": "data_access", "DELETE": "data_access",
        "EXPORT": "data_access", "IMPORT": "data_access",
        "API_CALL": "api", "KEY_ROTATE": "security", "CONFIG_CHANGE": "config",
    }.get(action, "system")


# ══════════════════════════════════════════════════════════════════════════════
# DÉMO CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
  from spidercrypt_investigation import InvestigationEngine

# 1. Initialiser le moteur
engine = InvestigationEngine()

# 2. Charger les événements réseau transformés
engine.load_audit_events("data/audit_events.parquet")

# 3. Lancer une investigation pour un acteur spécifique
# Remplace "user_5a5fadaa" par un acteur présent dans tes données
report = engine.investigate(actor_id="user_5a5fadaa", days_back=30)

# 4. Afficher et sauvegarder le rapport
engine.print_summary(report)
engine.save_report(report, "rapports/investigation_reseau.json")