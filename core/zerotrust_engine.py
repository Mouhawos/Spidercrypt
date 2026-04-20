"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT ENTERPRISE — Moteur Zero-Trust                        ║
║   Never Trust · Always Verify · Least Privilege · Continuous Monitoring    ║
╚══════════════════════════════════════════════════════════════════════════════╝

Implémente les 5 piliers du Zero-Trust selon NIST SP 800-207 :
  1. Vérification d'identité continue (toujours re-vérifier, jamais faire confiance)
  2. Contrôle d'accès par contexte (device, réseau, heure, comportement)
  3. Micro-segmentation des ressources
  4. Chiffrement de bout-en-bout (intégration ChaCha20-Poly1305 SpiderCrypt)
  5. Journalisation immuable & détection d'anomalies en temps réel

Dépendances :
    pip install polars pynacl cryptography faker

Usage :
    from spidercrypt_zerotrust import ZeroTrustEngine
    engine = ZeroTrustEngine()
    decision = engine.evaluate(request)
    print(decision.verdict)   # ALLOW | DENY | CHALLENGE_MFA | STEP_UP
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

# ══════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

class TrustLevel(int, Enum):
    """Niveau de confiance calculé (0–100)."""
    CRITICAL   = 0
    VERY_LOW   = 20
    LOW        = 40
    MEDIUM     = 60
    HIGH       = 80
    FULL       = 100

class Verdict(str, Enum):
    """Décision finale du moteur Zero-Trust."""
    ALLOW         = "ALLOW"          # Accès accordé
    DENY          = "DENY"           # Accès refusé
    CHALLENGE_MFA = "CHALLENGE_MFA"  # MFA supplémentaire requis
    STEP_UP       = "STEP_UP"        # Authentification renforcée requise
    QUARANTINE    = "QUARANTINE"     # Session isolée (lecture seule, surveillance max)

class RiskFactor(str, Enum):
    """Facteurs de risque Zero-Trust."""
    UNKNOWN_DEVICE          = "unknown_device"
    UNMANAGED_DEVICE        = "unmanaged_device"
    ANOMALOUS_LOCATION      = "anomalous_location"
    TOR_EXIT_NODE           = "tor_exit_node"
    HIGH_RISK_ASN           = "high_risk_asn"
    OFF_HOURS               = "off_hours"
    IMPOSSIBLE_TRAVEL       = "impossible_travel"
    SENSITIVE_RESOURCE      = "sensitive_resource"
    BULK_OPERATION          = "bulk_operation"
    FAILED_ATTEMPTS         = "failed_attempts"
    DORMANT_ACCOUNT         = "dormant_account"
    PRIVILEGE_MISMATCH      = "privilege_mismatch"
    ANOMALOUS_USER_AGENT    = "anomalous_user_agent"
    STALE_SESSION           = "stale_session"
    NO_MFA                  = "no_mfa"
    WEAK_AUTH               = "weak_auth"

# Poids des facteurs de risque (impacts sur le score de confiance, négatifs)
RISK_WEIGHTS: dict[RiskFactor, float] = {
    RiskFactor.UNKNOWN_DEVICE:       -30,
    RiskFactor.UNMANAGED_DEVICE:     -15,
    RiskFactor.ANOMALOUS_LOCATION:   -20,
    RiskFactor.TOR_EXIT_NODE:        -50,
    RiskFactor.HIGH_RISK_ASN:        -25,
    RiskFactor.OFF_HOURS:            -10,
    RiskFactor.IMPOSSIBLE_TRAVEL:    -60,
    RiskFactor.SENSITIVE_RESOURCE:   -15,
    RiskFactor.BULK_OPERATION:       -20,
    RiskFactor.FAILED_ATTEMPTS:      -35,
    RiskFactor.DORMANT_ACCOUNT:      -20,
    RiskFactor.PRIVILEGE_MISMATCH:   -40,
    RiskFactor.ANOMALOUS_USER_AGENT: -10,
    RiskFactor.STALE_SESSION:        -10,
    RiskFactor.NO_MFA:               -20,
    RiskFactor.WEAK_AUTH:            -15,
}

# Ressources classifiées par sensibilité (0=public, 1=interne, 2=confidentiel, 3=secret)
RESOURCE_SENSITIVITY: dict[str, int] = {
    "PUBLIC":        0,
    "INTERNAL":      1,
    "CONFIDENTIAL":  2,
    "SECRET":        3,
}

# Seuils de décision par niveau de sensibilité
DECISION_THRESHOLDS: dict[int, dict[str, int]] = {
    0: {"allow": 30,  "challenge_mfa": 15,  "step_up": 10},   # PUBLIC
    1: {"allow": 50,  "challenge_mfa": 35,  "step_up": 20},   # INTERNAL
    2: {"allow": 65,  "challenge_mfa": 50,  "step_up": 35},   # CONFIDENTIAL
    3: {"allow": 80,  "challenge_mfa": 65,  "step_up": 50},   # SECRET
}

# IPs / ASNs connus à risque (liste de démonstration — en prod: threat intel feed)
HIGH_RISK_ASN_RANGES = {
    "185.220.",   # Tor relays connus
    "176.10.",    # VPN/Tor providers
    "94.102.",    # Bulletproof hosting
}

# Plages horaires ouvrables (configurable)
WORK_HOURS = (7, 20)  # 07h–20h

# ══════════════════════════════════════════════════════════════════════════════
# MODÈLES DE DONNÉES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DeviceContext:
    """Contexte de l'appareil effectuant la requête."""
    device_id:         str
    is_managed:        bool   = False   # Appareil géré par MDM/EMM
    is_compliant:      bool   = False   # Conformité aux politiques (chiffrement, patch…)
    os_type:           str    = "UNKNOWN"  # WINDOWS | MACOS | LINUX | MOBILE | UNKNOWN
    os_version:        str    = "UNKNOWN"
    certificate:       str | None = None  # Certificat client mTLS
    last_seen_ip:      str | None = None
    registered_at:     str | None = None
    trust_score:       float  = 0.5     # 0.0 → 1.0

    def fingerprint(self) -> str:
        """Empreinte déterministe de l'appareil."""
        raw = f"{self.device_id}:{self.os_type}:{self.os_version}:{self.certificate or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class NetworkContext:
    """Contexte réseau de la connexion."""
    ip_address:     str
    asn:            str | None = None
    country:        str | None = None
    city:           str | None = None
    is_vpn:         bool = False
    is_tor:         bool = False
    is_proxy:       bool = False
    is_corporate:   bool = False     # IP du réseau d'entreprise connu
    user_agent:     str | None = None
    tls_version:    str = "TLS1.3"
    tls_cipher:     str | None = None


@dataclass
class IdentityContext:
    """Contexte d'identité de l'utilisateur."""
    user_id:          str
    roles:            list[str] = field(default_factory=list)
    auth_method:      str = "PASSWORD"  # PASSWORD | MFA_TOTP | MFA_FIDO2 | SSO | CERT
    auth_time:        str | None = None  # ISO timestamp de la dernière auth
    session_id:       str | None = None
    session_age_min:  float = 0          # Âge de la session en minutes
    mfa_verified:     bool = False
    risk_score:       float = 0.0        # Score de risque historique (0.0–1.0)
    last_login_ip:    str | None = None
    last_login_time:  str | None = None
    failed_attempts:  int = 0
    account_created:  str | None = None
    is_service_account: bool = False


@dataclass
class ResourceRequest:
    """Requête d'accès à une ressource spécifique."""
    resource_id:      str
    resource_type:    str   # API_KEY | DOCUMENT | USER_ACCOUNT | CONFIG | EXPORT | DB_TABLE
    sensitivity:      str   = "INTERNAL"  # PUBLIC | INTERNAL | CONFIDENTIAL | SECRET
    action:           str   = "READ"      # READ | WRITE | DELETE | EXPORT | ADMIN
    is_bulk:          bool  = False       # Opération en masse (>100 items)
    data_volume_mb:   float = 0.0
    requested_at:     str | None = None

    @property
    def sensitivity_level(self) -> int:
        return RESOURCE_SENSITIVITY.get(self.sensitivity, 1)


@dataclass
class ZeroTrustRequest:
    """
    Requête complète soumise au moteur Zero-Trust.
    Agrège tous les contextes nécessaires à l'évaluation.
    """
    request_id:  str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    identity:    IdentityContext   = field(default_factory=lambda: IdentityContext(user_id=""))
    device:      DeviceContext     = field(default_factory=lambda: DeviceContext(device_id=""))
    network:     NetworkContext    = field(default_factory=lambda: NetworkContext(ip_address=""))
    resource:    ResourceRequest   = field(default_factory=lambda: ResourceRequest(resource_id=""))


@dataclass
class PolicyViolation:
    """Violation d'une politique Zero-Trust détectée."""
    policy_id:    str
    policy_name:  str
    severity:     str   # INFO | WARNING | ERROR | CRITICAL
    description:  str
    remediation:  str
    risk_factor:  RiskFactor | None = None


@dataclass
class ZeroTrustDecision:
    """
    Décision complète du moteur Zero-Trust avec justification.
    """
    request_id:       str
    decided_at:       str
    verdict:          Verdict
    trust_score:      int          # 0–100
    risk_factors:     list[RiskFactor]
    violations:       list[PolicyViolation]
    ttl_seconds:      int          # Durée de validité de la décision
    session_bindings: dict         # Contraintes de session à appliquer
    audit_trail:      dict         # Trace complète pour journalisation
    recommendations:  list[str]    # Actions recommandées (pour l'admin)
    context_hash:     str          # Hash SHA-256 du contexte d'évaluation

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"]      = self.verdict.value
        d["risk_factors"] = [r.value for r in self.risk_factors]
        return d

    def is_allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def requires_mfa(self) -> bool:
        return self.verdict == Verdict.CHALLENGE_MFA

    def summary(self) -> str:
        icon = {
            Verdict.ALLOW:         "✅",
            Verdict.DENY:          "🚫",
            Verdict.CHALLENGE_MFA: "🔐",
            Verdict.STEP_UP:       "⬆️",
            Verdict.QUARANTINE:    "🔒",
        }.get(self.verdict, "❓")
        return (
            f"{icon} [{self.verdict.value}] trust={self.trust_score}/100 "
            f"| {len(self.risk_factors)} risques | {len(self.violations)} violations"
        )


# ══════════════════════════════════════════════════════════════════════════════
# POLITIQUES ZERO-TRUST
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ZeroTrustPolicy:
    """Politique de contrôle d'accès Zero-Trust."""
    policy_id:   str
    name:        str
    description: str
    severity:    str
    condition:   str   # Description lisible de la condition
    remediation: str
    risk_factor: RiskFactor | None = None

ZERO_TRUST_POLICIES: list[ZeroTrustPolicy] = [

    ZeroTrustPolicy(
        policy_id="ZTP-001",
        name="device_registration_required",
        description="Tout accès doit provenir d'un appareil enregistré",
        severity="ERROR",
        condition="device.device_id not in device_registry",
        remediation="Enregistrer l'appareil dans le MDM avant d'autoriser l'accès.",
        risk_factor=RiskFactor.UNKNOWN_DEVICE,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-002",
        name="device_compliance_required",
        description="L'appareil doit être conforme aux politiques de sécurité",
        severity="WARNING",
        condition="not device.is_compliant",
        remediation="Appliquer les mises à jour manquantes et activer le chiffrement disque.",
        risk_factor=RiskFactor.UNMANAGED_DEVICE,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-003",
        name="mfa_required_for_sensitive",
        description="MFA obligatoire pour les ressources CONFIDENTIELLES et SECRET",
        severity="CRITICAL",
        condition="resource.sensitivity_level >= 2 and not identity.mfa_verified",
        remediation="Activer l'authentification MFA (TOTP ou FIDO2) sur le compte.",
        risk_factor=RiskFactor.NO_MFA,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-004",
        name="session_max_age",
        description="Les sessions ne peuvent pas dépasser 8h sans re-authentification",
        severity="WARNING",
        condition="identity.session_age_min > 480",
        remediation="Re-authentifier l'utilisateur pour prolonger la session.",
        risk_factor=RiskFactor.STALE_SESSION,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-005",
        name="no_tor_access",
        description="Les accès via le réseau Tor sont interdits",
        severity="CRITICAL",
        condition="network.is_tor == True",
        remediation="Bloquer définitivement. Alerter le SOC immédiatement.",
        risk_factor=RiskFactor.TOR_EXIT_NODE,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-006",
        name="failed_attempts_lockout",
        description="Compte verrouillé après 5 tentatives échouées",
        severity="CRITICAL",
        condition="identity.failed_attempts >= 5",
        remediation="Réinitialiser le mot de passe via canal sécurisé. Notifier l'utilisateur.",
        risk_factor=RiskFactor.FAILED_ATTEMPTS,
    ),
        ZeroTrustPolicy(
        policy_id="ZTP-007",
        name="privilege_separation",
        description="Les rôles doivent correspondre à la ressource demandée",
        severity="ERROR",
        condition="required roles for this action/resource not satisfied",
        remediation="Demander l'élévation de privilèges via le processus IAM.",
        risk_factor=RiskFactor.PRIVILEGE_MISMATCH,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-008",
        name="bulk_operation_limit",
        description="Les opérations en masse requièrent une approbation supplémentaire",
        severity="WARNING",
        condition="resource.is_bulk == True and resource.sensitivity_level >= 1",
        remediation="Soumettre une demande d'accès temporaire avec justification métier.",
        risk_factor=RiskFactor.BULK_OPERATION,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-009",
        name="tls_minimum_version",
        description="TLS 1.2 minimum requis — TLS 1.3 recommandé",
        severity="ERROR",
        condition="network.tls_version not in ('TLS1.2', 'TLS1.3')",
        remediation="Mettre à jour le client TLS. TLS 1.0/1.1 sont obsolètes.",
        risk_factor=None,
    ),
       ZeroTrustPolicy(
        policy_id="ZTP-010",
        name="geographic_anomaly",
        description="Connexion depuis un pays non autorisé pour ce profil",
        severity="ERROR",
        condition="network.country not in allowed_countries",
        remediation="Vérifier avec l'utilisateur si le déplacement est légitime. Forcer MFA.",
        risk_factor=RiskFactor.ANOMALOUS_LOCATION,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-011",
        name="service_account_ip_restriction",
        description="Les comptes de service ne peuvent se connecter que depuis des IPs fixes",
        severity="CRITICAL",
        condition="identity.is_service_account and not network.is_corporate",
        remediation="Corriger la configuration du service. Désactiver le compte si compromis.",
        risk_factor=RiskFactor.ANOMALOUS_LOCATION,
    ),
    ZeroTrustPolicy(
        policy_id="ZTP-012",
        name="weak_auth_sensitive_resource",
        description="Mot de passe seul insuffisant pour les ressources CONFIDENTIELLES+",
        severity="WARNING",
        condition="identity.auth_method == 'PASSWORD' and resource.sensitivity_level >= 2",
        remediation="Exiger une authentification forte (MFA FIDO2 ou certificat client).",
        risk_factor=RiskFactor.WEAK_AUTH,
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# REGISTRE DES APPAREILS
# ══════════════════════════════════════════════════════════════════════════════

class DeviceRegistry:
    """
    Registre des appareils de confiance (MDM/EMM simplifié).
    En production : intégrer avec Microsoft Intune, Jamf, ou équivalent.
    """

    def __init__(self):
        self._devices: dict[str, DeviceContext] = {}
        self._compliance_cache: dict[str, tuple[bool, float]] = {}  # id → (compliant, ts)

    def register(self, device: DeviceContext) -> str:
        """Enregistre un appareil. Retourne son fingerprint."""
        fp = device.fingerprint()
        self._devices[device.device_id] = device
        print(
            f"  [device] registered: {device.device_id} [{device.os_type}] fp={fp}",
            flush=True,
        )
        return fp

    def lookup(self, device_id: str) -> DeviceContext | None:
        return self._devices.get(device_id)

    def is_registered(self, device_id: str) -> bool:
        return device_id in self._devices

    def is_compliant(self, device_id: str, max_age_min: float = 60.0) -> bool:
        """Vérifie la conformité (avec cache TTL)."""
        if device_id in self._compliance_cache:
            compliant, ts = self._compliance_cache[device_id]
            if time.time() - ts < max_age_min * 60:
                return compliant
        device = self._devices.get(device_id)
        if device is None:
            return False
        result = device.is_managed and device.is_compliant
        self._compliance_cache[device_id] = (result, time.time())
        return result

    def update_compliance(self, device_id: str, compliant: bool) -> None:
        if device_id in self._devices:
            self._devices[device_id].is_compliant = compliant
            self._compliance_cache.pop(device_id, None)

    def generate_demo_fleet(self, n: int = 10) -> list[DeviceContext]:
        """Génère une flotte d'appareils de démonstration."""
        fleet = []
        os_types = ["WINDOWS", "MACOS", "LINUX", "MOBILE"]
        for i in range(n):
            d = DeviceContext(
                device_id   = f"DEV-{i:04d}",
                is_managed  = random.random() > 0.2,
                is_compliant= random.random() > 0.15,
                os_type     = random.choice(os_types),
                os_version  = "latest" if random.random() > 0.3 else "outdated",
                certificate = f"cert_{uuid.uuid4().hex[:8]}" if random.random() > 0.3 else None,
                registered_at = datetime.now(timezone.utc).isoformat(),
                trust_score   = round(random.betavariate(5, 2), 2),
            )
            self.register(d)
            fleet.append(d)
        return fleet


# ══════════════════════════════════════════════════════════════════════════════
# SESSION STORE (Zero-Trust Continuous Verification)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionRecord:
    """Enregistrement d'une session active avec méta-données de confiance."""
    session_id:      str
    user_id:         str
    device_id:       str
    ip_address:      str
    country:         str | None
    created_at:      float      # Unix timestamp
    last_verified:   float      # Dernière vérification continue
    trust_score:     int
    mfa_verified:    bool
    verdicts:        list[str]  = field(default_factory=list)
    flags:           list[str]  = field(default_factory=list)
    is_quarantined:  bool       = False

    @property
    def age_minutes(self) -> float:
        return (time.time() - self.created_at) / 60

    @property
    def verification_age_minutes(self) -> float:
        return (time.time() - self.last_verified) / 60


class SessionStore:
    """
    Store de sessions Zero-Trust avec vérification continue.
    En production : Redis avec TTL automatique.
    """

    def __init__(self, max_session_age_min: float = 480.0):
        self._sessions: dict[str, SessionRecord] = {}
        self.max_age = max_session_age_min

    def create(
        self,
        user_id: str,
        device_id: str,
        ip: str,
        country: str | None,
        trust_score: int,
        mfa_verified: bool,
    ) -> SessionRecord:
        sid = str(uuid.uuid4())
        now = time.time()
        record = SessionRecord(
            session_id   = sid,
            user_id      = user_id,
            device_id    = device_id,
            ip_address   = ip,
            country      = country,
            created_at   = now,
            last_verified= now,
            trust_score  = trust_score,
            mfa_verified = mfa_verified,
        )
        self._sessions[sid] = record
        return record

    def get(self, session_id: str) -> SessionRecord | None:
        s = self._sessions.get(session_id)
        if s and s.age_minutes > self.max_age:
            self.invalidate(session_id)
            return None
        return s

    def update_trust(self, session_id: str, new_score: int) -> None:
        if s := self._sessions.get(session_id):
            s.trust_score    = new_score
            s.last_verified  = time.time()

    def quarantine(self, session_id: str, reason: str) -> None:
        if s := self._sessions.get(session_id):
            s.is_quarantined = True
            s.flags.append(f"QUARANTINE:{reason}")

    def invalidate(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def get_user_sessions(self, user_id: str) -> list[SessionRecord]:
        return [s for s in self._sessions.values() if s.user_id == user_id]

    def purge_expired(self) -> int:
        expired = [
            sid for sid, s in self._sessions.items()
            if s.age_minutes > self.max_age
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    def detect_concurrent_sessions(self, user_id: str) -> list[SessionRecord]:
        """Détecte les sessions concurrentes depuis des IPs différentes."""
        sessions = self.get_user_sessions(user_id)
        ips = {s.ip_address for s in sessions}
        if len(ips) > 1:
            return sessions
        return []


# ══════════════════════════════════════════════════════════════════════════════
# MOTEUR ZERO-TRUST PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

class ZeroTrustEngine:
    """
    Moteur d'évaluation Zero-Trust — Never Trust, Always Verify.

    Évalue chaque requête selon :
    1. Score de confiance contextuel (0–100)
    2. Vérification des politiques de sécurité
    3. Détection des facteurs de risque
    4. Décision adaptative (ALLOW / DENY / CHALLENGE_MFA / STEP_UP / QUARANTINE)
    5. Journalisation immuable pour conformité RGPD Art.30

    Intégration avec les autres modules SpiderCrypt :
    - spidercrypt_investigation.InvestigationEngine (alimentation en événements)
    - spidercrypt_spark_avro.SpidercryptSparkPipeline (chiffrement des journaux)
    - spidercrypt_synthetic.SyntheticDataFactory (génération de données de test)
    """

    # Rôles requis par type d'action × type de ressource
    REQUIRED_ROLES: dict[tuple[str, str], list[str]] = {
        ("READ",   "API_KEY"):      ["developer", "admin"],
        ("WRITE",  "API_KEY"):      ["developer", "admin"],
        ("DELETE", "API_KEY"):      ["admin"],
        ("READ",   "DOCUMENT"):     ["analyst", "developer", "manager", "admin"],
        ("WRITE",  "DOCUMENT"):     ["analyst", "manager", "admin"],
        ("DELETE", "DOCUMENT"):     ["manager", "admin"],
        ("EXPORT", "DOCUMENT"):     ["manager", "admin"],
        ("READ",   "USER_ACCOUNT"): ["hr", "admin"],
        ("WRITE",  "USER_ACCOUNT"): ["hr", "admin"],
        ("DELETE", "USER_ACCOUNT"): ["admin"],
        ("WRITE",  "CONFIG"):       ["admin"],
        ("READ",   "CONFIG"):       ["admin", "sre"],
        ("EXPORT", "DB_TABLE"):     ["dba", "admin"],
    }

    def __init__(
        self,
        device_registry: DeviceRegistry | None = None,
        session_store:   SessionStore   | None = None,
        allowed_countries: set[str] | None = None,
        corporate_ip_prefixes: list[str] | None = None,
        audit_callback=None,
    ):
        self.devices   = device_registry or DeviceRegistry()
        self.sessions  = session_store   or SessionStore()
        self._request_log: list[dict] = []

        # Configuration géographique (France + pays voisins par défaut)
        self.allowed_countries = allowed_countries or {
            "FR", "BE", "CH", "LU", "DE", "NL", "ES", "IT", "GB", "CA", "US"
        }
        # Préfixes IP du réseau d'entreprise
        self.corporate_prefixes = corporate_ip_prefixes or [
            "10.", "172.16.", "192.168.", "100.64."  # RFC 1918 + CGNAT
        ]

        # Callback optionnel pour intégration avec InvestigationEngine
        self._audit_callback = audit_callback

        print(
            "[SpiderCrypt] ZeroTrustEngine initialized (Never Trust / Always Verify)",
            flush=True,
        )

    # ── Point d'entrée principal ──────────────────────────────────────────────

    def evaluate(self, request: ZeroTrustRequest) -> ZeroTrustDecision:
        """
        Évalue une requête d'accès selon les principes Zero-Trust.

        Processus :
        1. Calculer le score de confiance contextuel
        2. Vérifier les politiques de sécurité
        3. Déterminer le verdict
        4. Construire les contraintes de session
        5. Journaliser l'événement
        """
        t0 = time.time()

        # 1. Score de confiance
        trust_score, risk_factors = self._compute_trust_score(request)

        # 2. Évaluation des politiques
        violations = self._evaluate_policies(request, risk_factors)

        # 3. Verdict
        verdict, ttl = self._determine_verdict(
            trust_score, risk_factors, violations, request
        )

        # 4. Contraintes de session
        bindings = self._build_session_bindings(request, verdict, trust_score)

        # 5. Recommandations
        recommendations = self._generate_recommendations(violations, risk_factors, verdict)

        # 6. Hash du contexte (intégrité de l'audit)
        context_hash = self._hash_context(request)

        decision = ZeroTrustDecision(
            request_id       = request.request_id,
            decided_at       = datetime.now(timezone.utc).isoformat(),
            verdict          = verdict,
            trust_score      = trust_score,
            risk_factors     = risk_factors,
            violations       = violations,
            ttl_seconds      = ttl,
            session_bindings = bindings,
            audit_trail      = self._build_audit_trail(request, trust_score, risk_factors),
            recommendations  = recommendations,
            context_hash     = context_hash,
        )

        # 7. Journalisation
        self._log_decision(decision, request, time.time() - t0)

        # 8. Gestion de session
        self._handle_session(request, decision)

        return decision

    # ── Calcul du score de confiance ─────────────────────────────────────────

    def _compute_trust_score(
        self, req: ZeroTrustRequest
    ) -> tuple[int, list[RiskFactor]]:
        """
        Score de confiance Zero-Trust (0–100).
        Commence à 100 et est dégradé par les facteurs de risque.
        """
        score   = 100.0
        factors: list[RiskFactor] = []

        # ── Identité ──────────────────────────────────────────────────────────
        if not req.identity.mfa_verified:
            score  += RISK_WEIGHTS[RiskFactor.NO_MFA]
            factors.append(RiskFactor.NO_MFA)

        if req.identity.auth_method == "PASSWORD":
            score  += RISK_WEIGHTS[RiskFactor.WEAK_AUTH]
            factors.append(RiskFactor.WEAK_AUTH)

        if req.identity.failed_attempts >= 3:
            pen = RISK_WEIGHTS[RiskFactor.FAILED_ATTEMPTS] * (req.identity.failed_attempts / 5)
            score  += pen
            factors.append(RiskFactor.FAILED_ATTEMPTS)

        if req.identity.session_age_min > 480:
            score  += RISK_WEIGHTS[RiskFactor.STALE_SESSION]
            factors.append(RiskFactor.STALE_SESSION)

        # Compte dormant (inactif >90 jours)
        if req.identity.last_login_time:
            try:
                last = datetime.fromisoformat(
                    req.identity.last_login_time.replace("Z", "+00:00")
                )
                days_inactive = (datetime.now(timezone.utc) - last).days
                if days_inactive > 90:
                    score  += RISK_WEIGHTS[RiskFactor.DORMANT_ACCOUNT]
                    factors.append(RiskFactor.DORMANT_ACCOUNT)
            except Exception:
                pass

        # Risque historique de l'utilisateur
        score -= req.identity.risk_score * 20  # Max -20 points

        # ── Appareil ──────────────────────────────────────────────────────────
        if not self.devices.is_registered(req.device.device_id):
            score  += RISK_WEIGHTS[RiskFactor.UNKNOWN_DEVICE]
            factors.append(RiskFactor.UNKNOWN_DEVICE)
        elif not self.devices.is_compliant(req.device.device_id):
            score  += RISK_WEIGHTS[RiskFactor.UNMANAGED_DEVICE]
            factors.append(RiskFactor.UNMANAGED_DEVICE)
        else:
            # Bonus pour appareil géré + conforme + certificat client
            if req.device.certificate:
                score += 5
            score += req.device.trust_score * 10  # Max +10

        # ── Réseau ────────────────────────────────────────────────────────────
        if req.network.is_tor:
            score  += RISK_WEIGHTS[RiskFactor.TOR_EXIT_NODE]
            factors.append(RiskFactor.TOR_EXIT_NODE)

        elif req.network.is_vpn or req.network.is_proxy:
            score  += RISK_WEIGHTS[RiskFactor.HIGH_RISK_ASN] // 2
            factors.append(RiskFactor.HIGH_RISK_ASN)

        elif any(req.network.ip_address.startswith(p) for p in HIGH_RISK_ASN_RANGES):
            score  += RISK_WEIGHTS[RiskFactor.HIGH_RISK_ASN]
            factors.append(RiskFactor.HIGH_RISK_ASN)

        # Bonus réseau d'entreprise
        if req.network.is_corporate or any(
            req.network.ip_address.startswith(p) for p in self.corporate_prefixes
        ):
            score += 10

        # Pays autorisé
        if req.network.country and req.network.country not in self.allowed_countries:
            score  += RISK_WEIGHTS[RiskFactor.ANOMALOUS_LOCATION]
            factors.append(RiskFactor.ANOMALOUS_LOCATION)

        # User-Agent suspect (headless, vieux navigateur, outils d'attaque)
        if req.network.user_agent:
            suspicious_ua = ["sqlmap", "nikto", "masscan", "nmap", "zgrab",
                              "python-requests/2.0", "curl/7.0", "wget/1.0"]
            if any(s.lower() in req.network.user_agent.lower() for s in suspicious_ua):
                score  += RISK_WEIGHTS[RiskFactor.ANOMALOUS_USER_AGENT]
                factors.append(RiskFactor.ANOMALOUS_USER_AGENT)

        # Voyage impossible (vérification avec la session existante)
        if req.identity.session_id:
            existing = self.sessions.get(req.identity.session_id)
            if existing and existing.country and req.network.country:
                if existing.country != req.network.country:
                    delta_min = (time.time() - existing.last_verified) / 60
                    if delta_min < 120:  # <2h pour traverser un pays
                        score  += RISK_WEIGHTS[RiskFactor.IMPOSSIBLE_TRAVEL]
                        factors.append(RiskFactor.IMPOSSIBLE_TRAVEL)

        # ── Heure ─────────────────────────────────────────────────────────────
        try:
            ts = datetime.fromisoformat(req.timestamp.replace("Z", "+00:00"))
            hour = ts.hour
            if hour < WORK_HOURS[0] or hour >= WORK_HOURS[1]:
                score  += RISK_WEIGHTS[RiskFactor.OFF_HOURS]
                factors.append(RiskFactor.OFF_HOURS)
        except Exception:
            pass

        # ── Ressource ─────────────────────────────────────────────────────────
        if req.resource.sensitivity_level >= 2:
            score  += RISK_WEIGHTS[RiskFactor.SENSITIVE_RESOURCE]
            factors.append(RiskFactor.SENSITIVE_RESOURCE)

        if req.resource.is_bulk:
            score  += RISK_WEIGHTS[RiskFactor.BULK_OPERATION]
            factors.append(RiskFactor.BULK_OPERATION)

        # Contrôle des rôles
        key = (req.resource.action, req.resource.resource_type)
        required = self.REQUIRED_ROLES.get(key, [])
        if required and not any(r in req.identity.roles for r in required):
            score  += RISK_WEIGHTS[RiskFactor.PRIVILEGE_MISMATCH]
            factors.append(RiskFactor.PRIVILEGE_MISMATCH)

        # Clamp final
        final_score = max(0, min(100, int(score)))
        return final_score, list(dict.fromkeys(factors))  # dédupliqués

    # ── Évaluation des politiques ─────────────────────────────────────────────

    def _evaluate_policies(
        self,
        req: ZeroTrustRequest,
        risk_factors: list[RiskFactor],
    ) -> list[PolicyViolation]:
        """Évalue toutes les politiques Zero-Trust applicables."""
        violations: list[PolicyViolation] = []

        for policy in ZERO_TRUST_POLICIES:
            violated = False

            if policy.policy_id == "ZTP-001":
                violated = not self.devices.is_registered(req.device.device_id)

            elif policy.policy_id == "ZTP-002":
                violated = (
                    self.devices.is_registered(req.device.device_id)
                    and not self.devices.is_compliant(req.device.device_id)
                )

            elif policy.policy_id == "ZTP-003":
                violated = (
                    req.resource.sensitivity_level >= 2
                    and not req.identity.mfa_verified
                )

            elif policy.policy_id == "ZTP-004":
                violated = req.identity.session_age_min > 480

            elif policy.policy_id == "ZTP-005":
                violated = req.network.is_tor

            elif policy.policy_id == "ZTP-006":
                violated = req.identity.failed_attempts >= 5

            elif policy.policy_id == "ZTP-007":
                key = (req.resource.action, req.resource.resource_type)
                required = self.REQUIRED_ROLES.get(key, [])
                violated = bool(required) and not any(
                    r in req.identity.roles for r in required
                )

            elif policy.policy_id == "ZTP-008":
                violated = (
                    req.resource.is_bulk
                    and req.resource.sensitivity_level >= 1
                )

            elif policy.policy_id == "ZTP-009":
                violated = req.network.tls_version not in ("TLS1.2", "TLS1.3")

            elif policy.policy_id == "ZTP-010":
                violated = (
                    req.network.country is not None
                    and req.network.country not in self.allowed_countries
                )

            elif policy.policy_id == "ZTP-011":
                violated = (
                    req.identity.is_service_account
                    and not req.network.is_corporate
                    and not any(
                        req.network.ip_address.startswith(p)
                        for p in self.corporate_prefixes
                    )
                )

            elif policy.policy_id == "ZTP-012":
                violated = (
                    req.identity.auth_method == "PASSWORD"
                    and req.resource.sensitivity_level >= 2
                )

            if violated:
                violations.append(PolicyViolation(
                    policy_id    = policy.policy_id,
                    policy_name  = policy.name,
                    severity     = policy.severity,
                    description  = policy.description,
                    remediation  = policy.remediation,
                    risk_factor  = policy.risk_factor,
                ))

        return violations

    # ── Verdict adaptatif ─────────────────────────────────────────────────────

    def _determine_verdict(
        self,
        trust_score: int,
        risk_factors: list[RiskFactor],
        violations: list[PolicyViolation],
        req: ZeroTrustRequest,
    ) -> tuple[Verdict, int]:
        """
        Détermine le verdict en fonction du score et du contexte.
        Retourne (verdict, ttl_seconds).
        """
        sensitivity = req.resource.sensitivity_level
        thresholds  = DECISION_THRESHOLDS[sensitivity]

        # Violations CRITIQUES → toujours DENY ou QUARANTINE
        critical_violations = [v for v in violations if v.severity == "CRITICAL"]
        if RiskFactor.TOR_EXIT_NODE in risk_factors:
            return Verdict.DENY, 0

        if RiskFactor.IMPOSSIBLE_TRAVEL in risk_factors:
            return Verdict.QUARANTINE, 300   # 5 min, lecture seule

        if RiskFactor.FAILED_ATTEMPTS in risk_factors and req.identity.failed_attempts >= 5:
            return Verdict.DENY, 0

        if len(critical_violations) >= 2:
            return Verdict.DENY, 0

        if len(critical_violations) == 1:
            if trust_score < 30:
                return Verdict.DENY, 0
            return Verdict.STEP_UP, 300

        # Décision basée sur le score de confiance
        if trust_score >= thresholds["allow"]:
            ttl = min(3600, max(300, trust_score * 30))  # 5min–60min
            return Verdict.ALLOW, ttl

        if trust_score >= thresholds["challenge_mfa"]:
            return Verdict.CHALLENGE_MFA, 600   # MFA requis, valide 10 min

        if trust_score >= thresholds["step_up"]:
            return Verdict.STEP_UP, 0           # Ré-auth complète

        return Verdict.DENY, 0

    # ── Contraintes de session ────────────────────────────────────────────────

    def _build_session_bindings(
        self,
        req: ZeroTrustRequest,
        verdict: Verdict,
        trust_score: int,
    ) -> dict:
        """Contraintes appliquées à la session si l'accès est accordé."""
        if verdict == Verdict.DENY:
            return {}

        bindings: dict[str, Any] = {
            "bound_to_ip":      req.network.ip_address,
            "bound_to_device":  req.device.device_id,
            "trust_score":      trust_score,
            "re_verify_every":  _reauth_interval(trust_score),  # minutes
            "allowed_actions":  _scoped_actions(verdict, req.resource),
            "read_only":        verdict == Verdict.QUARANTINE,
            "log_all_accesses": trust_score < 70,
            "rate_limit_rps":   _rate_limit(trust_score),
            "data_masking":     req.resource.sensitivity_level >= 2 and trust_score < 80,
        }

        if verdict == Verdict.QUARANTINE:
            bindings["quarantine_reason"] = "impossible_travel"
            bindings["notify_soc"]        = True

        return bindings

    # ── Recommandations ───────────────────────────────────────────────────────

    def _generate_recommendations(
        self,
        violations: list[PolicyViolation],
        risk_factors: list[RiskFactor],
        verdict: Verdict,
    ) -> list[str]:
        recs: list[str] = []
        seen = set()

        for v in violations:
            if v.remediation not in seen:
                recs.append(f"[{v.policy_id}] {v.remediation}")
                seen.add(v.remediation)

        if verdict == Verdict.DENY:
            recs.insert(0, "Accès refusé — journaliser et alerter le SOC si récurrent.")
        elif verdict == Verdict.QUARANTINE:
            recs.insert(0, "Session mise en quarantaine — investigation immédiate requise.")

        if not recs:
            recs.append("Accès accordé. Maintenir la surveillance continue.")

        return recs[:8]  # Max 8 recommandations

    # ── Gestion de session ────────────────────────────────────────────────────

    def _handle_session(
        self, req: ZeroTrustRequest, decision: ZeroTrustDecision
    ) -> None:
        """Crée, met à jour, ou invalide la session selon la décision."""
        sid = req.identity.session_id

        if decision.verdict == Verdict.DENY:
            if sid:
                self.sessions.invalidate(sid)
            return

        if decision.verdict == Verdict.QUARANTINE:
            if sid:
                self.sessions.quarantine(sid, "impossible_travel")
            return

        if decision.verdict in (Verdict.ALLOW, Verdict.CHALLENGE_MFA):
            if sid:
                self.sessions.update_trust(sid, decision.trust_score)
            else:
                s = self.sessions.create(
                    user_id      = req.identity.user_id,
                    device_id    = req.device.device_id,
                    ip           = req.network.ip_address,
                    country      = req.network.country,
                    trust_score  = decision.trust_score,
                    mfa_verified = req.identity.mfa_verified,
                )
                decision.session_bindings["session_id"] = s.session_id

    # ── Utilitaires ───────────────────────────────────────────────────────────

    def _hash_context(self, req: ZeroTrustRequest) -> str:
        payload = json.dumps({
            "user_id":     req.identity.user_id,
            "device_id":   req.device.device_id,
            "ip":          req.network.ip_address,
            "resource_id": req.resource.resource_id,
            "action":      req.resource.action,
            "timestamp":   req.timestamp,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _build_audit_trail(
        self,
        req: ZeroTrustRequest,
        trust_score: int,
        risk_factors: list[RiskFactor],
    ) -> dict:
        return {
            "user_id":       req.identity.user_id,
            "device_id":     req.device.device_id,
            "device_fp":     req.device.fingerprint(),
            "ip_address":    req.network.ip_address,
            "country":       req.network.country,
            "resource":      f"{req.resource.resource_type}:{req.resource.resource_id}",
            "action":        req.resource.action,
            "sensitivity":   req.resource.sensitivity,
            "auth_method":   req.identity.auth_method,
            "mfa_verified":  req.identity.mfa_verified,
            "trust_score":   trust_score,
            "risk_factors":  [r.value for r in risk_factors],
            "tls_version":   req.network.tls_version,
            "evaluated_at":  req.timestamp,
        }

    def _log_decision(
        self,
        decision: ZeroTrustDecision,
        req: ZeroTrustRequest,
        duration_s: float,
    ) -> None:
        entry = {
            **decision.audit_trail,
            "request_id":  decision.request_id,
            "verdict":     decision.verdict.value,
            "decided_at":  decision.decided_at,
            "duration_ms": round(duration_s * 1000, 2),
        }
        self._request_log.append(entry)

        if self._audit_callback:
            try:
                self._audit_callback(entry)
            except Exception:
                pass

    # ── API publique ──────────────────────────────────────────────────────────

    def get_audit_log(self) -> list[dict]:
        """Retourne le journal d'audit complet (immuable)."""
        return list(self._request_log)

    def get_stats(self) -> dict:
        """Statistiques globales du moteur."""
        if not self._request_log:
            return {}
        verdicts: defaultdict[str, int] = defaultdict(int)
        scores = []
        for entry in self._request_log:
            verdicts[entry["verdict"]] += 1
            scores.append(entry.get("trust_score", 0))

        return {
            "total_requests":    len(self._request_log),
            "verdicts":          dict(verdicts),
            "avg_trust_score":   round(sum(scores) / len(scores), 1) if scores else 0,
            "deny_rate_pct":     round(verdicts["DENY"] / len(self._request_log) * 100, 1),
            "challenge_rate_pct":round(
                (verdicts["CHALLENGE_MFA"] + verdicts["STEP_UP"])
                / len(self._request_log) * 100, 1
            ),
            "active_sessions":   len(self.sessions._sessions),
        }

    def print_decision(self, decision: ZeroTrustDecision) -> None:
        """Affiche un résumé lisible de la décision."""
        icons = {
            Verdict.ALLOW:         "✅",
            Verdict.DENY:          "🚫",
            Verdict.CHALLENGE_MFA: "🔐",
            Verdict.STEP_UP:       "⬆️",
            Verdict.QUARANTINE:    "🔒",
        }
        icon = icons.get(decision.verdict, "❓")

        print(f"\n{'─'*60}")
        print(f"  {icon}  DÉCISION ZERO-TRUST : {decision.verdict.value}")
        print(f"{'─'*60}")
        print(f"  Request ID   : {decision.request_id}")
        print(f"  Score        : {decision.trust_score}/100")
        print(f"  TTL          : {decision.ttl_seconds}s")
        print(f"  Context hash : {decision.context_hash[:16]}…")

        if decision.risk_factors:
            print(f"\n  ⚠️  Facteurs de risque ({len(decision.risk_factors)}) :")
            for rf in decision.risk_factors:
                print(f"    · {rf.value}")

        if decision.violations:
            print(f"\n  📋 Violations ({len(decision.violations)}) :")
            for v in decision.violations:
                sev_icon = {"CRITICAL": "🔴", "ERROR": "🟠", "WARNING": "🟡"}.get(v.severity, "⚪")
                print(f"    {sev_icon} [{v.policy_id}] {v.policy_name}")

        if decision.session_bindings:
            print(f"\n  🔗 Contraintes de session :")
            for k, v in decision.session_bindings.items():
                print(f"    {k}: {v}")

        print(f"\n  📌 Recommandations :")
        for rec in decision.recommendations[:3]:
            print(f"    → {rec}")
        print(f"{'─'*60}\n")

    def generate_demo_requests(self, n: int = 20) -> list[ZeroTrustRequest]:
        """
        Génère des requêtes Zero-Trust de démonstration variées.
        Couvre les différents scenarios (accès légitime, attaques, anomalies…).
        """
        from faker import Faker
        fake = Faker("fr_FR")

        resource_types = ["API_KEY", "DOCUMENT", "USER_ACCOUNT", "CONFIG", "EXPORT"]
        actions        = ["READ", "WRITE", "DELETE", "EXPORT"]
        sensitivities  = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"]
        os_types       = ["WINDOWS", "MACOS", "LINUX", "MOBILE"]
        auth_methods   = ["PASSWORD", "MFA_TOTP", "MFA_FIDO2", "SSO"]
        countries      = ["FR", "DE", "CN", "RU", "US", "BE", "TR"]
        roles_pool     = ["analyst", "developer", "manager", "admin", "hr", "sre"]

        requests = []
        for i in range(n):
            # Scénario déterminé aléatoirement
            scenario = random.choices(
                ["normal", "risky", "attack", "anomaly"],
                weights=[0.50, 0.25, 0.15, 0.10]
            )[0]

            is_tor      = scenario == "attack" and random.random() > 0.5
            is_managed  = scenario == "normal" or random.random() > 0.4
            mfa_ok      = scenario != "attack" and random.random() > 0.3
            failed_att  = 6 if scenario == "attack" else random.randint(0, 2)
            country     = "FR" if scenario == "normal" else random.choice(countries)
            sensitivity = random.choice(sensitivities)
            action      = random.choice(actions)
            rtype       = random.choice(resource_types)

            # Heure (scénarios nocturnes pour anomalies)
            if scenario == "anomaly":
                hour = random.choice([1, 2, 3, 4, 23])
            else:
                hour = random.randint(8, 18)
            ts = datetime.now(timezone.utc).replace(hour=hour).isoformat()

            req = ZeroTrustRequest(
                timestamp = ts,
                identity  = IdentityContext(
                    user_id          = f"usr_{i:04d}",
                    roles            = random.sample(roles_pool, k=random.randint(1, 3)),
                    auth_method      = random.choice(auth_methods),
                    mfa_verified     = mfa_ok,
                    session_age_min  = random.uniform(0, 600),
                    failed_attempts  = failed_att,
                    risk_score       = round(random.betavariate(1, 5), 2),
                    last_login_ip    = fake.ipv4_public(),
                    is_service_account = random.random() < 0.05,
                ),
                device    = DeviceContext(
                    device_id   = f"DEV-{random.randint(0, 19):04d}",
                    is_managed  = is_managed,
                    is_compliant= is_managed and random.random() > 0.1,
                    os_type     = random.choice(os_types),
                    certificate = f"cert_{uuid.uuid4().hex[:8]}" if is_managed else None,
                    trust_score = round(random.betavariate(5, 2) if is_managed else random.betavariate(1, 3), 2),
                ),
                network   = NetworkContext(
                    ip_address  = fake.ipv4_public(),
                    is_tor      = is_tor,
                    is_vpn      = not is_tor and random.random() < 0.1,
                    is_corporate= scenario == "normal" and random.random() > 0.3,
                    country     = country,
                    user_agent  = fake.user_agent(),
                    tls_version = random.choices(["TLS1.3","TLS1.2","TLS1.0"], weights=[0.7,0.25,0.05])[0],
                ),
                resource  = ResourceRequest(
                    resource_id   = str(uuid.uuid4())[:8],
                    resource_type = rtype,
                    sensitivity   = sensitivity,
                    action        = action,
                    is_bulk       = random.random() < 0.1,
                ),
            )
            requests.append(req)

        return requests


# ══════════════════════════════════════════════════════════════════════════════
# UTILITAIRES PRIVÉS
# ══════════════════════════════════════════════════════════════════════════════

def _reauth_interval(trust_score: int) -> int:
    """Intervalle de re-vérification en minutes selon le score de confiance."""
    if trust_score >= 85: return 60
    if trust_score >= 70: return 30
    if trust_score >= 55: return 15
    return 5

def _rate_limit(trust_score: int) -> int:
    """Limite de débit en req/s selon le score de confiance."""
    if trust_score >= 80: return 100
    if trust_score >= 60: return 50
    if trust_score >= 40: return 20
    return 5

def _scoped_actions(verdict: Verdict, resource: ResourceRequest) -> list[str]:
    """Actions autorisées selon le verdict et la sensibilité de la ressource."""
    if verdict == Verdict.QUARANTINE:
        return ["READ"]
    if verdict == Verdict.CHALLENGE_MFA:
        return ["READ"]
    # ALLOW : actions complètes (mais pas d'admin sans role explicite)
    base = ["READ"]
    if resource.sensitivity_level <= 1:
        base += ["WRITE"]
    if resource.sensitivity_level == 0:
        base += ["DELETE", "EXPORT"]
    return base


# ══════════════════════════════════════════════════════════════════════════════
# INTÉGRATION SPIDERCRYPT — Connecteur pour InvestigationEngine
# ══════════════════════════════════════════════════════════════════════════════

def build_audit_event_from_decision(decision: ZeroTrustDecision) -> dict:
    """
    Convertit une décision Zero-Trust en événement d'audit compatible
    avec spidercrypt_investigation.InvestigationEngine.
    """
    trail    = decision.audit_trail
    severity = "INFO"
    if decision.verdict == Verdict.DENY:          severity = "CRITICAL"
    elif decision.verdict == Verdict.QUARANTINE:  severity = "CRITICAL"
    elif decision.verdict == Verdict.STEP_UP:     severity = "ERROR"
    elif decision.verdict == Verdict.CHALLENGE_MFA: severity = "WARNING"

    return {
        "event_id":       decision.request_id,
        "timestamp_ms":   int(datetime.now(timezone.utc).timestamp() * 1000),
        "timestamp_iso":  decision.decided_at,
        "acteur_id":      trail.get("user_id", ""),
        "acteur_type":    "SERVICE_ACCOUNT" if trail.get("is_service_account") else "USER",
        "action":         trail.get("action", "UNKNOWN"),
        "resource_type":  trail.get("resource", "").split(":")[0],
        "resource_id":    trail.get("resource", "").split(":")[-1],
        "succes":         decision.verdict == Verdict.ALLOW,
        "severite":       severity,
        "ip_address":     trail.get("ip_address", ""),
        "user_agent":     "",
        "duree_ms":       0,
        "message":        f"ZeroTrust:{decision.verdict.value} trust={decision.trust_score}",
        "session_id":     decision.session_bindings.get("session_id", ""),
        "_synthetic":     True,
        # Champs Zero-Trust additionnels
        "zt_trust_score": decision.trust_score,
        "zt_verdict":     decision.verdict.value,
        "zt_risk_count":  len(decision.risk_factors),
        "zt_context_hash": decision.context_hash,
    }


# ══════════════════════════════════════════════════════════════════════════════
# DÉMO CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    print("🕷️  Spidercrypt — Démo Zero-Trust Engine\n")

    # 1. Initialiser le moteur et enregistrer une flotte d'appareils
    engine = ZeroTrustEngine()
    fleet  = engine.devices.generate_demo_fleet(n=20)
    print(f"  📱 Flotte : {len(fleet)} appareils enregistrés\n")

    # 2. Générer et évaluer des requêtes de démonstration
    requests = engine.generate_demo_requests(n=30)
    decisions = []
    for req in requests:
        dec = engine.evaluate(req)
        decisions.append(dec)

    # 3. Afficher quelques décisions intéressantes
    interesting = [
        d for d in decisions
        if d.verdict != Verdict.ALLOW or d.trust_score < 60
    ][:5]

    print(f"\n🔍 Décisions intéressantes ({len(interesting)}) :")
    for d in interesting:
        engine.print_decision(d)

    # 4. Statistiques globales
    stats = engine.get_stats()
    print("📊 Statistiques Zero-Trust :")
    for k, v in stats.items():
        print(f"   {k}: {v}")

    # 5. Export du journal d'audit (compatible InvestigationEngine)
    log      = engine.get_audit_log()
    log_path = Path("/tmp/spidercrypt_zt_audit.json")
    log_path.write_text(
        json.dumps(log, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\n  💾 Journal d'audit → {log_path}  ({len(log)} entrées)")

    # 6. Démo d'un scénario d'attaque explicite
    print("\n🎯 Scénario : Tentative d'accès via Tor + compte verrouillé")
    attack = ZeroTrustRequest(
        identity = IdentityContext(
            user_id         = "usr_hacker",
            roles           = ["analyst"],
            auth_method     = "PASSWORD",
            mfa_verified    = False,
            failed_attempts = 7,
        ),
        device   = DeviceContext(device_id="UNKNOWN-DEVICE"),
        network  = NetworkContext(
            ip_address = "185.220.101.45",
            is_tor     = True,
            country    = "RU",
        ),
        resource = ResourceRequest(
            resource_id   = "secret-keys-vault",
            resource_type = "API_KEY",
            sensitivity   = "SECRET",
            action        = "EXPORT",
        ),
    )
    dec = engine.evaluate(attack)
    engine.print_decision(dec)

    print("✅ Démo Zero-Trust terminée.")