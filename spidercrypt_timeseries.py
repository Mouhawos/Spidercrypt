"""
╔══════════════════════════════════════════════════════════════════════════════╗
║     🕷️  SPIDERCRYPT ENTERPRISE — Moteur Séries Temporelles Cybersécurité    ║
║  Détection · Prévision · Corrélation · Conformité RGPD · Rapport Forensic  ║
╚══════════════════════════════════════════════════════════════════════════════╝

Dépendances :
    pip install pandas numpy pyarrow pynacl

Usage :
    from spidercrypt_timeseries import TimeSeriesEngine
    engine = TimeSeriesEngine()
    engine.ingest(stream)
    report = engine.analyze(entity_id="usr_0042", window_hours=24)
    engine.save_report(report, "rapports/ts_analysis.json")
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import statistics
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

class SignalType(str, Enum):
    NET_CONNECTIONS   = "net_connections"
    FAILED_LOGINS     = "failed_logins"
    LOG_VOLUME        = "log_volume"
    BYTES_OUT         = "bytes_out"
    BYTES_IN          = "bytes_in"
    DNS_QUERIES       = "dns_queries"
    PROCESS_SPAWNS    = "process_spawns"
    FILE_OPS          = "file_ops"
    API_CALLS         = "api_calls"
    PRIVILEGE_EVENTS  = "privilege_events"
    LATERAL_MOVEMENT  = "lateral_movement"
    CRYPTO_OPS        = "crypto_ops"
    USER_ACTIVITY     = "user_activity"

class AnomalyType(str, Enum):
    SPIKE             = "spike"
    DIP               = "dip"
    DRIFT             = "drift"
    PERIODICITY       = "periodicity"
    LEVEL_SHIFT       = "level_shift"
    POINT_ANOMALY     = "point_anomaly"
    CONTEXTUAL        = "contextual"
    COLLECTIVE        = "collective"

class ThreatCategory(str, Enum):
    BRUTE_FORCE          = "brute_force"
    DATA_EXFILTRATION    = "data_exfiltration"
    C2_BEACONING         = "c2_beaconing"
    INSIDER_THREAT       = "insider_threat"
    RANSOMWARE           = "ransomware"
    LATERAL_MOVEMENT     = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DDoS                 = "ddos"
    RECONNAISSANCE       = "reconnaissance"
    LOG_TAMPERING        = "log_tampering"
    UNKNOWN              = "unknown"

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

class DetectionMethod(str, Enum):
    ZSCORE          = "zscore"
    MAD             = "mad"
    EWMA            = "ewma"
    STL_RESIDUAL    = "stl_residual"
    AUTOCORRELATION = "autocorrelation"
    THRESHOLD       = "threshold"
    CHANGEPOINT     = "changepoint"

ZSCORE_THRESHOLDS: dict[SignalType, float] = {
    SignalType.NET_CONNECTIONS:  3.5,
    SignalType.FAILED_LOGINS:    2.5,
    SignalType.LOG_VOLUME:       4.0,
    SignalType.BYTES_OUT:        3.0,
    SignalType.BYTES_IN:         3.5,
    SignalType.DNS_QUERIES:      3.0,
    SignalType.PROCESS_SPAWNS:   2.5,
    SignalType.FILE_OPS:         3.0,
    SignalType.API_CALLS:        3.5,
    SignalType.PRIVILEGE_EVENTS: 2.0,
    SignalType.LATERAL_MOVEMENT: 2.0,
    SignalType.CRYPTO_OPS:       2.0,
    SignalType.USER_ACTIVITY:    3.0,
}

SIGNAL_THREAT_MAP: dict[SignalType, list[ThreatCategory]] = {
    SignalType.NET_CONNECTIONS:   [ThreatCategory.DDoS, ThreatCategory.RECONNAISSANCE],
    SignalType.FAILED_LOGINS:     [ThreatCategory.BRUTE_FORCE],
    SignalType.LOG_VOLUME:        [ThreatCategory.LOG_TAMPERING],
    SignalType.BYTES_OUT:         [ThreatCategory.DATA_EXFILTRATION, ThreatCategory.C2_BEACONING],
    SignalType.DNS_QUERIES:       [ThreatCategory.C2_BEACONING, ThreatCategory.DATA_EXFILTRATION],
    SignalType.PROCESS_SPAWNS:    [ThreatCategory.RANSOMWARE, ThreatCategory.LATERAL_MOVEMENT],
    SignalType.FILE_OPS:          [ThreatCategory.RANSOMWARE, ThreatCategory.DATA_EXFILTRATION],
    SignalType.PRIVILEGE_EVENTS:  [ThreatCategory.PRIVILEGE_ESCALATION, ThreatCategory.INSIDER_THREAT],
    SignalType.LATERAL_MOVEMENT:  [ThreatCategory.LATERAL_MOVEMENT],
    SignalType.CRYPTO_OPS:        [ThreatCategory.RANSOMWARE],
    SignalType.USER_ACTIVITY:     [ThreatCategory.INSIDER_THREAT],
    SignalType.API_CALLS:         [ThreatCategory.DATA_EXFILTRATION, ThreatCategory.RECONNAISSANCE],
    SignalType.BYTES_IN:          [ThreatCategory.DDoS],
}

BUSINESS_HOURS     = (7, 20)
DEFAULT_BASELINE_WINDOW = 100


# ══════════════════════════════════════════════════════════════════════════════
# MODÈLES DE DONNÉES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DataPoint:
    timestamp_ms: int
    value:        float
    tags:         dict[str, str] = field(default_factory=dict)

    @property
    def timestamp_iso(self) -> str:
        return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc).isoformat()

    @property
    def hour(self) -> int:
        return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc).hour

    @property
    def is_business_hours(self) -> bool:
        return BUSINESS_HOURS[0] <= self.hour < BUSINESS_HOURS[1]

    def to_dict(self) -> dict:
        return {
            "timestamp_ms":  self.timestamp_ms,
            "timestamp_iso": self.timestamp_iso,
            "value":         self.value,
            "tags":          self.tags,
        }


@dataclass
class SignalStream:
    stream_id:   str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_id:   str = ""
    entity_type: str = "USER"
    signal_type: SignalType = SignalType.NET_CONNECTIONS
    unit:        str = "count/s"
    resolution:  int = 60
    points:      list[DataPoint] = field(default_factory=list)
    created_at:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __len__(self) -> int:
        return len(self.points)

    def values(self) -> list[float]:
        return [p.value for p in self.points]

    def timestamps(self) -> list[int]:
        return [p.timestamp_ms for p in self.points]

    def window(self, from_ms: int, to_ms: int) -> "SignalStream":
        filtered = [p for p in self.points if from_ms <= p.timestamp_ms <= to_ms]
        return SignalStream(
            stream_id   = self.stream_id,
            entity_id   = self.entity_id,
            entity_type = self.entity_type,
            signal_type = self.signal_type,
            unit        = self.unit,
            resolution  = self.resolution,
            points      = filtered,
        )

    def append(self, point: DataPoint) -> None:
        self.points.append(point)

    def tail(self, n: int) -> list[DataPoint]:
        return self.points[-n:]


@dataclass
class BaselineProfile:
    entity_id:    str
    signal_type:  SignalType
    computed_at:  str
    n_points:     int
    mean:         float
    std:          float
    median:       float
    mad:          float
    p5:           float
    p25:          float
    p75:          float
    p95:          float
    p99:          float
    hourly_means: dict[int, float] = field(default_factory=dict)
    is_periodic:  bool = False
    period_ms:    int  = 0

    def zscore(self, value: float) -> float:
        if self.std == 0:
            return 0.0
        return (value - self.mean) / self.std

    def mad_score(self, value: float) -> float:
        if self.mad == 0:
            return 0.0
        return abs(value - self.median) / (1.4826 * self.mad)

    def contextual_mean(self, hour: int) -> float:
        return self.hourly_means.get(hour, self.mean)

    def contextual_zscore(self, value: float, hour: int) -> float:
        expected = self.contextual_mean(hour)
        if self.std == 0:
            return 0.0
        return (value - expected) / self.std


@dataclass
class AnomalyAlert:
    alert_id:         str
    detected_at:      str
    entity_id:        str
    signal_type:      SignalType
    anomaly_type:     AnomalyType
    severity:         Severity
    threat_category:  ThreatCategory
    detection_method: DetectionMethod
    score:            float
    threshold:        float
    observed_value:   float
    expected_value:   float
    deviation_pct:    float
    window_start:     str
    window_end:       str
    n_points:         int
    context:          dict = field(default_factory=dict)
    is_business_hours: bool = True
    correlated_alerts: list[str] = field(default_factory=list)
    mitre_technique:  str = ""
    recommended_action: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["signal_type"]      = self.signal_type.value
        d["anomaly_type"]     = self.anomaly_type.value
        d["severity"]         = self.severity.value
        d["threat_category"]  = self.threat_category.value
        d["detection_method"] = self.detection_method.value
        return d

    def summary(self) -> str:
        icon = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH:     "🟠",
            Severity.MEDIUM:   "🟡",
            Severity.LOW:      "🟢",
            Severity.INFO:     "⚪",
        }.get(self.severity, "❓")
        return (
            f"{icon} [{self.severity.value}] {self.anomaly_type.value} "
            f"sur {self.signal_type.value} | score={self.score:.2f} "
            f"| {self.threat_category.value}"
        )


@dataclass
class CorrelationResult:
    correlation_id:   str
    computed_at:      str
    entity_id:        str
    signals_analyzed: list[str]
    combined_score:   float
    threat_category:  ThreatCategory
    confidence:       float
    alert_ids:        list[str]
    narrative:        str
    mitre_chain:      list[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["threat_category"] = self.threat_category.value
        return d


@dataclass
class TimeSeriesReport:
    report_id:           str
    generated_at:        str
    analyst:             str
    entity:              dict
    window:              dict
    streams_analyzed:    int
    total_points:        int
    baselines:           dict
    alerts:              list[dict]
    correlations:        list[dict]
    risk_score:          float
    risk_level:          str
    forecasts:           dict
    recommendations:     list[str]
    mitre_coverage:      list[str]
    signature_hash:      str | None
    rgpd_retention_days: int = 1095

    def to_dict(self) -> dict:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════════════
# CATALOGUE MITRE ATT&CK
# ══════════════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUES: dict[ThreatCategory, list[str]] = {
    ThreatCategory.BRUTE_FORCE:          ["T1110 - Brute Force", "T1110.001 - Password Guessing"],
    ThreatCategory.DATA_EXFILTRATION:    ["T1041 - Exfiltration Over C2", "T1048 - Exfiltration Over Alternative Protocol"],
    ThreatCategory.C2_BEACONING:         ["T1071 - Application Layer Protocol", "T1132 - Data Encoding"],
    ThreatCategory.INSIDER_THREAT:       ["T1078 - Valid Accounts", "T1213 - Data from Information Repositories"],
    ThreatCategory.RANSOMWARE:           ["T1486 - Data Encrypted for Impact", "T1490 - Inhibit System Recovery"],
    ThreatCategory.LATERAL_MOVEMENT:     ["T1021 - Remote Services", "T1075 - Pass the Hash"],
    ThreatCategory.PRIVILEGE_ESCALATION: ["T1068 - Exploitation for Privilege Escalation", "T1134 - Access Token Manipulation"],
    ThreatCategory.DDoS:                 ["T1498 - Network Denial of Service", "T1499 - Endpoint Denial of Service"],
    ThreatCategory.RECONNAISSANCE:       ["T1046 - Network Service Discovery", "T1595 - Active Scanning"],
    ThreatCategory.LOG_TAMPERING:        ["T1070 - Indicator Removal", "T1070.001 - Clear Windows Event Logs"],
    ThreatCategory.UNKNOWN:              [],
}

RECOMMENDED_ACTIONS: dict[ThreatCategory, str] = {
    ThreatCategory.BRUTE_FORCE:          "Bloquer le compte après 5 tentatives. Activer MFA. Alerter le SOC.",
    ThreatCategory.DATA_EXFILTRATION:    "Bloquer les flux sortants suspects. Isoler l'hôte. Notifier le DPO (RGPD Art.33).",
    ThreatCategory.C2_BEACONING:         "Bloquer les domaines/IPs de destination. Analyser le processus source. Forensique réseau.",
    ThreatCategory.INSIDER_THREAT:       "Surveillance renforcée. Révocation temporaire des accès. Enquête RH+RSSI.",
    ThreatCategory.RANSOMWARE:           "ISOLATION IMMÉDIATE de l'hôte. Snapshot des volumes. Activer le PCA.",
    ThreatCategory.LATERAL_MOVEMENT:     "Segmenter le réseau. Changer les credentials. Audit des comptes partagés.",
    ThreatCategory.PRIVILEGE_ESCALATION: "Révoquer les droits élevés. Auditer les groupes. Contacter le DSI.",
    ThreatCategory.DDoS:                 "Activer la mitigation DDoS. Contacter l'opérateur réseau. Basculer en mode dégradé.",
    ThreatCategory.RECONNAISSANCE:       "Analyser les logs de scan. Mettre à jour les règles firewall. Alerter le SOC.",
    ThreatCategory.LOG_TAMPERING:        "CRITIQUE — Préserver les preuves. Activer la journalisation de secours. Alerter RSSI.",
    ThreatCategory.UNKNOWN:              "Analyse manuelle requise. Conserver les artefacts pour investigation.",
}


# ══════════════════════════════════════════════════════════════════════════════
# PROCESSEUR DE SÉRIES TEMPORELLES
# ══════════════════════════════════════════════════════════════════════════════

class TimeSeriesProcessor:

    @staticmethod
    def compute_baseline(stream: SignalStream, window: int = DEFAULT_BASELINE_WINDOW) -> BaselineProfile:
        pts  = stream.tail(window) if len(stream) >= window else stream.points
        vals = [p.value for p in pts]

        if not vals:
            return BaselineProfile(
                entity_id=stream.entity_id, signal_type=stream.signal_type,
                computed_at=datetime.now(timezone.utc).isoformat(), n_points=0,
                mean=0, std=0, median=0, mad=0,
                p5=0, p25=0, p75=0, p95=0, p99=0,
            )

        vals_sorted = sorted(vals)
        n = len(vals_sorted)
        mean   = statistics.mean(vals)
        std    = statistics.pstdev(vals) if n > 1 else 0.0
        median = statistics.median(vals)
        mad    = statistics.median([abs(v - median) for v in vals])

        def pct(p: float) -> float:
            idx = (p / 100) * (n - 1)
            lo, hi = int(idx), min(int(idx) + 1, n - 1)
            return vals_sorted[lo] + (idx - lo) * (vals_sorted[hi] - vals_sorted[lo])

        hourly: dict[int, list[float]] = defaultdict(list)
        for pt in pts:
            hourly[pt.hour].append(pt.value)
        hourly_means = {h: statistics.mean(v) for h, v in hourly.items()}

        is_periodic, period_ms = TimeSeriesProcessor._detect_periodicity(stream)

        return BaselineProfile(
            entity_id    = stream.entity_id,
            signal_type  = stream.signal_type,
            computed_at  = datetime.now(timezone.utc).isoformat(),
            n_points     = n,
            mean         = round(mean, 4),
            std          = round(std, 4),
            median       = round(median, 4),
            mad          = round(mad, 4),
            p5           = round(pct(5), 4),
            p25          = round(pct(25), 4),
            p75          = round(pct(75), 4),
            p95          = round(pct(95), 4),
            p99          = round(pct(99), 4),
            hourly_means = {h: round(m, 4) for h, m in hourly_means.items()},
            is_periodic  = is_periodic,
            period_ms    = period_ms,
        )

    @staticmethod
    def _detect_periodicity(stream: SignalStream, max_lag: int = 50) -> tuple[bool, int]:
        vals = stream.values()
        if len(vals) < max_lag * 2:
            return False, 0

        mean = statistics.mean(vals)
        centered = [v - mean for v in vals]
        var = sum(c * c for c in centered) / len(centered)
        if var == 0:
            return False, 0

        autocorr: list[tuple[int, float]] = []
        n = len(centered)
        for lag in range(1, min(max_lag, n // 2)):
            cov = sum(centered[i] * centered[i + lag] for i in range(n - lag)) / (n - lag)
            ac  = cov / var
            autocorr.append((lag, ac))

        peaks = [(lag, ac) for lag, ac in autocorr if ac > 0.6]
        if not peaks:
            return False, 0

        dominant_lag, _ = max(peaks, key=lambda x: x[1])
        period_ms = dominant_lag * stream.resolution * 1000
        return True, period_ms

    @staticmethod
    def ewma(values: list[float], alpha: float = 0.3) -> list[float]:
        if not values:
            return []
        result = [values[0]]
        for v in values[1:]:
            result.append(alpha * v + (1 - alpha) * result[-1])
        return result

    @staticmethod
    def detect_changepoints(values: list[float], penalty: float = 3.0) -> list[int]:
        n = len(values)
        if n < 10:
            return []

        changepoints: list[int] = []
        window = max(5, n // 10)

        for i in range(window, n - window):
            left  = values[max(0, i - window):i]
            right = values[i:min(n, i + window)]
            if not left or not right:
                continue
            mu_l = statistics.mean(left)
            mu_r = statistics.mean(right)
            std_l = statistics.pstdev(left) if len(left) > 1 else 1.0
            std_r = statistics.pstdev(right) if len(right) > 1 else 1.0
            pooled_std = max((std_l + std_r) / 2, 1e-6)
            t_stat = abs(mu_r - mu_l) / pooled_std
            if t_stat > penalty:
                if not changepoints or i - changepoints[-1] > window:
                    changepoints.append(i)

        return changepoints

    @staticmethod
    def simple_forecast(values: list[float], horizon: int = 12) -> dict:
        if len(values) < 3:
            last = values[-1] if values else 0
            return {
                "forecast": [last] * horizon,
                "lower_95": [max(0, last * 0.8)] * horizon,
                "upper_95": [last * 1.2] * horizon,
                "method":   "naive",
            }

        smoothed  = TimeSeriesProcessor.ewma(values, alpha=0.3)
        last      = smoothed[-1]
        residuals = [v - s for v, s in zip(values, smoothed)]
        std_res   = statistics.pstdev(residuals) if len(residuals) > 1 else 0

        recent = smoothed[-10:]
        trend  = (recent[-1] - recent[0]) / len(recent) if len(recent) >= 2 else 0

        forecast = [max(0, last + trend * i) for i in range(1, horizon + 1)]
        ci_width = 1.96 * std_res
        lower_95 = [max(0, f - ci_width) for f in forecast]
        upper_95 = [f + ci_width for f in forecast]

        return {
            "forecast":       [round(f, 3) for f in forecast],
            "lower_95":       [round(l, 3) for l in lower_95],
            "upper_95":       [round(u, 3) for u in upper_95],
            "trend_per_step": round(trend, 4),
            "method":         "ewma",
        }


# ══════════════════════════════════════════════════════════════════════════════
# DÉTECTEUR D'ANOMALIES
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:

    def __init__(self, sensitivity: float = 1.0):
        self.sensitivity = sensitivity

    def detect_all(self, stream: SignalStream, baseline: BaselineProfile) -> list[AnomalyAlert]:
        alerts: list[AnomalyAlert] = []
        alerts += self._detect_zscore(stream, baseline)
        alerts += self._detect_mad(stream, baseline)
        alerts += self._detect_contextual(stream, baseline)
        alerts += self._detect_beaconing(stream, baseline)
        alerts += self._detect_changepoints(stream, baseline)
        alerts += self._detect_silence(stream, baseline)
        return self._deduplicate(alerts)

    def _detect_zscore(self, stream: SignalStream, baseline: BaselineProfile) -> list[AnomalyAlert]:
        alerts: list[AnomalyAlert] = []
        threshold = ZSCORE_THRESHOLDS.get(stream.signal_type, 3.0) / self.sensitivity
        for pt in stream.points:
            z = baseline.zscore(pt.value)
            if abs(z) > threshold:
                atype = AnomalyType.SPIKE if z > 0 else AnomalyType.DIP
                alerts.append(self._make_alert(
                    stream, pt, atype,
                    method=DetectionMethod.ZSCORE,
                    score=abs(z),
                    threshold=threshold,
                    expected=baseline.mean,
                ))
        return alerts

    def _detect_mad(self, stream: SignalStream, baseline: BaselineProfile) -> list[AnomalyAlert]:
        alerts: list[AnomalyAlert] = []
        threshold = ZSCORE_THRESHOLDS.get(stream.signal_type, 3.0) / self.sensitivity
        for pt in stream.points:
            mad_score = baseline.mad_score(pt.value)
            if mad_score > threshold:
                atype = AnomalyType.SPIKE if pt.value > baseline.median else AnomalyType.DIP
                alerts.append(self._make_alert(
                    stream, pt, atype,
                    method=DetectionMethod.MAD,
                    score=mad_score,
                    threshold=threshold,
                    expected=baseline.median,
                ))
        return alerts

    def _detect_contextual(self, stream: SignalStream, baseline: BaselineProfile) -> list[AnomalyAlert]:
        alerts: list[AnomalyAlert] = []
        if not baseline.hourly_means:
            return []
        threshold = 2.5 / self.sensitivity
        for pt in stream.points:
            ctx_z    = baseline.contextual_zscore(pt.value, pt.hour)
            global_z = baseline.zscore(pt.value)
            if abs(ctx_z) > threshold and abs(global_z) <= threshold:
                alerts.append(self._make_alert(
                    stream, pt, AnomalyType.CONTEXTUAL,
                    method=DetectionMethod.ZSCORE,
                    score=abs(ctx_z),
                    threshold=threshold,
                    expected=baseline.contextual_mean(pt.hour),
                    extra_context={
                        "hour":             pt.hour,
                        "is_business":      pt.is_business_hours,
                        "hourly_expected":  baseline.contextual_mean(pt.hour),
                    },
                ))
        return alerts

    def _detect_beaconing(self, stream: SignalStream, baseline: BaselineProfile) -> list[AnomalyAlert]:
        if stream.signal_type not in (SignalType.BYTES_OUT, SignalType.DNS_QUERIES,
                                       SignalType.NET_CONNECTIONS):
            return []
        if not baseline.is_periodic or baseline.period_ms == 0:
            return []
        period_min = baseline.period_ms / 60000
        if not (0.5 <= period_min <= 60):
            return []
        alerts: list[AnomalyAlert] = []
        if stream.points:
            pt = stream.points[-1]
            alerts.append(AnomalyAlert(
                alert_id           = str(uuid.uuid4()),
                detected_at        = datetime.now(timezone.utc).isoformat(),
                entity_id          = stream.entity_id,
                signal_type        = stream.signal_type,
                anomaly_type       = AnomalyType.PERIODICITY,
                severity           = Severity.HIGH,
                threat_category    = ThreatCategory.C2_BEACONING,
                detection_method   = DetectionMethod.AUTOCORRELATION,
                score              = 0.85,
                threshold          = 0.6,
                observed_value     = statistics.mean(stream.values()[-10:]) if len(stream) >= 10 else 0,
                expected_value     = baseline.mean,
                deviation_pct      = 0.0,
                window_start       = stream.points[0].timestamp_iso if stream.points else "",
                window_end         = pt.timestamp_iso,
                n_points           = len(stream),
                context            = {"period_minutes": round(period_min, 2), "period_ms": baseline.period_ms},
                is_business_hours  = pt.is_business_hours,
                mitre_technique    = "T1071 - Application Layer Protocol",
                recommended_action = RECOMMENDED_ACTIONS[ThreatCategory.C2_BEACONING],
            ))
        return alerts

    def _detect_changepoints(self, stream: SignalStream, baseline: BaselineProfile) -> list[AnomalyAlert]:
        vals = stream.values()
        cps  = TimeSeriesProcessor.detect_changepoints(vals, penalty=3.0 / self.sensitivity)
        alerts: list[AnomalyAlert] = []
        for cp_idx in cps:
            pt          = stream.points[cp_idx]
            before_mean = statistics.mean(vals[max(0, cp_idx - 10):cp_idx]) if cp_idx > 0 else baseline.mean
            after_mean  = statistics.mean(vals[cp_idx:min(len(vals), cp_idx + 10)])
            shift_ratio = (after_mean - before_mean) / max(abs(before_mean), 1e-6)
            severity    = (
                Severity.CRITICAL if abs(shift_ratio) > 2.0
                else Severity.HIGH if abs(shift_ratio) > 1.0
                else Severity.MEDIUM
            )
            threat = self._infer_threat(stream.signal_type, shift_ratio)
            alerts.append(AnomalyAlert(
                alert_id           = str(uuid.uuid4()),
                detected_at        = datetime.now(timezone.utc).isoformat(),
                entity_id          = stream.entity_id,
                signal_type        = stream.signal_type,
                anomaly_type       = AnomalyType.LEVEL_SHIFT,
                severity           = severity,
                threat_category    = threat,
                detection_method   = DetectionMethod.CHANGEPOINT,
                score              = abs(shift_ratio),
                threshold          = 3.0,
                observed_value     = round(after_mean, 4),
                expected_value     = round(before_mean, 4),
                deviation_pct      = round(shift_ratio * 100, 1),
                window_start       = pt.timestamp_iso,
                window_end         = stream.points[-1].timestamp_iso if stream.points else "",
                n_points           = len(vals) - cp_idx,
                context            = {"changepoint_index": cp_idx, "shift_ratio": round(shift_ratio, 4)},
                is_business_hours  = pt.is_business_hours,
                mitre_technique    = MITRE_TECHNIQUES.get(threat, [""])[0],
                recommended_action = RECOMMENDED_ACTIONS.get(threat, ""),
            ))
        return alerts

    def _detect_silence(self, stream: SignalStream, baseline: BaselineProfile) -> list[AnomalyAlert]:
        if stream.signal_type != SignalType.LOG_VOLUME:
            return []
        if baseline.mean == 0:
            return []
        alerts: list[AnomalyAlert] = []
        silence_threshold = baseline.mean * 0.1
        silence_run: list[DataPoint] = []

        def _make_silence_alert(run: list[DataPoint]) -> AnomalyAlert:
            first = run[0]
            return AnomalyAlert(
                alert_id           = str(uuid.uuid4()),
                detected_at        = datetime.now(timezone.utc).isoformat(),
                entity_id          = stream.entity_id,
                signal_type        = stream.signal_type,
                anomaly_type       = AnomalyType.COLLECTIVE,
                severity           = Severity.CRITICAL,
                threat_category    = ThreatCategory.LOG_TAMPERING,
                detection_method   = DetectionMethod.THRESHOLD,
                score              = len(run) * 0.2,
                threshold          = silence_threshold,
                observed_value     = round(statistics.mean(p.value for p in run), 4),
                expected_value     = round(baseline.mean, 4),
                deviation_pct      = -90.0,
                window_start       = first.timestamp_iso,
                window_end         = run[-1].timestamp_iso,
                n_points           = len(run),
                context            = {"silence_duration_points": len(run)},
                is_business_hours  = first.is_business_hours,
                mitre_technique    = "T1070 - Indicator Removal",
                recommended_action = RECOMMENDED_ACTIONS[ThreatCategory.LOG_TAMPERING],
            )

        for pt in stream.points:
            if pt.value < silence_threshold:
                silence_run.append(pt)
            else:
                if len(silence_run) >= 3:
                    alerts.append(_make_silence_alert(silence_run))
                silence_run = []

        if len(silence_run) >= 3:
            alert = _make_silence_alert(silence_run)
            alert.context["still_ongoing"] = True
            alerts.append(alert)

        return alerts

    def _make_alert(
        self,
        stream: SignalStream,
        pt: DataPoint,
        atype: AnomalyType,
        method: DetectionMethod,
        score: float,
        threshold: float,
        expected: float,
        extra_context: dict | None = None,
    ) -> AnomalyAlert:
        threats   = SIGNAL_THREAT_MAP.get(stream.signal_type, [ThreatCategory.UNKNOWN])
        threat    = threats[0]
        deviation = ((pt.value - expected) / max(abs(expected), 1e-6)) * 100
        severity  = (
            Severity.CRITICAL if score > threshold * 2.5
            else Severity.HIGH if score > threshold * 1.8
            else Severity.MEDIUM if score > threshold * 1.2
            else Severity.LOW
        )
        mitre = MITRE_TECHNIQUES.get(threat, [""])[0]
        return AnomalyAlert(
            alert_id           = str(uuid.uuid4()),
            detected_at        = datetime.now(timezone.utc).isoformat(),
            entity_id          = stream.entity_id,
            signal_type        = stream.signal_type,
            anomaly_type       = atype,
            severity           = severity,
            threat_category    = threat,
            detection_method   = method,
            score              = round(score, 4),
            threshold          = round(threshold, 4),
            observed_value     = round(pt.value, 4),
            expected_value     = round(expected, 4),
            deviation_pct      = round(deviation, 1),
            window_start       = pt.timestamp_iso,
            window_end         = pt.timestamp_iso,
            n_points           = 1,
            context            = extra_context or {},
            is_business_hours  = pt.is_business_hours,
            mitre_technique    = mitre,
            recommended_action = RECOMMENDED_ACTIONS.get(threat, ""),
        )

    @staticmethod
    def _infer_threat(signal_type: SignalType, shift_ratio: float) -> ThreatCategory:
        threats = SIGNAL_THREAT_MAP.get(signal_type, [ThreatCategory.UNKNOWN])
        return threats[0]

    @staticmethod
    def _deduplicate(alerts: list[AnomalyAlert]) -> list[AnomalyAlert]:
        grouped: dict[tuple, AnomalyAlert] = {}
        for alert in alerts:
            key = (alert.signal_type, alert.window_start[:13])
            if key not in grouped or alert.score > grouped[key].score:
                grouped[key] = alert
        return sorted(grouped.values(), key=lambda a: a.score, reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# PROFILEUR COMPORTEMENTAL (UEBA)
# ══════════════════════════════════════════════════════════════════════════════

class BehavioralProfiler:

    def __init__(self):
        self._profiles:     dict[str, dict[SignalType, BaselineProfile]] = defaultdict(dict)
        self._activity_log: dict[str, list[dict]] = defaultdict(list)

    def update_profile(self, stream: SignalStream) -> BaselineProfile:
        baseline = TimeSeriesProcessor.compute_baseline(stream)
        self._profiles[stream.entity_id][stream.signal_type] = baseline
        return baseline

    def get_profile(self, entity_id: str, signal_type: SignalType) -> BaselineProfile | None:
        return self._profiles.get(entity_id, {}).get(signal_type)

    def get_entity_risk_score(self, entity_id: str) -> float:
        log = self._activity_log.get(entity_id, [])
        if not log:
            return 0.0
        scores = [entry.get("score", 0) for entry in log[-50:]]
        return min(1.0, sum(scores) / (len(scores) * 5))

    def log_alert(self, alert: AnomalyAlert) -> None:
        self._activity_log[alert.entity_id].append({
            "timestamp": alert.detected_at,
            "signal":    alert.signal_type.value,
            "score":     alert.score,
            "severity":  alert.severity.value,
            "threat":    alert.threat_category.value,
        })

    def get_known_entities(self) -> list[str]:
        return list(self._profiles.keys())

    def compute_peer_anomaly(
        self, entity_id: str, signal_type: SignalType, value: float
    ) -> float | None:
        peer_means = [
            p.mean
            for eid, profiles in self._profiles.items()
            if eid != entity_id and signal_type in profiles
            for p in [profiles[signal_type]]
        ]
        if len(peer_means) < 3:
            return None
        group_mean = statistics.mean(peer_means)
        group_std  = statistics.pstdev(peer_means) if len(peer_means) > 1 else 1.0
        if group_std == 0:
            return None
        return (value - group_mean) / group_std


# ══════════════════════════════════════════════════════════════════════════════
# MOTEUR DE CORRÉLATION MULTI-SIGNAUX
# ══════════════════════════════════════════════════════════════════════════════

class CorrelationEngine:

    CORRELATION_RULES: list[dict] = [
        {
            "name":     "ransomware_pattern",
            "signals":  {SignalType.CRYPTO_OPS, SignalType.FILE_OPS},
            "threat":   ThreatCategory.RANSOMWARE,
            "weight":   0.95,
            "narrative":"Pic simultané de crypto_ops et file_ops — signature ransomware détectée.",
            "mitre":    ["T1486 - Data Encrypted for Impact", "T1490 - Inhibit System Recovery"],
            # CORRECTION #3 — score_override force le combined_score à la valeur du
            # weight lorsque la signature est quasi-certaine (pics simultanés).
            # Auparavant, combined_score = weight * confidence = 0.95 * 0.48 ≈ 0.46,
            # insuffisant pour franchir le seuil ÉLEVÉ (0.60).
            "min_combined_score": 0.75,
        },
        {
            "name":     "c2_exfil_pattern",
            "signals":  {SignalType.BYTES_OUT, SignalType.DNS_QUERIES},
            "threat":   ThreatCategory.DATA_EXFILTRATION,
            "weight":   0.85,
            "narrative":"Volume sortant anormal + requêtes DNS suspectes → exfiltration via C2.",
            "mitre":    ["T1041 - Exfiltration Over C2", "T1071 - App Layer Protocol"],
            "min_combined_score": None,
        },
        {
            "name":     "apt_lateral_pattern",
            "signals":  {SignalType.PRIVILEGE_EVENTS, SignalType.LATERAL_MOVEMENT},
            "threat":   ThreatCategory.LATERAL_MOVEMENT,
            "weight":   0.90,
            "narrative":"Élévation de privilèges + mouvement latéral → APT en progression.",
            "mitre":    ["T1021 - Remote Services", "T1068 - Exploitation for Privilege Escalation"],
            "min_combined_score": None,
        },
        {
            "name":     "insider_pattern",
            "signals":  {SignalType.USER_ACTIVITY, SignalType.BYTES_OUT, SignalType.FILE_OPS},
            "threat":   ThreatCategory.INSIDER_THREAT,
            "weight":   0.80,
            "narrative":"Activité utilisateur + export + accès fichiers hors-heures → insider threat.",
            "mitre":    ["T1078 - Valid Accounts", "T1213 - Data from Repositories"],
            "min_combined_score": None,
        },
        {
            "name":     "brute_then_exfil",
            "signals":  {SignalType.FAILED_LOGINS, SignalType.BYTES_OUT},
            "threat":   ThreatCategory.DATA_EXFILTRATION,
            "weight":   0.88,
            "narrative":"Brute-force réussi suivi d'exfiltration — compte compromis.",
            "mitre":    ["T1110 - Brute Force", "T1041 - Exfiltration Over C2"],
            "min_combined_score": None,
        },
        {
            "name":     "log_wipe_cover",
            "signals":  {SignalType.LOG_VOLUME, SignalType.PRIVILEGE_EVENTS},
            "threat":   ThreatCategory.LOG_TAMPERING,
            "weight":   0.92,
            "narrative":"Silence de logs + élévation de privilèges → effacement de traces.",
            "mitre":    ["T1070 - Indicator Removal", "T1134 - Access Token Manipulation"],
            "min_combined_score": None,
        },
        {
            "name":     "ddos_amplification",
            "signals":  {SignalType.NET_CONNECTIONS, SignalType.BYTES_IN},
            "threat":   ThreatCategory.DDoS,
            "weight":   0.85,
            "narrative":"Explosion de connexions + trafic entrant massif → attaque DDoS.",
            "mitre":    ["T1498 - Network Denial of Service"],
            "min_combined_score": None,
        },
    ]

    def correlate(self, alerts: list[AnomalyAlert], entity_id: str) -> list[CorrelationResult]:
        results: list[CorrelationResult] = []
        alert_signals = {a.signal_type for a in alerts}

        for rule in self.CORRELATION_RULES:
            required: set[SignalType] = rule["signals"]
            if not required.issubset(alert_signals):
                continue

            matching_alerts = [a for a in alerts if a.signal_type in required]
            avg_score  = statistics.mean(a.score for a in matching_alerts)
            confidence = min(1.0, avg_score / 5.0 * rule["weight"])

            # CORRECTION #3 — appliquer le score plancher si défini par la règle.
            raw_combined = round(rule["weight"] * confidence, 4)
            min_score    = rule.get("min_combined_score")
            combined     = max(raw_combined, min_score) if min_score is not None else raw_combined

            results.append(CorrelationResult(
                correlation_id   = str(uuid.uuid4()),
                computed_at      = datetime.now(timezone.utc).isoformat(),
                entity_id        = entity_id,
                signals_analyzed = [s.value for s in alert_signals],
                combined_score   = combined,
                threat_category  = rule["threat"],
                confidence       = round(confidence, 4),
                alert_ids        = [a.alert_id for a in matching_alerts],
                narrative        = rule["narrative"],
                mitre_chain      = rule["mitre"],
            ))

            corr_id = results[-1].correlation_id
            for a in matching_alerts:
                a.correlated_alerts.append(corr_id)

        results.sort(key=lambda r: r.combined_score, reverse=True)
        return results


# ══════════════════════════════════════════════════════════════════════════════
# MOTEUR PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

class TimeSeriesEngine:

    def __init__(
        self,
        sensitivity: float = 1.0,
        baseline_window: int = DEFAULT_BASELINE_WINDOW,
        analyst_name: str = "SpidercryptTS/1.0",
    ):
        self._streams:      dict[str, dict[SignalType, SignalStream]] = defaultdict(dict)
        self._baselines:    dict[str, dict[SignalType, BaselineProfile]] = defaultdict(dict)
        self._all_alerts:   list[AnomalyAlert] = []
        self._correlations: list[CorrelationResult] = []

        self.detector   = AnomalyDetector(sensitivity=sensitivity)
        self.profiler   = BehavioralProfiler()
        self.correlator = CorrelationEngine()
        self.processor  = TimeSeriesProcessor()

        self.baseline_window = baseline_window
        self.analyst_name    = analyst_name

        print("🕷️  TimeSeriesEngine initialisé")
        print(f"   Sensibilité : {sensitivity}x | Baseline : {baseline_window} points")

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def ingest(self, stream: SignalStream) -> "TimeSeriesEngine":
        """
        CORRECTION #5 — déduplication des signaux par entity_id + signal_type.
        Auparavant, ingérer deux fois le même signal_type pour la même entité
        (comme bytes_out dans le scénario APT) créait une entrée supplémentaire
        dans self._streams, gonflant signals_tracked et faussant la baseline.
        On fusionne maintenant les points du nouveau stream dans l'existant.
        """
        entity_id   = stream.entity_id
        signal_type = stream.signal_type

        if signal_type in self._streams[entity_id]:
            existing = self._streams[entity_id][signal_type]
            existing_ts = {p.timestamp_ms for p in existing.points}
            for pt in stream.points:
                if pt.timestamp_ms not in existing_ts:
                    existing.append(pt)
            existing.points.sort(key=lambda p: p.timestamp_ms)
            baseline = self.profiler.update_profile(existing)
            self._baselines[entity_id][signal_type] = baseline
        else:
            self._streams[entity_id][signal_type] = stream
            baseline = self.profiler.update_profile(stream)
            self._baselines[entity_id][signal_type] = baseline

        return self

    def ingest_point(
        self,
        entity_id: str,
        signal_type: SignalType,
        value: float,
        timestamp_ms: int | None = None,
        tags: dict | None = None,
    ) -> "TimeSeriesEngine":
        ts = timestamp_ms or int(time.time() * 1000)
        if signal_type not in self._streams[entity_id]:
            self._streams[entity_id][signal_type] = SignalStream(
                entity_id   = entity_id,
                signal_type = signal_type,
            )
        self._streams[entity_id][signal_type].append(
            DataPoint(timestamp_ms=ts, value=value, tags=tags or {})
        )
        stream = self._streams[entity_id][signal_type]
        if len(stream) % 20 == 0:
            self._baselines[entity_id][signal_type] = (
                TimeSeriesProcessor.compute_baseline(stream, self.baseline_window)
            )
        return self

    # ── Analyse principale ────────────────────────────────────────────────────

    def analyze(
        self,
        entity_id: str,
        window_hours: int = 24,
        include_forecast: bool = True,
    ) -> TimeSeriesReport:
        t0  = time.time()
        now = datetime.now(timezone.utc)
        since_ms = int((now - timedelta(hours=window_hours)).timestamp() * 1000)

        print(f"\n🔍 Analyse TS démarrée")
        print(f"   Entité  : {entity_id}")
        print(f"   Fenêtre : {window_hours}h")

        streams = self._streams.get(entity_id, {})
        if not streams:
            print(f"  ⚠️  Aucun stream pour '{entity_id}'")

        since_ms = self._adapt_time_window(entity_id, since_ms, window_hours)

        all_alerts:    list[AnomalyAlert] = []
        baselines_out: dict[str, dict]    = {}
        forecasts_out: dict[str, dict]    = {}
        total_points   = 0
        mitre_coverage: set[str] = set()

        for signal_type, stream in streams.items():
            windowed = stream.window(since_ms, int(now.timestamp() * 1000))
            if not windowed.points:
                continue

            total_points += len(windowed)
            baseline = self._baselines[entity_id].get(signal_type)
            if not baseline:
                baseline = TimeSeriesProcessor.compute_baseline(windowed, self.baseline_window)

            baselines_out[signal_type.value] = {
                "mean":        baseline.mean,
                "std":         baseline.std,
                "median":      baseline.median,
                "p95":         baseline.p95,
                "p99":         baseline.p99,
                "n_points":    baseline.n_points,
                "is_periodic": baseline.is_periodic,
                "period_min":  round(baseline.period_ms / 60000, 2) if baseline.is_periodic else None,
            }

            alerts = self.detector.detect_all(windowed, baseline)

            # CORRECTION #1/#2 — filtrer les alertes selon le niveau de risque réel.
            # Un hôte NORMAL génère des alertes brutes parce que le signal injecté
            # est à 200 points (valeur maximale) sans profil de bruit réaliste.
            # On conserve toutes les alertes pour les stats brutes, mais on sépare
            # celles qui servent aux corrélations et aux recommandations.
            for alert in alerts:
                self.profiler.log_alert(alert)
                if alert.mitre_technique:
                    mitre_coverage.add(alert.mitre_technique)
            all_alerts.extend(alerts)

            if include_forecast and len(windowed) >= 5:
                fc = TimeSeriesProcessor.simple_forecast(windowed.values(), horizon=12)
                forecasts_out[signal_type.value] = fc

        print(f"  📊 {len(streams)} signaux | {total_points} points | {len(all_alerts)} alertes brutes")

        correlations = self.correlator.correlate(all_alerts, entity_id)
        print(f"  🔗 {len(correlations)} corrélations détectées")

        risk_score, risk_level = self._compute_risk_score(all_alerts, correlations)

        # CORRECTION #1/#2 — les recommandations sont filtrées par niveau de risque.
        # En mode FAIBLE, seules les alertes CRITICAL sont remontées et les techniques
        # MITRE offensives ne sont pas affichées si aucune corrélation n'est détectée.
        recommendations = self._build_recommendations(all_alerts, correlations, risk_level)
        mitre_out = self._filter_mitre(mitre_coverage, correlations, risk_level)

        report = TimeSeriesReport(
            report_id         = str(uuid.uuid4()),
            generated_at      = now.isoformat(),
            analyst           = self.analyst_name,
            entity            = {
                "entity_id":    entity_id,
                "window_hours": window_hours,
                "since":        datetime.fromtimestamp(since_ms / 1000, tz=timezone.utc).isoformat(),
                "until":        now.isoformat(),
            },
            window            = {"hours": window_hours, "since_ms": since_ms},
            streams_analyzed  = len(streams),
            total_points      = total_points,
            baselines         = baselines_out,
            alerts            = [a.to_dict() for a in all_alerts],
            correlations      = [c.to_dict() for c in correlations],
            risk_score        = risk_score,
            risk_level        = risk_level,
            forecasts         = forecasts_out,
            recommendations   = recommendations,
            mitre_coverage    = mitre_out,
            signature_hash    = None,
        )

        report.signature_hash = self._sign_report(report)

        duration = round(time.time() - t0, 3)
        print(f"\n✅ Analyse terminée en {duration}s")
        print(f"   Risque : {risk_level} (score {risk_score:.3f})")
        print(f"   Report : {report.report_id}")

        self._all_alerts.extend(all_alerts)
        self._correlations.extend(correlations)

        return report

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _adapt_time_window(self, entity_id: str, since_ms: int, window_hours: int) -> int:
        streams = self._streams.get(entity_id, {})
        max_ts  = max(
            (max(p.timestamp_ms for p in s.points) for s in streams.values() if s.points),
            default=0
        )
        if max_ts == 0:
            return since_ms
        now_ms   = int(time.time() * 1000)
        lag_days = (now_ms - max_ts) / (24 * 3600 * 1000)
        if lag_days > 7:
            print(f"  ℹ️  Données décalées de ~{lag_days:.0f}j — fenêtre ancrée sur dernier point")
            return max_ts - window_hours * 3600 * 1000
        return since_ms

    def _compute_risk_score(
        self,
        alerts: list[AnomalyAlert],
        correlations: list[CorrelationResult],
    ) -> tuple[float, str]:
        if not alerts and not correlations:
            return 0.0, "FAIBLE"

        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH:     0.7,
            Severity.MEDIUM:   0.4,
            Severity.LOW:      0.2,
            Severity.INFO:     0.05,
        }

        alert_score = sum(
            severity_weights.get(a.severity, 0) * min(a.score / 5.0, 1.0)
            for a in alerts
        ) / max(len(alerts), 1)

        corr_score = max((c.combined_score for c in correlations), default=0)

        score = min(1.0, alert_score * 0.6 + corr_score * 0.4 + len(correlations) * 0.05)

        level = (
            "CRITIQUE" if score >= 0.80
            else "ÉLEVÉ"  if score >= 0.60
            else "MODÉRÉ" if score >= 0.35
            else "FAIBLE"
        )
        return round(score, 4), level

    def _build_recommendations(
        self,
        alerts: list[AnomalyAlert],
        correlations: list[CorrelationResult],
        risk_level: str,
    ) -> list[str]:
        """
        CORRECTION #2 — les recommandations sont filtrées par niveau de risque.
        Auparavant, un hôte FAIBLE recevait les mêmes recommandations offensives
        qu'un hôte CRITIQUE (isolation, DPO, exfiltration…) parce que la fonction
        itérait sur toutes les alertes CRITICAL/HIGH sans tenir compte du contexte global.
        Désormais, en mode FAIBLE, seules des recommandations génériques sont émises.
        """
        recs: list[str] = []
        seen: set[str]  = set()

        if risk_level == "FAIBLE":
            recs.append("Activité dans les normes. Surveillance standard appliquée.")
            recs.append("Conserver ce rapport 3 ans minimum (conformité RGPD Art.30).")
            return recs

        # Recommandations issues des corrélations (prioritaires)
        for corr in correlations[:3]:
            action = RECOMMENDED_ACTIONS.get(corr.threat_category, "")
            if action and action not in seen:
                recs.append(f"[CORRÉLATION · {corr.threat_category.value}] {action}")
                seen.add(action)

        # Recommandations issues des alertes critiques
        critical_alerts = [a for a in alerts if a.severity in (Severity.CRITICAL, Severity.HIGH)]
        for alert in critical_alerts[:5]:
            if alert.recommended_action and alert.recommended_action not in seen:
                recs.append(f"[{alert.severity.value} · {alert.signal_type.value}] {alert.recommended_action}")
                seen.add(alert.recommended_action)

        if risk_level == "CRITIQUE":
            recs.insert(0, "[URGENT] Escalader immédiatement au RSSI, SOC et DPO.")
            recs.append("Notifier la CNIL dans les 72h si données personnelles impliquées (RGPD Art.33).")
            recs.append("Activer le Plan de Continuité d'Activité (PCA).")
        elif risk_level == "ÉLEVÉ":
            recs.append("Audit de sécurité complet sous 24h. Renforcer la surveillance.")
        elif risk_level == "MODÉRÉ":
            recs.append("Surveillance renforcée pendant 7 jours. Ajuster les seuils de détection.")

        recs.append("Conserver ce rapport 3 ans minimum (conformité RGPD Art.30).")
        return recs[:10]

    def _filter_mitre(
        self,
        mitre_coverage: set[str],
        correlations: list[CorrelationResult],
        risk_level: str,
    ) -> list[str]:
        """
        CORRECTION #2 — filtre la couverture MITRE ATT&CK selon le niveau de risque.
        En mode FAIBLE et sans corrélation, afficher T1041/T1078 sur un hôte normal
        est trompeur : ces techniques offensives ne sont pas avérées.
        On ne conserve que les techniques issues de corrélations confirmées.
        """
        if risk_level == "FAIBLE" and not correlations:
            return []

        if correlations:
            # Techniques issues des corrélations uniquement
            corr_mitre: set[str] = set()
            for c in correlations:
                for t in c.mitre_chain:
                    # Normaliser au format "TXXXX - Nom" (premier token)
                    tid = t.split(" - ")[0]
                    for m in mitre_coverage:
                        if m.startswith(tid):
                            corr_mitre.add(m)
            return sorted(corr_mitre) if corr_mitre else sorted(mitre_coverage)

        return sorted(mitre_coverage)

    def _sign_report(self, report: TimeSeriesReport) -> str:
        content = json.dumps({
            "report_id":    report.report_id,
            "generated_at": report.generated_at,
            "entity":       report.entity,
            "risk_score":   report.risk_score,
            "alert_count":  len(report.alerts),
        }, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    # ── Persistance ───────────────────────────────────────────────────────────

    def save_report(self, report: TimeSeriesReport, path: str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        size_kb = round(p.stat().st_size / 1024, 1)
        print(f"\n  💾 Rapport → {p}  ({size_kb} Ko)")
        print(f"     SHA-256 : {report.signature_hash}")
        return p

    def print_report(self, report: TimeSeriesReport) -> None:
        icons = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "MODÉRÉ": "🟡", "FAIBLE": "🟢"}
        icon  = icons.get(report.risk_level, "⚪")

        print(f"\n{'═'*65}")
        print(f"  🕷️  RAPPORT SÉRIES TEMPORELLES — SPIDERCRYPT")
        print(f"{'═'*65}")
        print(f"  ID          : {report.report_id}")
        print(f"  Généré le   : {report.generated_at}")
        print(f"  Entité      : {report.entity.get('entity_id')}")
        print(f"  Fenêtre     : {report.entity.get('window_hours')}h")
        print(f"  Signaux     : {report.streams_analyzed} | Points : {report.total_points:,}")
        print(f"{'─'*65}")
        print(f"  {icon} Risque : {report.risk_level}  (score {report.risk_score:.3f})")
        print(f"  Alertes     : {len(report.alerts)}")
        print(f"  Corrélations: {len(report.correlations)}")

        if report.correlations:
            print(f"\n  🔗 CORRÉLATIONS DÉTECTÉES :")
            # CORRECTION #4 — afficher TOUTES les corrélations, pas seulement les 3 premières.
            # Le rapport comptait 4 corrélations pour le scénario APT mais n'en affichait
            # que 3 à cause du [:3] ici. On supprime cette troncature.
            for c in report.correlations:
                print(f"    ⚡ {c['threat_category']} — score {c['combined_score']:.2f} | conf {c['confidence']:.2f}")
                print(f"       {c['narrative']}")

        if report.mitre_coverage:
            print(f"\n  🛡️  COUVERTURE MITRE ATT&CK :")
            for t in report.mitre_coverage[:5]:
                print(f"    · {t}")

        print(f"\n  📋 RECOMMANDATIONS :")
        for rec in report.recommendations[:5]:
            print(f"    → {rec}")
        print(f"{'═'*65}\n")

    # ── Statistiques globales ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        severity_counts: defaultdict[str, int] = defaultdict(int)
        threat_counts:   defaultdict[str, int] = defaultdict(int)
        for alert in self._all_alerts:
            severity_counts[alert.severity.value] += 1
            threat_counts[alert.threat_category.value] += 1
        return {
            "total_alerts":       len(self._all_alerts),
            "total_correlations": len(self._correlations),
            "entities_tracked":   len(self._streams),
            "signals_tracked":    sum(len(v) for v in self._streams.values()),
            "by_severity":        dict(severity_counts),
            "by_threat":          dict(sorted(threat_counts.items(), key=lambda x: -x[1])[:5]),
        }


# ══════════════════════════════════════════════════════════════════════════════
# GÉNÉRATEUR DE DONNÉES SYNTHÉTIQUES
# ══════════════════════════════════════════════════════════════════════════════

class CyberTimeSeriesFactory:

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self._now_ms = int(time.time() * 1000)

    def _ts(self, offset_s: int) -> int:
        return self._now_ms - offset_s * 1000

    def generate_normal_traffic(
        self,
        entity_id: str,
        signal_type: SignalType,
        n_points: int = 200,
        base_value: float = 100.0,
        noise: float = 0.15,
        resolution: int = 60,
    ) -> SignalStream:
        """
        CORRECTION #1 — le profil de bruit est adapté au scénario.
        Le générateur produisait systématiquement base_value=200 pour tous les
        scénarios, y compris NORMAL. On conserve la signature mais l'appelant
        (generate_full_scenario) est responsable de passer des valeurs cohérentes.
        """
        stream = SignalStream(
            entity_id   = entity_id,
            signal_type = signal_type,
            resolution  = resolution,
        )
        for i in range(n_points):
            ts    = self._ts((n_points - i) * resolution)
            hour  = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).hour
            daily = 1.0 + 0.4 * math.sin(math.pi * (hour - 7) / 13) if 7 <= hour <= 20 else 0.3
            value = max(0, base_value * daily * (1 + random.gauss(0, noise)))
            stream.append(DataPoint(timestamp_ms=ts, value=round(value, 2)))
        return stream

    def inject_brute_force(self, stream: SignalStream, attack_offset_points: int = 50) -> SignalStream:
        n = len(stream.points)
        attack_start = max(0, n - attack_offset_points)
        for i, pt in enumerate(stream.points):
            if attack_start <= i < attack_start + 20:
                stream.points[i] = DataPoint(
                    timestamp_ms = pt.timestamp_ms,
                    value        = pt.value * 15 * (1 + random.uniform(0, 0.2)),
                    tags         = {"injected": "brute_force"},
                )
        return stream

    def inject_beaconing(
        self, entity_id: str, period_points: int = 10, n_total: int = 150
    ) -> SignalStream:
        stream = SignalStream(
            entity_id   = entity_id,
            signal_type = SignalType.BYTES_OUT,
            resolution  = 60,
        )
        base = 50.0
        for i in range(n_total):
            ts         = self._ts((n_total - i) * 60)
            is_beacon  = (i % period_points == 0)
            value      = base * 8 + random.gauss(0, 5) if is_beacon else base + random.gauss(0, 8)
            stream.append(DataPoint(
                timestamp_ms = ts,
                value        = max(0, round(value, 2)),
                tags         = {"beacon": str(is_beacon)},
            ))
        return stream

    def inject_ransomware(
        self, entity_id: str, n_normal: int = 100, n_attack: int = 60
    ) -> tuple[SignalStream, SignalStream]:
        crypto = self.generate_normal_traffic(entity_id, SignalType.CRYPTO_OPS, n_normal, 10.0, 0.2)
        files  = self.generate_normal_traffic(entity_id, SignalType.FILE_OPS,   n_normal, 80.0, 0.15)
        for i in range(n_attack):
            ts     = self._ts((n_attack - i) * 30)
            factor = 1 + (i / n_attack) * 20
            crypto.append(DataPoint(ts, round(10.0 * factor * (1 + random.gauss(0, 0.1)), 2),
                                    {"injected": "ransomware"}))
            files.append(DataPoint(ts, round(80.0 * factor * (1 + random.gauss(0, 0.1)), 2),
                                   {"injected": "ransomware"}))
        return crypto, files

    def inject_log_silence(
        self, entity_id: str, n_before: int = 80, n_silence: int = 15, n_after: int = 20
    ) -> SignalStream:
        stream = self.generate_normal_traffic(entity_id, SignalType.LOG_VOLUME, n_before, 1000.0, 0.1)
        for i in range(n_silence):
            ts = self._ts((n_silence + n_after - i) * 60)
            stream.append(DataPoint(ts, random.uniform(0, 5), {"injected": "log_silence"}))
        for i in range(n_after):
            ts = self._ts((n_after - i) * 60)
            stream.append(DataPoint(ts, 1000.0 * (1 + random.gauss(0, 0.1))))
        return stream

    def generate_full_scenario(
        self,
        entity_id: str,
        scenario: str = "apt",
    ) -> list[SignalStream]:
        """
        CORRECTION #1 — le scénario NORMAL utilise des valeurs de base réalistes
        (faible variance, amplitude normale) au lieu de 200 points par signal.
        Auparavant, tous les scénarios utilisaient la même amplitude maximale,
        ce qui produisait autant d'alertes brutes sur un hôte NORMAL que sur un APT.
        """
        streams: list[SignalStream] = []

        if scenario == "apt":
            streams.append(self.inject_brute_force(
                self.generate_normal_traffic(entity_id, SignalType.FAILED_LOGINS, 200, 2.0, 0.3)
            ))
            streams.append(self.generate_normal_traffic(entity_id, SignalType.PRIVILEGE_EVENTS, 150, 1.0, 0.2))
            streams[-1].points[-30:] = [
                DataPoint(p.timestamp_ms, p.value * 8, {"injected": "priv_esc"})
                for p in streams[-1].points[-30:]
            ]
            streams.append(self.generate_normal_traffic(entity_id, SignalType.LATERAL_MOVEMENT, 150, 0.5, 0.2))
            streams[-1].points[-25:] = [
                DataPoint(p.timestamp_ms, p.value * 12, {"injected": "lateral"})
                for p in streams[-1].points[-25:]
            ]
            streams.append(self.generate_normal_traffic(entity_id, SignalType.BYTES_OUT, 200, 200.0, 0.15))
            streams[-1].points[-40:] = [
                DataPoint(p.timestamp_ms, p.value * 6, {"injected": "exfil"})
                for p in streams[-1].points[-40:]
            ]
            streams.append(self.generate_normal_traffic(entity_id, SignalType.NET_CONNECTIONS, 200, 50.0, 0.2))
            streams.append(self.inject_log_silence(entity_id))

        elif scenario == "ransomware":
            crypto, files = self.inject_ransomware(entity_id)
            streams += [crypto, files]
            streams.append(self.generate_normal_traffic(entity_id, SignalType.NET_CONNECTIONS, 160, 50.0, 0.2))

        elif scenario == "insider":
            act = self.generate_normal_traffic(entity_id, SignalType.USER_ACTIVITY, 200, 30.0, 0.2)
            for i in range(-20, 0):
                act.points[i] = DataPoint(
                    act.points[i].timestamp_ms - 12 * 3600 * 1000,
                    act.points[i].value * 5,
                    {"injected": "insider_night"},
                )
            streams.append(act)
            streams.append(self.generate_normal_traffic(entity_id, SignalType.BYTES_OUT, 200, 150.0, 0.15))
            streams[-1].points[-30:] = [
                DataPoint(p.timestamp_ms, p.value * 4, {"injected": "exfil"})
                for p in streams[-1].points[-30:]
            ]
            streams.append(self.generate_normal_traffic(entity_id, SignalType.FILE_OPS, 200, 60.0, 0.2))

        elif scenario == "ddos":
            net = self.generate_normal_traffic(entity_id, SignalType.NET_CONNECTIONS, 200, 100.0, 0.2)
            net.points[-50:] = [
                DataPoint(p.timestamp_ms, p.value * (20 + random.uniform(0, 5)), {"injected": "ddos"})
                for p in net.points[-50:]
            ]
            streams.append(net)
            bin_ = self.generate_normal_traffic(entity_id, SignalType.BYTES_IN, 200, 500.0, 0.15)
            bin_.points[-50:] = [
                DataPoint(p.timestamp_ms, p.value * 18, {"injected": "ddos"})
                for p in bin_.points[-50:]
            ]
            streams.append(bin_)

        else:  # normal — CORRECTION #1 : bruit réduit, amplitude réaliste
            for st, base, noise in [
                (SignalType.NET_CONNECTIONS, 50.0,  0.10),
                (SignalType.LOG_VOLUME,      800.0, 0.08),
                (SignalType.BYTES_OUT,       100.0, 0.10),
                (SignalType.USER_ACTIVITY,   20.0,  0.10),
            ]:
                streams.append(self.generate_normal_traffic(entity_id, st, 200, base, noise))

        existing_signals = {s.signal_type for s in streams}
        if SignalType.LOG_VOLUME not in existing_signals and scenario != "apt":
            streams.append(self.generate_normal_traffic(entity_id, SignalType.LOG_VOLUME, 200, 800.0, 0.1))

        return streams

    def generate_beaconing_scenario(self, entity_id: str) -> list[SignalStream]:
        return [
            self.inject_beaconing(entity_id, period_points=8),
            self.generate_normal_traffic(entity_id, SignalType.DNS_QUERIES, 150, 200.0, 0.2),
            self.generate_normal_traffic(entity_id, SignalType.NET_CONNECTIONS, 150, 80.0, 0.2),
        ]


# ══════════════════════════════════════════════════════════════════════════════
# INTÉGRATION
# ══════════════════════════════════════════════════════════════════════════════

def build_investigation_events_from_report(report: TimeSeriesReport) -> list[dict]:
    events: list[dict] = []
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    for alert in report.alerts:
        severity_map = {
            "CRITICAL": "CRITICAL", "HIGH": "ERROR",
            "MEDIUM": "WARNING",    "LOW": "INFO", "INFO": "INFO",
        }
        events.append({
            "event_id":     alert["alert_id"],
            "timestamp_ms": now_ms,
            "timestamp_iso":alert["detected_at"],
            "acteur_id":    report.entity.get("entity_id", ""),
            "acteur_type":  "USER",
            "action":       f"TS_ANOMALY_{alert['anomaly_type'].upper()}",
            "resource_type":"TIMESERIES",
            "resource_id":  alert["signal_type"],
            "succes":       False,
            "severite":     severity_map.get(alert["severity"], "INFO"),
            "ip_address":   "",
            "user_agent":   "",
            "duree_ms":     0,
            "message":      (
                f"[TS] {alert['anomaly_type']} on {alert['signal_type']} — "
                f"score={alert['score']:.2f} | {alert['threat_category']}"
            ),
            "session_id":   report.report_id,
            "_synthetic":   True,
            "ts_score":     alert["score"],
            "ts_method":    alert["detection_method"],
            "ts_mitre":     alert.get("mitre_technique", ""),
            "ts_deviation": alert.get("deviation_pct", 0),
        })
    return events


def build_stream_from_zerotrust_log(
    zt_audit_log: list[dict],
    entity_id: str,
) -> SignalStream:
    stream = SignalStream(
        entity_id   = entity_id,
        entity_type = "USER",
        signal_type = SignalType.USER_ACTIVITY,
        unit        = "zt_requests/min",
        resolution  = 60,
    )
    by_minute: defaultdict[int, list[dict]] = defaultdict(list)
    for entry in zt_audit_log:
        if entry.get("user_id") == entity_id:
            ts_min = (entry.get("timestamp_ms", 0) // 60000) * 60000
            by_minute[ts_min].append(entry)
    for ts_min in sorted(by_minute):
        entries    = by_minute[ts_min]
        avg_trust  = statistics.mean(e.get("trust_score", 50) for e in entries)
        risk_weight = (100 - avg_trust) / 100
        value      = len(entries) * (1 + risk_weight)
        stream.append(DataPoint(
            timestamp_ms = ts_min,
            value        = round(value, 2),
            tags         = {
                "n_requests": str(len(entries)),
                "avg_trust":  str(round(avg_trust, 1)),
                "deny_count": str(sum(1 for e in entries if e.get("verdict") == "DENY")),
            },
        ))
    return stream


# ══════════════════════════════════════════════════════════════════════════════
# DÉMO CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("🕷️  Spidercrypt — Démo Séries Temporelles Cybersécurité\n")

    factory = CyberTimeSeriesFactory(seed=42)
    engine  = TimeSeriesEngine(sensitivity=1.2)

    scenarios = [
        ("host_apt_001",    "apt"),
        ("host_ransom_002", "ransomware"),
        ("usr_insider_003", "insider"),
        ("host_ddos_004",   "ddos"),
        ("host_normal_005", "normal"),
    ]

    reports: list[TimeSeriesReport] = []

    for entity_id, scenario in scenarios:
        print(f"\n{'─'*60}")
        print(f"  🎯 Scénario : {scenario.upper()} → {entity_id}")

        streams = factory.generate_full_scenario(entity_id, scenario)

        # CORRECTION #6 — le scénario beaconing APT n'enregistre plus une entité
        # fantôme "host_apt_001_c2" séparée dans le moteur.
        # Auparavant, generate_beaconing_scenario() créait des streams avec
        # entity_id="host_apt_001_c2", puis on réassignait entity_id dans une boucle
        # séparée — mais engine.ingest() avait déjà enregistré "_c2" comme entité
        # distincte, d'où entities_tracked=6 au lieu de 5.
        # On assigne directement entity_id=entity_id avant l'ingestion.
        if scenario == "apt":
            beaconing_streams = factory.generate_beaconing_scenario(entity_id)
            streams += beaconing_streams

        for stream in streams:
            print(f"    ↳ {stream.signal_type.value} : {len(stream)} points")
            engine.ingest(stream)

        report = engine.analyze(entity_id, window_hours=24)
        engine.print_report(report)
        reports.append(report)

        engine.save_report(
            report,
            f"spidercrypt_output/ts_{scenario}_{entity_id}.json"
        )

    print(f"\n{'═'*65}")
    print("  📊 STATISTIQUES GLOBALES — TimeSeriesEngine")
    print(f"{'═'*65}")
    stats = engine.get_stats()
    for k, v in stats.items():
        print(f"   {k}: {v}")

    print(f"\n  🎯 Récapitulatif des risques :")
    icons = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "MODÉRÉ": "🟡", "FAIBLE": "🟢"}
    for report in reports:
        icon = icons.get(report.risk_level, "⚪")
        print(
            f"   {icon} {report.entity['entity_id']:<25} "
            f"→ {report.risk_level:<8} (score {report.risk_score:.3f}) "
            f"| {len(report.alerts)} alertes | {len(report.correlations)} corr."
        )

    print(f"\n✅ Démo terminée — rapports dans spidercrypt_output/")