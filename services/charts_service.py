"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT ENTERPRISE — Service Graphiques Seaborn               ║
║   Timeline · Heatmap · Anomalies · Score de risque · Distribution          ║
╚══════════════════════════════════════════════════════════════════════════════╝

Génère des graphiques PNG depuis les rapports d'investigation.
Retourne les images encodées en base64 pour intégration HTML/API.
"""

from __future__ import annotations

import base64
import io
from datetime import datetime
from typing import Any

import matplotlib
matplotlib.use("Agg")  # Mode sans interface graphique (serveur)
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd
import numpy as np

# ── Style global SpiderCrypt ──────────────────────────────────────────────────
sns.set_theme(style="darkgrid", palette="deep")
SPIDER_COLORS = {
    "CRITIQUE": "#e74c3c",
    "ÉLEVÉ":    "#e67e22",
    "MOYEN":    "#f1c40f",
    "FAIBLE":   "#2ecc71",
    "INFO":     "#3498db",
    "WARNING":  "#e67e22",
    "ERROR":    "#e74c3c",
    "CRITICAL": "#c0392b",
}
BG_COLOR    = "#1a1a2e"
TEXT_COLOR  = "#ecf0f1"
ACCENT      = "#9b59b6"


def _fig_to_base64(fig: plt.Figure) -> str:
    """Convertit une figure Matplotlib en chaîne base64 PNG."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return encoded


def _base_fig(title: str, figsize=(12, 5)) -> tuple[plt.Figure, plt.Axes]:
    """Crée une figure avec le style SpiderCrypt."""
    fig, ax = plt.subplots(figsize=figsize, facecolor=BG_COLOR)
    ax.set_facecolor("#16213e")
    ax.tick_params(colors=TEXT_COLOR)
    ax.xaxis.label.set_color(TEXT_COLOR)
    ax.yaxis.label.set_color(TEXT_COLOR)
    ax.title.set_color(TEXT_COLOR)
    for spine in ax.spines.values():
        spine.set_edgecolor("#2c3e50")
    fig.suptitle(f"🕷️  {title}", color=TEXT_COLOR, fontsize=13, fontweight="bold")
    return fig, ax


# ══════════════════════════════════════════════════════════════════════════════
# GRAPHIQUE 1 — Timeline des événements
# ══════════════════════════════════════════════════════════════════════════════

def chart_timeline(timeline: list[dict], actor_id: str) -> str:
    """
    Graphique en barres verticales montrant les événements dans le temps,
    colorés par sévérité.
    """
    if not timeline:
        return _empty_chart("Aucun événement dans la timeline")

    df = pd.DataFrame(timeline)

    # Parser les timestamps
    try:
        df["ts"] = pd.to_datetime(df["timestamp_iso"], utc=True, errors="coerce")
        df = df.dropna(subset=["ts"]).sort_values("ts")
    except Exception:
        return _empty_chart("Erreur parsing timestamps")

    # Score de risque par événement
    if "risque_score" not in df.columns:
        df["risque_score"] = 0.5

    # Couleurs par sévérité
    sev_col = df.get("severite", pd.Series(["INFO"] * len(df)))
    colors = [SPIDER_COLORS.get(s, "#3498db") for s in sev_col]

    fig, ax = _base_fig(f"Timeline des événements — {actor_id}", figsize=(14, 5))

    ax.bar(
        range(len(df)),
        df["risque_score"].fillna(0.3),
        color=colors,
        alpha=0.85,
        width=0.7,
    )

    # Légende sévérités
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=SPIDER_COLORS["CRITICAL"], label="CRITICAL"),
        Patch(facecolor=SPIDER_COLORS["ERROR"],    label="ERROR"),
        Patch(facecolor=SPIDER_COLORS["WARNING"],  label="WARNING"),
        Patch(facecolor=SPIDER_COLORS["INFO"],     label="INFO"),
    ]
    ax.legend(handles=legend_elements, loc="upper right",
              facecolor="#16213e", labelcolor=TEXT_COLOR, fontsize=8)

    ax.set_xlabel("Événements (chronologique)", color=TEXT_COLOR)
    ax.set_ylabel("Score de risque", color=TEXT_COLOR)
    ax.set_ylim(0, 1.1)
    ax.set_xticks([])

    # Annoter le nombre total
    ax.text(0.02, 0.95, f"{len(df)} événements", transform=ax.transAxes,
            color=TEXT_COLOR, fontsize=9, va="top")

    fig.tight_layout()
    return _fig_to_base64(fig)


# ══════════════════════════════════════════════════════════════════════════════
# GRAPHIQUE 2 — Heatmap des risques par heure et jour
# ══════════════════════════════════════════════════════════════════════════════

def chart_risk_heatmap(timeline: list[dict], actor_id: str) -> str:
    """
    Heatmap : axe X = heure de la journée, axe Y = jour de la semaine.
    Intensité = score de risque moyen.
    """
    if not timeline:
        return _empty_chart("Pas de données pour la heatmap")

    df = pd.DataFrame(timeline)
    try:
        df["ts"] = pd.to_datetime(df["timestamp_iso"], utc=True, errors="coerce")
        df = df.dropna(subset=["ts"])
        df["heure"] = df["ts"].dt.hour
        df["jour"]  = df["ts"].dt.day_name()
    except Exception:
        return _empty_chart("Erreur parsing timestamps")

    if "risque_score" not in df.columns:
        df["risque_score"] = 0.3

    jours_ordre = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    jours_fr    = ["Lundi","Mardi","Mercredi","Jeudi","Vendredi","Samedi","Dimanche"]

    pivot = df.pivot_table(
        values="risque_score",
        index="jour",
        columns="heure",
        aggfunc="mean",
    ).reindex([j for j in jours_ordre if j in df["jour"].unique()])

    if pivot.empty:
        return _empty_chart("Pas assez de données pour la heatmap")

    # Compléter les heures manquantes
    all_hours = list(range(24))
    for h in all_hours:
        if h not in pivot.columns:
            pivot[h] = np.nan
    pivot = pivot[sorted(pivot.columns)]

    fig, ax = _base_fig(f"Heatmap Risque par Heure/Jour — {actor_id}", figsize=(14, 4))

    sns.heatmap(
        pivot,
        ax=ax,
        cmap="YlOrRd",
        linewidths=0.3,
        linecolor="#1a1a2e",
        annot=False,
        cbar_kws={"label": "Score risque moyen", "shrink": 0.8},
        vmin=0, vmax=1,
    )

    # Labels FR
    ytick_labels = []
    for label in ax.get_yticklabels():
        en = label.get_text()
        idx = jours_ordre.index(en) if en in jours_ordre else -1
        ytick_labels.append(jours_fr[idx] if idx >= 0 else en)
    ax.set_yticklabels(ytick_labels, color=TEXT_COLOR, rotation=0)
    ax.set_xticklabels(ax.get_xticklabels(), color=TEXT_COLOR, fontsize=7)
    ax.set_xlabel("Heure de la journée", color=TEXT_COLOR)
    ax.set_ylabel("Jour", color=TEXT_COLOR)

    fig.tight_layout()
    return _fig_to_base64(fig)


# ══════════════════════════════════════════════════════════════════════════════
# GRAPHIQUE 3 — Distribution des anomalies par type
# ══════════════════════════════════════════════════════════════════════════════

def chart_anomalies(anomalies: list[dict], actor_id: str) -> str:
    """
    Graphique en barres horizontales des types d'anomalies détectées,
    colorées par sévérité.
    """
    if not anomalies:
        return _empty_chart("Aucune anomalie détectée ✅")

    df = pd.DataFrame(anomalies)

    # Compter par type
    counts = df["type_anomalie"].value_counts().head(10)
    severites = df.groupby("type_anomalie")["severite"].first()

    colors = [SPIDER_COLORS.get(severites.get(t, "INFO"), "#3498db") for t in counts.index]

    fig, ax = _base_fig(f"Anomalies détectées — {actor_id}", figsize=(12, max(4, len(counts) * 0.6)))

    bars = ax.barh(counts.index, counts.values, color=colors, alpha=0.85, height=0.6)

    # Valeurs sur les barres
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", color=TEXT_COLOR, fontsize=9)

    ax.set_xlabel("Nombre d'occurrences", color=TEXT_COLOR)
    ax.set_ylabel("Type d'anomalie", color=TEXT_COLOR)
    ax.set_yticklabels(counts.index, color=TEXT_COLOR, fontsize=9)
    ax.invert_yaxis()

    fig.tight_layout()
    return _fig_to_base64(fig)


# ══════════════════════════════════════════════════════════════════════════════
# GRAPHIQUE 4 — Évolution du score de risque dans le temps
# ══════════════════════════════════════════════════════════════════════════════

def chart_risk_evolution(timeline: list[dict], actor_id: str) -> str:
    """
    Courbe lissée du score de risque dans le temps avec zones colorées.
    """
    if not timeline:
        return _empty_chart("Pas de données pour l'évolution du risque")

    df = pd.DataFrame(timeline)
    try:
        df["ts"] = pd.to_datetime(df["timestamp_iso"], utc=True, errors="coerce")
        df = df.dropna(subset=["ts"]).sort_values("ts")
    except Exception:
        return _empty_chart("Erreur parsing timestamps")

    if "risque_score" not in df.columns:
        return _empty_chart("Pas de score de risque disponible")

    df["risque_score"] = df["risque_score"].fillna(0)

    # Rééchantillonner par heure
    df_ts = df.set_index("ts")["risque_score"].resample("1h").mean().fillna(method="ffill")

    fig, ax = _base_fig(f"Évolution du Score de Risque — {actor_id}", figsize=(14, 5))

    x = df_ts.index
    y = df_ts.values

    ax.plot(x, y, color=ACCENT, linewidth=2, zorder=3)
    ax.fill_between(x, y, alpha=0.3, color=ACCENT)

    # Zones de seuil
    ax.axhline(0.8, color=SPIDER_COLORS["CRITICAL"], linestyle="--", alpha=0.6, linewidth=1)
    ax.axhline(0.6, color=SPIDER_COLORS["WARNING"],  linestyle="--", alpha=0.6, linewidth=1)
    ax.axhline(0.35, color=SPIDER_COLORS["FAIBLE"],  linestyle="--", alpha=0.6, linewidth=1)

    ax.text(x[-1], 0.82, " CRITIQUE",  color=SPIDER_COLORS["CRITICAL"], fontsize=8)
    ax.text(x[-1], 0.62, " ÉLEVÉ",    color=SPIDER_COLORS["WARNING"],  fontsize=8)
    ax.text(x[-1], 0.37, " MOYEN",    color=SPIDER_COLORS["FAIBLE"],   fontsize=8)

    ax.set_ylim(0, 1.05)
    ax.set_xlabel("Temps", color=TEXT_COLOR)
    ax.set_ylabel("Score de risque", color=TEXT_COLOR)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m %Hh"))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right", color=TEXT_COLOR)

    fig.tight_layout()
    return _fig_to_base64(fig)


# ══════════════════════════════════════════════════════════════════════════════
# GRAPHIQUE 5 — Répartition des actions
# ══════════════════════════════════════════════════════════════════════════════

def chart_actions_pie(timeline: list[dict], actor_id: str) -> str:
    """
    Camembert des actions effectuées par l'acteur (READ, WRITE, DELETE…).
    """
    if not timeline:
        return _empty_chart("Pas de données d'actions")

    df = pd.DataFrame(timeline)
    if "action" not in df.columns:
        return _empty_chart("Champ 'action' absent")

    counts = df["action"].value_counts().head(8)

    fig, ax = plt.subplots(figsize=(8, 6), facecolor=BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    palette = sns.color_palette("husl", len(counts))
    wedges, texts, autotexts = ax.pie(
        counts.values,
        labels=counts.index,
        autopct="%1.1f%%",
        colors=palette,
        startangle=140,
        pctdistance=0.85,
    )
    for text in texts + autotexts:
        text.set_color(TEXT_COLOR)
        text.set_fontsize(9)

    ax.set_title(f"🕷️  Répartition des Actions — {actor_id}",
                 color=TEXT_COLOR, fontsize=12, fontweight="bold")
    fig.tight_layout()
    return _fig_to_base64(fig)


# ══════════════════════════════════════════════════════════════════════════════
# UTILITAIRE — Graphique vide
# ══════════════════════════════════════════════════════════════════════════════

def _empty_chart(message: str) -> str:
    """Retourne un graphique vide avec un message."""
    fig, ax = _base_fig(message, figsize=(8, 3))
    ax.text(0.5, 0.5, message, transform=ax.transAxes,
            ha="center", va="center", color=TEXT_COLOR, fontsize=12)
    ax.set_xticks([])
    ax.set_yticks([])
    return _fig_to_base64(fig)


# ══════════════════════════════════════════════════════════════════════════════
# FONCTION PRINCIPALE — Génère tous les graphiques d'un rapport
# ══════════════════════════════════════════════════════════════════════════════

def generate_all_charts(report: dict) -> dict[str, str]:
    """
    Génère tous les graphiques Seaborn depuis un rapport d'investigation.
    Retourne un dict {nom_chart: base64_png}.
    """
    actor_id = report.get("subject", {}).get("actor_id", "inconnu")
    timeline  = report.get("timeline",  [])
    anomalies = report.get("anomalies", [])

    charts = {}

    try:
        charts["timeline"]       = chart_timeline(timeline, actor_id)
    except Exception as e:
        charts["timeline"]       = _empty_chart(f"Erreur : {e}")

    try:
        charts["risk_heatmap"]   = chart_risk_heatmap(timeline, actor_id)
    except Exception as e:
        charts["risk_heatmap"]   = _empty_chart(f"Erreur : {e}")

    try:
        charts["anomalies"]      = chart_anomalies(anomalies, actor_id)
    except Exception as e:
        charts["anomalies"]      = _empty_chart(f"Erreur : {e}")

    try:
        charts["risk_evolution"] = chart_risk_evolution(timeline, actor_id)
    except Exception as e:
        charts["risk_evolution"] = _empty_chart(f"Erreur : {e}")

    try:
        charts["actions_pie"]    = chart_actions_pie(timeline, actor_id)
    except Exception as e:
        charts["actions_pie"]    = _empty_chart(f"Erreur : {e}")

    return charts