"""SpiderCrypt Enterprise — global configuration (env / secrets / paths)."""

from __future__ import annotations

import os
import tempfile
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_SECRET_PLACEHOLDER = "spidercrypt-dev-secret-change-in-prod"
_DEMO_API_KEYS = ("dev-key-001", "dev-key-002")


def _default_data_dir() -> str:
    return str(Path(tempfile.gettempdir()) / "spidercrypt")


class Settings(BaseSettings):
    """Configuration centralisée de l'API SpiderCrypt."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────────────────────────────
    APP_NAME: str = "SpiderCrypt Enterprise API"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Plateforme de cybersécurité Zero-Trust — Never Trust · Always Verify"
    )
    DEBUG: bool = False
    ENV: str = "development"

    # ── Sécurité ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = _DEV_SECRET_PLACEHOLDER
    API_KEY_HEADER: str = "X-SpiderCrypt-Key"
    ALLOWED_API_KEYS: list[str] = Field(default_factory=lambda: list(_DEMO_API_KEYS))

    # ── CORS ─────────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:8080"]
    )

    # ── Zero-Trust ───────────────────────────────────────────────────────────
    ZT_MAX_SESSION_AGE_MIN: float = 480.0
    ZT_ALLOWED_COUNTRIES: list[str] = Field(
        default_factory=lambda: [
            "FR",
            "BE",
            "CH",
            "LU",
            "DE",
            "NL",
            "ES",
            "IT",
            "GB",
            "CA",
            "US",
        ]
    )
    ZT_CORPORATE_IP_PREFIXES: list[str] = Field(
        default_factory=lambda: ["10.", "172.16.", "192.168.", "100.64."]
    )

    # ── Synthétique ──────────────────────────────────────────────────────────
    SYNTHETIC_DEFAULT_LOCALE: str = "fr_FR"
    SYNTHETIC_DEFAULT_SEED: int = 42

    # ── Stockage ─────────────────────────────────────────────────────────────
    DATA_DIR: str = Field(default_factory=_default_data_dir)
    AUDIT_LOG_PATH: str | None = None

    @field_validator("ALLOWED_API_KEYS", mode="before")
    @classmethod
    def _split_api_keys(cls, v: object) -> object:
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

    @model_validator(mode="after")
    def _audit_log_path(self) -> Settings:
        if not self.AUDIT_LOG_PATH:
            object.__setattr__(
                self,
                "AUDIT_LOG_PATH",
                str(Path(self.DATA_DIR) / "audit.json"),
            )
        return self

    @model_validator(mode="after")
    def _production_guardrails(self) -> Settings:
        if str(self.ENV).lower() != "production":
            return self
        if self.SECRET_KEY == _DEV_SECRET_PLACEHOLDER or len(self.SECRET_KEY) < 32:
            raise ValueError(
                "ENV=production requires a strong SECRET_KEY (≥32 chars, not the dev placeholder)."
            )
        if self.ALLOWED_API_KEYS == list(_DEMO_API_KEYS):
            raise ValueError(
                "ENV=production requires non-demo ALLOWED_API_KEYS "
                "(comma-separated or JSON list in env)."
            )
        return self


@lru_cache()
def get_settings() -> Settings:
    """Singleton des paramètres (chargé une seule fois)."""
    s = Settings()
    # #region agent log
    from core.agent_debug_log import agent_log

    run_id = os.getenv("AGENT_RUN_ID", "post-fix")
    env_dir = os.getenv("DATA_DIR")
    norm_data = s.DATA_DIR.replace("\\", "/").rstrip("/")
    norm_audit = str(s.AUDIT_LOG_PATH or "").replace("\\", "/")
    audit_under_datadir = norm_audit == f"{norm_data}/audit.json"
    agent_log(
        "H2",
        "core/config.py:get_settings",
        "DATA_DIR vs AUDIT_LOG_PATH",
        {
            "env_DATA_DIR": env_dir,
            "settings_DATA_DIR": s.DATA_DIR,
            "settings_AUDIT_LOG_PATH": s.AUDIT_LOG_PATH,
            "audit_path_matches_datadir_join": audit_under_datadir,
        },
        run_id=run_id,
    )
    agent_log(
        "H3",
        "core/config.py:get_settings",
        "DATA_DIR default style",
        {"DATA_DIR_is_unix_tmp_style": s.DATA_DIR.startswith("/tmp")},
        run_id=run_id,
    )
    agent_log(
        "H4",
        "core/config.py:get_settings",
        "production weak defaults",
        {
            "ENV": s.ENV,
            "using_default_secret": s.SECRET_KEY == _DEV_SECRET_PLACEHOLDER,
            "allowed_keys_count": len(s.ALLOWED_API_KEYS),
            "demo_keys_only": set(s.ALLOWED_API_KEYS) <= set(_DEMO_API_KEYS),
        },
        run_id=run_id,
    )
    # #endregion
    return s
