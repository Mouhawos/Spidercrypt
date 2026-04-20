"""Compact NDJSON debug logger for agent sessions (folded in editor)."""
from __future__ import annotations

import json
import time
from pathlib import Path

_LOG_PATH = Path(__file__).resolve().parent.parent / "debug-832300.log"


def agent_log(
    hypothesis_id: str,
    location: str,
    message: str,
    data: dict | None = None,
    *,
    run_id: str = "pre-fix",
) -> None:
    # #region agent log
    try:
        line = json.dumps(
            {
                "sessionId": "832300",
                "timestamp": int(time.time() * 1000),
                "hypothesisId": hypothesis_id,
                "location": location,
                "message": message,
                "data": data or {},
                "runId": run_id,
            },
            ensure_ascii=False,
        )
        with _LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    # #endregion
