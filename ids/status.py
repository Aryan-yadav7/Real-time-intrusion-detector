"""The big green / yellow / red banner at the top of the dashboard.

Rules (look at the last 5 minutes only, so the banner calms down by itself):
  red     under attack: an active flood / password-guessing alert, OR 5+ serious threats
  yellow  suspicious: at least one threat of any kind
  green   all clear
"""
from __future__ import annotations

WINDOW_SECONDS = 300
RED_HIGH_COUNT = 5
HIGH_SCORE = 70


def compute_status(counts: dict) -> dict:
    """counts: {"total", "high", "behavior", "blocked"} for the last WINDOW_SECONDS."""
    total, high = counts["total"], counts["high"]
    behavior, blocked = counts["behavior"], counts["blocked"]
    minutes = WINDOW_SECONDS // 60

    if behavior or high >= RED_HIGH_COUNT:
        why = ("Someone is flooding the site or guessing passwords. "
               if behavior else "Several serious attack attempts. ")
        return {"level": "danger", "title": "Under attack",
                "message": f"{why}{total} threat{'s' if total != 1 else ''} in the last "
                           f"{minutes} minutes, {blocked} blocked."}
    if total:
        return {"level": "warning", "title": "Suspicious activity",
                "message": f"{total} suspicious request{'s' if total != 1 else ''} in the last "
                           f"{minutes} minutes. Nothing alarming yet, but keep an eye on it."}
    return {"level": "ok", "title": "All clear",
            "message": f"No threats in the last {minutes} minutes. Your site looks healthy."}
