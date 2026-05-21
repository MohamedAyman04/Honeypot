import json
import os
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _generate_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    nonce = secrets.token_hex(2)
    return f"{ts}_{nonce}"


class StoryClient:
    def __init__(self, component: str, level: str) -> None:
        self.component = component
        self.level = level
        self.logger_url = (os.environ.get("STORY_LOGGER_URL") or "http://story_logger:8600").rstrip("/")
        self.run_id = os.environ.get("STORY_RUN_ID") or _generate_run_id()
        self.timeout = float(os.environ.get("STORY_LOGGER_TIMEOUT", "0.5"))

    def log(self, event_type: str, message: str, severity: str = "info", details: dict[str, Any] | None = None) -> None:
        if not self.logger_url:
            return

        payload = {
            "timestamp": _utc_now(),
            "run_id": self.run_id,
            "level": self.level,
            "component": self.component,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "details": details or {},
        }

        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        request = urllib.request.Request(
            url=f"{self.logger_url}/story/events",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout):
                pass
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
            return
