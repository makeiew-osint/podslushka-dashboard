"""External site monitor for GitHub Actions.

This process must run outside the web service so it can report an outage even
when the dashboard itself is completely stopped.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def send_message(token: str, chat_id: str, text: str) -> None:
    payload = urllib.parse.urlencode(
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError(f"Telegram returned HTTP {response.status}")


def site_is_available(url: str) -> tuple[bool, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "PodslushkaSiteMonitor/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if 200 <= response.status < 400:
                return True, f"HTTP {response.status}"
            return False, f"HTTP {response.status}"
    except urllib.error.HTTPError as error:
        # A live login page may intentionally reject a probe, but 5xx means
        # the service is unavailable.
        if error.code < 500:
            return True, f"HTTP {error.code}"
        return False, f"HTTP {error.code}"
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        return False, str(error)[:180]


def main() -> int:
    url = os.getenv("SITE_URL", "https://podslushka-dashboard.onrender.com/").strip()
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_UPDATES_CHAT_ID", "").strip()
    state_path = Path(os.getenv("MONITOR_STATE_FILE", "monitor-state.json"))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    if not token or not chat_id:
        print("TELEGRAM_BOT_TOKEN and TELEGRAM_UPDATES_CHAT_ID are required", file=sys.stderr)
        return 2

    previous = {}
    if state_path.exists():
        try:
            previous = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = {}

    available, details = site_is_available(url)
    current_state = "online" if available else "offline"
    previous_state = previous.get("state")
    # The first successful check establishes a baseline; it is not a recovery.
    # A recovery is reported only after an earlier check observed an outage.
    if current_state != previous_state and not (previous_state is None and available):
        if available:
            title = "Сайт снова работает"
            body = f"Панель доступна. Проверка: {details}."
        else:
            title = "Сайт на технических работах"
            body = f"Панель недоступна. Проверка: {details}."
        send_message(token, chat_id, f"📢 <b>Podslushka DB</b>\n{title}\n{body}")

    state_path.write_text(
        json.dumps(
            {
                "state": current_state,
                "checked_at": int(time.time()),
                "details": details,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"{current_state}: {details}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
