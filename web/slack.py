import os
import requests


def send_slack_notification(msg: str) -> None:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json={"text": msg}, timeout=5)
    except Exception as e:
        print(f"[WARN] slack notification failed: {e}")
