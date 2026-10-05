#!/usr/bin/env python3
"""
Discord Webhook Notifier for PW-Sentry
Author: Pebri & Antigravity Research Team
"""

import json
import urllib.request
import urllib.error
from datetime import datetime

class DiscordNotifier:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send_alert(self, title, details_dict, is_emergency=True):
        if not self.webhook_url:
            return False, "No webhook URL configured"

        fields = []
        for k, v in details_dict.items():
            inline = len(str(v)) < 30
            fields.append({
                "name": str(k),
                "value": f"`{v}`",
                "inline": inline
            })

        embed = {
            "title": f"🚨 {title}",
            "description": "Automated threat detection and active quarantine executed.",
            "color": 15158332 if is_emergency else 3066993, # Red or Green
            "fields": fields,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "footer": {
                "text": "PW-Sentry Security Daemon • Active Defense"
            }
        }

        payload = {
            "embeds": [embed]
        }

        return self.send_raw(payload)

    def send_text(self, text):
        if not self.webhook_url:
            return False, "No webhook URL configured"
        payload = {"content": text}
        return self.send_raw(payload)

    def send_raw(self, payload_dict):
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload_dict).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "PW-Sentry-IDS/1.0"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return True, resp.status
        except urllib.error.HTTPError as e:
            return False, f"HTTP Error {e.code}: {e.read().decode('utf-8')}"
        except Exception as e:
            return False, str(e)
