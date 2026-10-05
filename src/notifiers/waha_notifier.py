#!/usr/bin/env python3
"""
WAHA (WhatsApp HTTP API) Notifier for PW-Sentry
Author: Pebri & Antigravity Research Team
"""

import json
import urllib.request
import urllib.error

class WAHANotifier:
    def __init__(self, api_url, api_key, session_name, target_chat_id):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.session_name = session_name
        self.target_chat_id = target_chat_id

    def send_alert(self, title, details_dict):
        """
        Format and send a structured security alert to the WhatsApp group.
        """
        lines = [
            f"🚨 *[PW-SENTRY SECURITY ALERT]* 🚨",
            f"*{title}*",
            "━━━━━━━━━━━━━━━━━━━━━━"
        ]

        for k, v in details_dict.items():
            lines.append(f"• *{k}:* `{v}`")

        lines.append("━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("🛡️ _Action Taken: Auto-Quarantine, Account Banned & IP Dropped._")

        message_text = "\n".join(lines)
        return self.send_text(message_text)

    def send_text(self, text):
        endpoint = f"{self.api_url}/api/sendText"
        payload = {
            "session": self.session_name,
            "chatId": self.target_chat_id,
            "text": text
        }

        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": self.api_key
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = resp.read().decode("utf-8")
                return True, result
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8")
            return False, f"HTTP Error {e.code}: {err_msg}"
        except Exception as e:
            return False, str(e)
