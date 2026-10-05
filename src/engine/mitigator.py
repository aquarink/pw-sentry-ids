#!/usr/bin/env python3
"""
Active Defense & Mitigation Engine for PW-Sentry
Author: Pebri & Antigravity Research Team
"""

import subprocess
import pymysql
import hashlib
import random
import string

class ActiveMitigator:
    def __init__(self, db_config, waha_notifier=None, discord_notifier=None):
        self.db_config = db_config
        self.notifier = waha_notifier
        self.discord_notifier = discord_notifier
        self.quarantined_users = set()
        self.blocked_ips = set()

    def get_db_connection(self):
        return pymysql.connect(
            host=self.db_config.get("host", "127.0.0.1"),
            user=self.db_config.get("user", "root"),
            password=self.db_config.get("password", ""),
            database=self.db_config.get("database", "pw"),
            autocommit=True
        )

    def generate_random_password(self, length=20):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(random.choice(chars) for _ in range(length))

    def ban_account(self, userid, username=None, reason="Malicious Exploit / Policy Violation"):
        if userid in self.quarantined_users:
            return False, "Already quarantined"

        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # 1. Add to forbid table (10 years)
            cursor.callproc("addForbid", (int(userid), 100, 315360000, reason.encode("utf-8")[:255], 0))

            # 2. Get username if not provided
            if not username:
                cursor.execute("SELECT name FROM users WHERE ID=%s", (int(userid),))
                row = cursor.fetchone()
                if row:
                    username = row[0]

            # 3. Scramble password
            new_pass = self.generate_random_password()
            if username:
                md5_hash = hashlib.md5((username + new_pass).encode("utf-8")).digest()
                cursor.execute(
                    "UPDATE users SET passwd=%s, passwd2=%s WHERE ID=%s",
                    (md5_hash, md5_hash, int(userid))
                )

            conn.close()
            self.quarantined_users.add(userid)
            return True, f"User {userid} ({username}) banned and password scrambled."
        except Exception as e:
            return False, f"DB Error: {e}"

    def block_ip(self, ip_str):
        if not ip_str or ip_str in self.blocked_ips:
            return False, "IP already blocked or invalid"

        # Never block localhost or LAN
        if ip_str.startswith("127.") or ip_str.startswith("192.168.") or ip_str.startswith("10."):
            return False, "Skipping private/local IP"

        try:
            # 1. Add to iptables
            subprocess.run(["iptables", "-I", "INPUT", "-s", ip_str, "-j", "DROP"], check=True)
            # 2. Kill existing active sockets
            subprocess.run(["ss", "-K", "dst", ip_str], capture_output=True)

            self.blocked_ips.add(ip_str)
            return True, f"IP {ip_str} blocked in firewall and socket killed."
        except Exception as e:
            return False, f"Firewall Error: {e}"

    def execute_quarantine(self, anomaly_type, userid=None, username=None, roleid=None, ip_str=None, details=None):
        """
        Coordinates full quarantine: MySQL ban, iptables drop, and Dual WhatsApp + Discord notification.
        """
        actions_taken = []

        if userid:
            ban_ok, ban_msg = self.ban_account(userid, username=username, reason=f"PW-Sentry: {anomaly_type}")
            if ban_ok:
                actions_taken.append(f"Account Ban (UID: {userid})")

        if ip_str:
            ip_ok, ip_msg = self.block_ip(ip_str)
            if ip_ok:
                actions_taken.append(f"IP Block ({ip_str})")

        # Prepare Alert Dictionary for Notification
        alert_payload = {
            "Threat Category": anomaly_type,
            "Target UserID": str(userid) if userid else "N/A",
            "Target Username": str(username) if username else "N/A",
            "Target RoleID": str(roleid) if roleid else "N/A",
            "Attacker IP": str(ip_str) if ip_str else "N/A",
            "Mitigation Status": " + ".join(actions_taken) if actions_taken else "Flagged & Logged"
        }

        if details:
            for k, v in details.items():
                alert_payload[k] = str(v)

        # 1. Send via WhatsApp to PROJECT PW group
        if self.notifier:
            try:
                self.notifier.send_alert(
                    f"🚨 THREAT MITIGATED: {anomaly_type}",
                    alert_payload
                )
            except Exception as e:
                print(f"[!] Failed to send WhatsApp alert: {e}")

        # 2. Send via Discord Webhook
        if self.discord_notifier:
            try:
                self.discord_notifier.send_alert(
                    f"THREAT MITIGATED: {anomaly_type}",
                    alert_payload,
                    is_emergency=True
                )
            except Exception as e:
                print(f"[!] Failed to send Discord alert: {e}")

        return True
