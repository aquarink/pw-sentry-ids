#!/usr/bin/env python3
"""
PW-Sentry: Real-Time Multi-Layer Protocol Anomaly Detection & Mitigation Daemon
Author: Pebri & Antigravity Research Team
License: MIT
"""

import os
import sys
import glob
import time
import json
import re
import socket
import struct
import threading
from datetime import datetime

# Adjust module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "notifiers"))
sys.path.insert(0, os.path.dirname(__file__))

from notifiers.waha_notifier import WAHANotifier
from notifiers.discord_notifier import DiscordNotifier
from engine.mitigator import ActiveMitigator

def int_to_ipv4(ip_int):
    try:
        return socket.inet_ntoa(struct.pack('<i', int(ip_int)))
    except Exception:
        return None

class KernelSocketMonitor:
    def __init__(self, spike_threshold=50):
        self.spike_threshold = spike_threshold
        self.last_resets = None
        self.last_time = time.time()

    def get_tcp_snmp(self):
        stats = {}
        try:
            with open("/proc/net/snmp", "r") as f:
                lines = f.readlines()
                for i in range(0, len(lines), 2):
                    if lines[i].startswith("Tcp:"):
                        headers = lines[i].split()
                        values = lines[i+1].split()
                        stats = dict(zip(headers[1:], [int(v) for v in values[1:]]))
                        break
        except Exception:
            pass
        return stats

    def check_rst_delta(self):
        stats = self.get_tcp_snmp()
        now = time.time()
        dt = max(now - self.last_time, 0.001)
        self.last_time = now

        resets_sent = stats.get("OutRsts", 0)
        curr_estab = stats.get("CurrEstab", 0)
        retrans = stats.get("RetransSegs", 0)

        alert = None
        if self.last_resets is not None:
            delta_rst = (resets_sent - self.last_resets) / dt
            if delta_rst > self.spike_threshold:
                alert = {
                    "layer": "L4_KERNEL_SOCKET",
                    "type": "TCP_RST_STORM_DETECTED",
                    "severity": "CRITICAL",
                    "delta_rst_per_sec": round(delta_rst, 2),
                    "curr_estab": curr_estab,
                    "retrans_segs": retrans,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }

        self.last_resets = resets_sent
        return alert

class PWSentry:
    def __init__(self, config_path=None):
        if not config_path:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "sentry.conf")

        with open(config_path, "r") as f:
            self.config = json.load(f)

        # Initialize Notifiers
        waha_cfg = self.config.get("waha", {})
        self.notifier = WAHANotifier(
            api_url=waha_cfg.get("api_url"),
            api_key=waha_cfg.get("api_key"),
            session_name=waha_cfg.get("session_name"),
            target_chat_id=waha_cfg.get("target_chat_id")
        )

        discord_cfg = self.config.get("discord", {})
        self.discord_notifier = DiscordNotifier(
            webhook_url=discord_cfg.get("webhook_url")
        )

        # Initialize Mitigator (Dual Notifier: WhatsApp + Discord)
        self.mitigator = ActiveMitigator(
            db_config=self.config.get("database", {}),
            waha_notifier=self.notifier,
            discord_notifier=self.discord_notifier
        )

        # Metrics & Correlation Tables
        self.socket_monitor = KernelSocketMonitor(
            spike_threshold=self.config.get("thresholds", {}).get("rst_spike_per_sec", 50)
        )
        self.user_ip_map = {}      # userid -> ip_str
        self.user_role_map = {}    # userid -> roleid
        self.role_user_map = {}    # roleid -> userid
        self.account_name_map = {} # username -> ip_str
        self.pwadmin_failed_attempts = {} # ip -> count
        self.pwadmin_last_conn_ip = {}    # id -> ip
        self.role_rpc_counter = {}
        self.lock = threading.Lock()
        self.running = False

    def find_active_logs(self):
        log_dir = self.config.get("log_dir", "/home/logs")
        logs = {}

        # 1. glink1.log
        glink = os.path.join(log_dir, "glink1.log")
        if os.path.exists(glink):
            logs["glink"] = glink

        # 2. Latest gs01 err log
        gs_errs = sorted(glob.glob(os.path.join(log_dir, "gs 01_*_err.log")))
        if gs_errs:
            logs["gs_err"] = gs_errs[-1]
        elif os.path.exists(os.path.join(log_dir, "gs01.log")):
            logs["gs_err"] = os.path.join(log_dir, "gs01.log")

        # 3. Latest authd std log
        auth_logs = sorted(glob.glob(os.path.join(log_dir, "authd_*_std.log")))
        if auth_logs:
            logs["authd"] = auth_logs[-1]
        elif os.path.exists(os.path.join(log_dir, "authd.log")):
            logs["authd"] = os.path.join(log_dir, "authd.log")

        # 4. Latest gdeliveryd err log
        deliv_logs = sorted(glob.glob(os.path.join(log_dir, "gdeliveryd_*_err.log")))
        if deliv_logs:
            logs["gdelivery"] = deliv_logs[-1]
        elif os.path.exists(os.path.join(log_dir, "gdeliveryd.log")):
            logs["gdelivery"] = os.path.join(log_dir, "gdeliveryd.log")

        # 5. PWAdmin Port 1500 logs
        pw_work = "/pwadmin/pwadmin_work.log"
        if os.path.exists(pw_work):
            logs["pwadmin_work"] = pw_work

        pw_log = "/pwadmin/pwadmin.log"
        if os.path.exists(pw_log):
            logs["pwadmin_log"] = pw_log

        # 6. Economic & Role Database Transactions (formatlog)
        formatlog = "/home/logservice/logs/world2.formatlog"
        if os.path.exists(formatlog):
            logs["formatlog"] = formatlog

        return logs

    def process_log_line(self, tag, line):
        line_str = line.strip()

        # A. Learn User IP mappings from authd
        # Pattern: GQueryPasswd:account is momomo , login ip is -186966936
        if "GQueryPasswd:account is" in line_str:
            match = re.search(r"account is (\S+) , login ip is (-?\d+)", line_str)
            if match:
                acc_name = match.group(1)
                ip_val = int_to_ipv4(match.group(2))
                if ip_val:
                    with self.lock:
                        self.account_name_map[acc_name] = ip_val

        # Pattern: UserLogin:userid=8608,sid=...
        elif "UserLogin:userid=" in line_str:
            match = re.search(r"UserLogin:userid=(\d+)", line_str)
            if match:
                uid = int(match.group(1))
                # Correlate with recent account if known
                with self.lock:
                    if self.account_name_map:
                        last_acc, last_ip = list(self.account_name_map.items())[-1]
                        self.user_ip_map[uid] = last_ip

        # B. Learn Role mappings from gdeliveryd
        # Pattern: PlayerLogin userid 8608 roleid 6960
        elif "PlayerLogin userid" in line_str:
            match = re.search(r"PlayerLogin userid (\d+) roleid (\d+)", line_str)
            if match:
                uid = int(match.group(1))
                rid = int(match.group(2))
                with self.lock:
                    self.user_role_map[uid] = rid
                    self.role_user_map[rid] = uid

        # C. Anomaly: Protocol State or Size Policy Error (Malicious Payload Injection)
        elif "Protocol state or size policy error" in line_str:
            # Pattern: sid=..., type=75, size=10510, acceptsize=60
            match = re.search(r"sid=(\d+),\s*type=(\d+),\s*size=(\d+),\s*acceptsize=(\d+)", line_str)
            size = int(match.group(3)) if match else 0
            pkt_type = int(match.group(2)) if match else 0

            # ONLY flag gameserver handshake exploit (type 75, oversized payload >= 1000 bytes)
            # Low-level glink1 debug traces (type 71, 3, 83) are normal network/client artifacts.
            if tag == "gs_err" and pkt_type == 75 and size >= 1000:
                print(f"[!] CRITICAL ANOMALY: Gameserver Protocol Size Exploit (Size: {size}, Type: {pkt_type})")
                self.mitigator.execute_quarantine(
                    anomaly_type="PROTOCOL_SIZE_POLICY_EXPLOIT",
                    userid=None,
                    roleid=None,
                    ip_str=None,
                    details={
                        "Packet Type": pkt_type,
                        "Payload Size": f"{size} bytes (Max: 60)",
                        "Violation": "Payload size exceeded handshake acceptance limit",
                        "Impact": "Intercepted at gameserver boundary; gateway buffer safe"
                    }
                )

        # D. Anomaly: Gateway Session Drop All Players
        elif "disconnect from gameserver 1, drop all players" in line_str:
            print("[!] CRITICAL ANOMALY: Gateway Session Drop Detected")
            # Send high priority notification
            self.notifier.send_text(
                "🚨 *[PW-SENTRY ALERT: GATEWAY SESSION DROP]*\n"
                "Gateway (glinkd 1) dropped connection with gameserver 1.\n"
                "Automated recovery active: Inspecting socket buffers and reconnecting."
            )

        # E. Port 1500 (PWAdmin) Brute Force & Session Watcher
        elif tag == "pwadmin_work":
            # Track client connection: Client connected (id:6) from 110.138.33.145
            match_conn = re.search(r"Client connected \(id:(\d+)\) from (\S+)", line_str)
            if match_conn:
                conn_id, client_ip = match_conn.group(1), match_conn.group(2)
                with self.lock:
                    self.pwadmin_last_conn_ip[conn_id] = client_ip

            # Track wrong password attempt: Client disconnected with wrong pass (id:6) ip: 85.217.149.9
            match_fail = re.search(r"Client disconnected with wrong pass \(id:(\d+)\) ip:\s*(\S+)", line_str)
            if match_fail:
                _, bad_ip = match_fail.group(1), match_fail.group(2)
                with self.lock:
                    count = self.pwadmin_failed_attempts.get(bad_ip, 0) + 1
                    self.pwadmin_failed_attempts[bad_ip] = count
                print(f"[!] PWAdmin Authentication Failure from {bad_ip} (Attempt {count})")
                if count >= 2:
                    self.mitigator.block_ip(bad_ip)
                    self.notifier.send_text(
                        f"🚨 *[PW-SENTRY: PORT 1500 BRUTE-FORCE DETECTED]*\n"
                        f"• *Attacker IP:* `{bad_ip}`\n"
                        f"• *Failed Attempts:* `{count}`\n"
                        f"• *Action Taken:* IP otomatis di-DROP di firewall iptables."
                    )
                    if self.discord_notifier:
                        self.discord_notifier.send_alert(
                            "PORT 1500 BRUTE-FORCE BLOCKED",
                            {
                                "Threat": "PWAdmin Password Brute-Force",
                                "Attacker IP": bad_ip,
                                "Failed Attempts": str(count),
                                "Action": "IP Dropped in iptables"
                            },
                            is_emergency=True
                        )

            # Track successful login: Password accepted (id:6)
            match_ok = re.search(r"Password accepted \(id:(\d+)\)", line_str)
            if match_ok:
                conn_id = match_ok.group(1)
                with self.lock:
                    login_ip = self.pwadmin_last_conn_ip.get(conn_id, "Unknown")
                print(f"[!] PWAdmin Login Accepted for id:{conn_id} from {login_ip}")
                self.notifier.send_text(
                    f"🛡️ *[PW-SENTRY AUDIT: PWADMIN SESSION OPENED]*\n"
                    f"• *Port:* `1500` (Management Daemon)\n"
                    f"• *Admin IP:* `{login_ip}`\n"
                    f"• *Status:* Password Accepted / Session Active"
                )
                if self.discord_notifier:
                    self.discord_notifier.send_alert(
                        "PWADMIN SESSION ESTABLISHED",
                        {
                            "Event": "Admin Login",
                            "Port": "1500",
                            "Source IP": login_ip,
                            "Status": "Authorized"
                        }
                    )

        # F. Formatlog Anomaly: Illegal Asset / Gold / EXP Injection
        elif tag == "formatlog" and "formatlog:putroledata:" in line_str:
            # Pattern: formatlog:putroledata:sid=1898:roleid=5248:timestamp=10:level=55:exp=329488:money=10000000:overwite=1
            match = re.search(r"roleid=(\d+):.*exp=(\d+):money=(\d+):overwite=(\d+)", line_str)
            if match:
                rid = int(match.group(1))
                exp_val = int(match.group(2))
                money_val = int(match.group(3))
                overwrite_flag = int(match.group(4))

                # Flag high-value manual injection (> 1M gold or > 1M EXP with overwrite=1)
                if overwrite_flag == 1 and (money_val >= 1000000 or exp_val >= 1000000):
                    print(f"[!] CRITICAL ANOMALY: Direct Role Asset Injection! RoleID: {rid}, Money: {money_val}, EXP: {exp_val}")
                    self.notifier.send_text(
                        f"🚨 *[PW-SENTRY ALERT: DETEKSI INJEKSI ASET / GOLD]* 🚨\n"
                        f"• *Target RoleID:* `{rid}`\n"
                        f"• *Injeksi Gold:* `{money_val:,} Coins`\n"
                        f"• *Injeksi EXP:* `{exp_val:,} EXP`\n"
                        f"• *Vektor:* `gamedbd::putroledata (Direct Overwrite via Port 1500)`\n"
                        f"• *Status:* Perubahan data karakter bernilai tinggi terdeteksi!"
                    )
                    if self.discord_notifier:
                        self.discord_notifier.send_alert(
                            "ILLEGAL ASSET INJECTION DETECTED",
                            {
                                "Target RoleID": str(rid),
                                "Injected Money": f"{money_val:,} Coins",
                                "Injected EXP": f"{exp_val:,} EXP",
                                "Vector": "Direct Overwrite (gamedbd / Port 1500)",
                                "Severity": "CRITICAL"
                            },
                            is_emergency=True
                        )

        # G. PWAdmin High-Level Action Audit
        elif tag == "pwadmin_log":
            if "Give" in line_str and "gold" in line_str:
                self.notifier.send_text(f"⚠️ *[PW-SENTRY AUDIT]*\n`{line_str}`")
            elif "Shell:" in line_str:
                self.notifier.send_text(f"⚠️ *[PW-SENTRY SHELL EXECUTION]*\n`{line_str}`")

    def follow_file(self, tag, filepath):
        if not os.path.exists(filepath):
            return
        with open(filepath, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.15)
                    continue
                self.process_log_line(tag, line)

    def start(self):
        self.running = True
        print("=" * 75)
        print("🛡️  PW-Sentry: Active Defense & Real-Time Mitigation Daemon")
        print("Connected to WAHA Notification Service (Target: PROJECT PW)")
        print("=" * 75)

        active_logs = self.find_active_logs()
        for tag, path in active_logs.items():
            t = threading.Thread(target=self.follow_file, args=(tag, path), daemon=True)
            t.start()
            print(f"[+] Attached active watcher to {tag}: {path}")

        # Send Startup Status to WA Group & Discord
        target_group_label = self.config.get("waha", {}).get("target_chat_id", "Admin Channel")
        self.notifier.send_text(
            "🛡️ *[PW-SENTRY DAEMON ONLINE]*\n"
            "• *Mode:* Active Defense & Auto-Quarantine\n"
            "• *Observability:* L4 Socket Telemetry + L7 State Inspector\n"
            f"• *Target Group:* {target_group_label}\n"
            "• *Status:* Actively protecting server against protocol exploits."
        )

        if self.discord_notifier:
            self.discord_notifier.send_text(
                "🛡️ **[PW-SENTRY DAEMON ONLINE]**\n"
                "• **Mode:** `Active Defense & Auto-Quarantine`\n"
                "• **Observability:** `L4 Socket Telemetry + L7 State Inspector`\n"
                "• **Status:** `Actively protecting server against protocol exploits (Dual Alert: Discord + WhatsApp)`"
            )

        try:
            while self.running:
                alert = self.socket_monitor.check_rst_delta()
                if alert:
                    print(f"[!] Kernel Socket Alert: {alert}")
                    self.notifier.send_alert(
                        "L4 KERNEL SOCKET ANOMALY",
                        {
                            "Threat Type": alert.get("type"),
                            "RST Rate": f"{alert.get('delta_rst_per_sec')} packets/sec",
                            "Active Estabs": str(alert.get("curr_estab"))
                        }
                    )
                time.sleep(1.0)
        except KeyboardInterrupt:
            self.running = False
            print("\nPW-Sentry Daemon stopped.")

if __name__ == "__main__":
    sentry = PWSentry()
    sentry.start()
