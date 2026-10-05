#!/usr/bin/env python3
"""
PW-Sentry: Real-Time Multi-Layer Protocol Anomaly Detection System for MMORPG Servers
Author: Pebri & Antigravity Research Team
License: MIT
"""

import os
import sys
import time
import json
import re
import threading
from datetime import datetime

# ==============================================================================
# Configuration Defaults
# ==============================================================================
DEFAULT_CONFIG = {
    "log_paths": {
        "gs_log": "/home/logs/gs01.log",
        "glink_log": "/home/logs/glink.log",
        "delivery_log": "/home/logs/gdeliveryd.log"
    },
    "thresholds": {
        "rst_spike_per_sec": 50,
        "max_packet_size_init": 60,
        "ewma_alpha": 0.2,
        "burst_window_seconds": 10,
        "burst_limit_per_role": 5
    },
    "alert_log": "/home/pw-sentry-ids/alerts.jsonl"
}

# ==============================================================================
# Layer 4: Kernel Socket & TCP Statistics Collector
# ==============================================================================
class KernelSocketMonitor:
    def __init__(self, spike_threshold=50):
        self.spike_threshold = spike_threshold
        self.last_resets = None
        self.last_time = time.time()

    def get_tcp_snmp(self):
        """Parse /proc/net/snmp for TCP metrics."""
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
        except Exception as e:
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


# ==============================================================================
# Layer 7: Protocol State & Engine Log Stream Parser
# ==============================================================================
class ProtocolLogInspector:
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.role_rpc_counter = {}
        self.lock = threading.Lock()

    def inspect_line(self, source, line):
        # 1. Detect Protocol State or Size Policy Error
        if "Protocol state or size policy error" in line:
            # Pattern: sid=..., type=75, size=10510, acceptsize=60
            match = re.search(r"sid=(\d+),\s*type=(\d+),\s*size=(\d+),\s*acceptsize=(\d+)", line)
            details = {}
            if match:
                details = {
                    "session_id": int(match.group(1)),
                    "packet_type": int(match.group(2)),
                    "actual_size": int(match.group(3)),
                    "accept_size": int(match.group(4))
                }
            self.alert_callback({
                "layer": "L7_PROTOCOL_STATE",
                "type": "PROTOCOL_SIZE_POLICY_VIOLATION",
                "severity": "EMERGENCY",
                "source": source,
                "raw": line.strip(),
                "details": details,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

        # 2. Detect Cascading Gateway Eviction (Drop All Players)
        elif "drop all players" in line or "disconnect from gameserver" in line:
            self.alert_callback({
                "layer": "L7_GATEWAY_SESSION",
                "type": "CASCADING_SESSION_EVICTION",
                "severity": "EMERGENCY",
                "source": source,
                "raw": line.strip(),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

        # 3. Detect Burst of Heavy Bulk RPCs (Auction / Inventory / Mail)
        elif "sysauctiongetitem" in line or "dbgetmaillist" in line:
            match = re.search(r"roleid=(\d+)", line)
            if match:
                role_id = int(match.group(1))
                now = time.time()
                with self.lock:
                    history = self.role_rpc_counter.get(role_id, [])
                    # Keep events within last 10 seconds
                    history = [t for t in history if now - t < 10.0]
                    history.append(now)
                    self.role_rpc_counter[role_id] = history

                    if len(history) >= DEFAULT_CONFIG["thresholds"]["burst_limit_per_role"]:
                        self.alert_callback({
                            "layer": "APP_BEHAVIORAL",
                            "type": "RPC_BURST_FLOODING",
                            "severity": "WARNING",
                            "role_id": role_id,
                            "rpc_count_in_window": len(history),
                            "window_seconds": 10,
                            "raw": line.strip(),
                            "timestamp": datetime.utcnow().isoformat() + "Z"
                        })


# ==============================================================================
# Log Tailer Daemon
# ==============================================================================
def follow_file(filepath, source_tag, inspector):
    if not os.path.exists(filepath):
        return
    with open(filepath, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            inspector.inspect_line(source_tag, line)


# ==============================================================================
# PW-Sentry Core Controller
# ==============================================================================
class PWSentry:
    def __init__(self, config=DEFAULT_CONFIG):
        self.config = config
        self.running = False
        self.socket_monitor = KernelSocketMonitor(
            spike_threshold=config["thresholds"]["rst_spike_per_sec"]
        )
        self.inspector = ProtocolLogInspector(self.dispatch_alert)

    def dispatch_alert(self, alert_data):
        print(f"\n[ALERT - {alert_data.get('severity')}] {alert_data.get('type')}")
        print(f"Timestamp: {alert_data.get('timestamp')}")
        print(f"Payload: {json.dumps(alert_data, indent=2)}")

        # Append to alerts.jsonl
        try:
            os.makedirs(os.path.dirname(self.config["alert_log"]), exist_ok=True)
            with open(self.config["alert_log"], "a") as f:
                f.write(json.dumps(alert_data) + "\n")
        except Exception as e:
            print(f"Failed to write alert log: {e}", file=sys.stderr)

    def start(self):
        self.running = True
        print("=" * 70)
        print("🛡️  PW-Sentry Intrusion & Anomaly Detection System Started")
        print(f"Monitoring L4 Socket Telemetry & L7 Engine Logs")
        print("=" * 70)

        # Start Log Tailers
        for tag, path in self.config["log_paths"].items():
            if os.path.exists(path):
                t = threading.Thread(
                    target=follow_file,
                    args=(path, tag, self.inspector),
                    daemon=True
                )
                t.start()
                print(f"[+] Attached watcher to {tag}: {path}")

        # L4 Polling Loop
        while self.running:
            alert = self.socket_monitor.check_rst_delta()
            if alert:
                self.dispatch_alert(alert)
            time.sleep(1.0)


if __name__ == "__main__":
    sentry = PWSentry()
    try:
        sentry.start()
    except KeyboardInterrupt:
        print("\nStopping PW-Sentry...")
        sys.exit(0)
