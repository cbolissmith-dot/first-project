correlation_engine.py
2025-01-01 10:00:01 AUTH username=john status=FAIL src_ip=192.168.1.10
2025-01-01 10:00:05 AUTH username=john status=FAIL src_ip=192.168.1.10
2025-01-01 10:00:10 AUTH username=john status=FAIL src_ip=192.168.1.10
2025-01-01 10:00:15 AUTH username=john status=SUCCESS src_ip=192.168.1.10
2025-01-01 10:01:00 AUTH username=admin status=FAIL src_ip=10.0.0.5
2025-01-01 10:01:05 AUTH username=admin status=FAIL src_ip=10.0.0.5
2025-01-01 10:01:10 AUTH username=admin status=FAIL src_ip=10.0.0.5
2025-01-01 10:01:15 AUTH username=admin status=FAIL src_ip=10.0.0.5
2025-01-01 10:02:00 ACCESS username=john resource=SERVER01 action=LOGIN src_ip=192.168.1.10
2025-01-01 10:02:30 ACCESS username=john resource=SERVER02 action=LOGIN src_ip=192.168.1.10
2025-01-01 10:03:00 ACCESS username=john resource=SERVER03 action=LOGIN src_ip=192.168.1.10
2025-01-01 10:04:00 AUTH username=service status=SUCCESS src_ip=203.0.113.50
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# ============================================================
# Advanced SOC Correlation & Threat Intelligence Engine
# ------------------------------------------------------------
# Features:
# - Event normalization
# - Brute force detection
# - Suspicious successful login detection
# - Lateral movement pattern detection
# - Threat intelligence enrichment (simulated)
# - Severity scoring
# - Structured incident report output (JSON + human readable)
#
# This is designed to look like something a SOC Lead or
# senior detection engineer might prototype.
# ============================================================

# -----------------------------
# Config / Tuning Parameters
# -----------------------------
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

BRUTE_FORCE_WINDOW_MINUTES = 5
BRUTE_FORCE_THRESHOLD = 3

LATERAL_MOVEMENT_WINDOW_MINUTES = 10
LATERAL_MOVEMENT_RESOURCE_THRESHOLD = 3

SUSPICIOUS_GEO_IPS = {"203.0.113.50", "198.51.100.23"}  # Example "untrusted" IPs
HIGH_RISK_USERS = {"admin", "root", "service"}  # Privileged or service accounts

# Simulated threat intel feed (real world: pulled from API)
THREAT_FEED_MALICIOUS_IPS = {
    "203.0.113.50": {"reputation": "malicious", "source": "ThreatFeedX", "threat_type": "botnet"},
    "198.51.100.23": {"reputation": "suspicious", "source": "ThreatFeedY", "threat_type": "brute_force"},
}

# -----------------------------
# Event Model & Parsing
# -----------------------------
class Event:
    """
    Normalized event object.
    """
    def __init__(self, raw_line, timestamp, event_type, username=None,
                 status=None, src_ip=None, resource=None, action=None):
        self.raw_line = raw_line
        self.timestamp = timestamp
        self.event_type = event_type  # e.g., AUTH, ACCESS
        self.username = username
        self.status = status          # e.g., SUCCESS, FAIL
        self.src_ip = src_ip
        self.resource = resource
        self.action = action          # e.g., LOGIN

    def __repr__(self):
        return f"<Event {self.event_type} {self.timestamp} {self.username} {self.src_ip}>"

def parse_log_line(line):
    """
    Parse a single log line into an Event object.
    Expected format examples:
    2025-01-01 10:00:01 AUTH username=john status=FAIL src_ip=192.168.1.10
    2025-01-01 10:02:00 ACCESS username=john resource=SERVER01 action=LOGIN src_ip=192.168.1.10
    """
    line = line.strip()
    if not line:
        return None

    try:
        # Split timestamp and the rest
        ts_str = " ".join(line.split()[:2])
        timestamp = datetime.strptime(ts_str, TIME_FORMAT)
        remaining = " ".join(line.split()[2:])
    except Exception:
        return None

    # Extract event type (AUTH, ACCESS, etc.)
    parts = remaining.split()
    if not parts:
        return None
    event_type = parts[0].upper()
    kv_pairs = parts[1:]

    fields = {}
    for kv in kv_pairs:
        if "=" in kv:
            k, v = kv.split("=", 1)
            fields[k] = v

    return Event(
        raw_line=line,
        timestamp=timestamp,
        event_type=event_type,
        username=fields.get("username"),
        status=fields.get("status"),
        src_ip=fields.get("src_ip"),
        resource=fields.get("resource"),
        action=fields.get("action"),
    )

def load_events(file_path):
    events = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                evt = parse_log_line(line)
                if evt:
                    events.append(evt)
    except FileNotFoundError:
        print("Error: Log file not found.")
    return events

# -----------------------------
# Threat Intelligence
# -----------------------------
def enrich_with_threat_intel(event):
    """
    Simulated enrichment using a static threat intel feed.
    """
    intel = THREAT_FEED_MALICIOUS_IPS.get(event.src_ip)
    if not intel:
        return {
            "ip_reputation": "unknown",
            "intel_source": None,
            "threat_type": None,
        }
    return {
        "ip_reputation": intel["reputation"],
        "intel_source": intel["source"],
        "threat_type": intel["threat_type"],
    }

# -----------------------------
# Detection Logic
# -----------------------------
class CorrelationEngine:
    """
    Core engine that analyzes events and produces incidents.
    """

    def __init__(self, events):
        self.events = sorted(events, key=lambda e: e.timestamp)
        self.incidents = []

    def run(self):
        self.detect_brute_force()
        self.detect_suspicious_success_logins()
        self.detect_lateral_movement()
        self.sort_incidents_by_severity()
        return self.incidents

    def detect_brute_force(self):
        """
        Detect multiple failed logins from same IP or against same user
        within a time window.
        """
        fails_by_ip = defaultdict(list)
        fails_by_user = defaultdict(list)

        for evt in self.events:
            if evt.event_type == "AUTH" and evt.status == "FAIL":
                fails_by_ip[evt.src_ip].append(evt)
                fails_by_user[evt.username].append(evt)

        # Evaluate patterns
        self._evaluate_brute_force_group(fails_by_ip, by="ip")
        self._evaluate_brute_force_group(fails_by_user, by="user")

    def _evaluate_brute_force_group(self, group_dict, by="ip"):
        for key, events in group_dict.items():
            # Sliding window check
            events = sorted(events, key=lambda e: e.timestamp)
            start_idx = 0
            for end_idx in range(len(events)):
                while (events[end_idx].timestamp - events[start_idx].timestamp >
                       timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)):
                    start_idx += 1
                window_size = end_idx - start_idx + 1
                if window_size >= BRUTE_FORCE_THRESHOLD:
                    related_events = events[start_idx:end_idx + 1]
                    self._add_incident_brute_force(key, related_events, by)

    def _add_incident_brute_force(self, key, events, by):
        first_time = events[0].timestamp
        last_time = events[-1].timestamp
        usernames = {e.username for e in events if e.username}
        src_ips = {e.src_ip for e in events if e.src_ip}

        description = f"Detected potential brute-force attack by {by}='{key}'. " \
                      f"{len(events)} failed login events between {first_time} and {last_time}."

        severity = self._score_severity(
            base=7,
            num_events=len(events),
            high_risk_user=bool(HIGH_RISK_USERS.intersection(usernames)),
            malicious_ip=any(e.src_ip in THREAT_FEED_MALICIOUS_IPS for e in events)
        )

        enriched_events = []
        for e in events:
            intel = enrich_with_threat_intel(e)
            enriched_events.append({
                "timestamp": e.timestamp.strftime(TIME_FORMAT),
                "event_type": e.event_type,
                "username": e.username,
                "src_ip": e.src_ip,
                "status": e.status,
                "threat_intel": intel,
                "raw": e.raw_line,
            })

        incident = {
            "type": "Brute Force",
            "key": key,
            "dimension": by,
            "time_window_start": first_time.strftime(TIME_FORMAT),
            "time_window_end": last_time.strftime(TIME_FORMAT),
            "usernames": list(usernames),
            "src_ips": list(src_ips),
            "event_count": len(events),
            "severity": severity,
            "description": description,
            "events": enriched_events,
        }
        self.incidents.append(incident)

    def detect_suspicious_success_logins(self):
        """
        Detect successful logins from suspicious IPs or for high-risk users.
        """
        for evt in self.events:
            if evt.event_type == "AUTH" and evt.status == "SUCCESS":
                intel = enrich_with_threat_intel(evt)
                is_suspicious_ip = evt.src_ip in SUSPICIOUS_GEO_IPS or intel["ip_reputation"] != "unknown"
                is_high_risk_user = evt.username in HIGH_RISK_USERS

                if is_suspicious_ip or is_high_risk_user:
                    severity = self._score_severity(
                        base=6,
                        num_events=1,
                        high_risk_user=is_high_risk_user,
                        malicious_ip=is_suspicious_ip or intel["ip_reputation"] == "malicious"
                    )
                    description = (
                        f"Suspicious successful login for user='{evt.username}' from IP='{evt.src_ip}'. "
                        f"High-risk user: {is_high_risk_user}, Suspicious IP: {is_suspicious_ip}."
                    )

                    incident = {
                        "type": "Suspicious Successful Login",
                        "time": evt.timestamp.strftime(TIME_FORMAT),
                        "username": evt.username,
                        "src_ip": evt.src_ip,
                        "severity": severity,
                        "description": description,
                        "threat_intel": intel,
                        "event": {
                            "timestamp": evt.timestamp.strftime(TIME_FORMAT),
                            "event_type": evt.event_type,
                            "status": evt.status,
                            "raw": evt.raw_line,
                        },
                    }
                    self.incidents.append(incident)

    def detect_lateral_movement(self):
        """
        Detect a single user accessing many resources in a short time
        from the same IP (possible lateral movement).
        """
        # Group ACCESS events by (username, src_ip)
        access_by_user_ip = defaultdict(list)
        for evt in self.events:
            if evt.event_type == "ACCESS" and evt.action == "LOGIN":
                key = (evt.username, evt.src_ip)
                access_by_user_ip[key].append(evt)

        for (username, src_ip), events in access_by_user_ip.items():
            events = sorted(events, key=lambda e: e.timestamp)
            start_idx = 0
            for end_idx in range(len(events)):
                while (events[end_idx].timestamp - events[start_idx].timestamp >
                       timedelta(minutes=LATERAL_MOVEMENT_WINDOW_MINUTES)):
                    start_idx += 1
                window_events = events[start_idx:end_idx + 1]
                resources = {e.resource for e in window_events if e.resource}
                if len(resources) >= LATERAL_MOVEMENT_RESOURCE_THRESHOLD:
                    self._add_incident_lateral_movement(username, src_ip, window_events, resources)

    def _add_incident_lateral_movement(self, username, src_ip, events, resources):
        first_time = events[0].timestamp
        last_time = events[-1].timestamp

        intel = enrich_with_threat_intel(events[0])
        severity = self._score_severity(
            base=8,
            num_events=len(events),
            high_risk_user=username in HIGH_RISK_USERS,
            malicious_ip=intel["ip_reputation"] != "unknown"
        )

        description = (
            f"Possible lateral movement: user='{username}' accessed {len(resources)} resources from "
            f"IP='{src_ip}' between {first_time} and {last_time}."
        )

        enriched_events = []
        for e in events:
            ev_intel = enrich_with_threat_intel(e)
            enriched_events.append({
                "timestamp": e.timestamp.strftime(TIME_FORMAT),
                "event_type": e.event_type,
                "username": e.username,
                "src_ip": e.src_ip,
                "resource": e.resource,
                "action": e.action,
                "threat_intel": ev_intel,
                "raw": e.raw_line,
            })

        incident = {
            "type": "Lateral Movement",
            "time_window_start": first_time.strftime(TIME_FORMAT),
            "time_window_end": last_time.strftime(TIME_FORMAT),
            "username": username,
            "src_ip": src_ip,
            "resources": list(resources),
            "event_count": len(events),
            "severity": severity,
            "description": description,
            "threat_intel": intel,
            "events": enriched_events,
        }
        self.incidents.append(incident)

    @staticmethod
    def _score_severity(base, num_events, high_risk_user=False, malicious_ip=False):
        severity = base
        if num_events > 5:
            severity += 1
        if num_events > 10:
            severity += 1
        if high_risk_user:
            severity += 1
        if malicious_ip:
            severity += 1
        return min(severity, 10)

    def sort_incidents_by_severity(self):
        self.incidents.sort(key=lambda i: i.get("severity", 0), reverse=True)

# -----------------------------
# Reporting
# -----------------------------
def print_human_readable_report(incidents):
    print("\n================ SOC INCIDENT REPORT ================\n")
    if not incidents:
        print("No incidents detected. Environment appears clean (based on current rules).")
        return

    for idx, inc in enumerate(incidents, 1):
        print(f"--- Incident {idx} ---")
        print(f"Type:       {inc.get('type')}")
        print(f"Severity:   {inc.get('severity')}")
        print(f"Description:\n  {inc.get('description')}\n")

        if inc["type"] == "Brute Force":
            print(f"Dimension:  {inc.get('dimension')} = {inc.get('key')}")
            print(f"Time window: {inc.get('time_window_start')}  →  {inc.get('time_window_end')}")
            print(f"Users:      {', '.join(inc.get('usernames', [])) or 'N/A'}")
            print(f"Source IPs: {', '.join(inc.get('src_ips', [])) or 'N/A'}")
            print(f"Events:     {inc.get('event_count')}")
        elif inc["type"] == "Suspicious Successful Login":
            print(f"Time:       {inc.get('time')}")
            print(f"User:       {inc.get('username')}")
            print(f"Source IP:  {inc.get('src_ip')}")
            ti = inc.get("threat_intel", {})
            print(f"IP Reputation: {ti.get('ip_reputation')} (source={ti.get('intel_source')})")
        elif inc["type"] == "Lateral Movement":
            print(f"Time window: {inc.get('time_window_start')}  →  {inc.get('time_window_end')}")
            print(f"User:       {inc.get('username')}")
            print(f"Source IP:  {inc.get('src_ip')}")
            print(f"Resources:  {', '.join(inc.get('resources', []))}")
            print(f"Events:     {inc.get('event_count')}")

        print("\nSample Events:")
        for e in inc.get("events", [])[:5]:
            print(f"  [{e['timestamp']}] {e['event_type']} user={e.get('username')} "
                  f"ip={e.get('src_ip')} res={e.get('resource')} status={e.get('status')}")
        print()

def save_json_report(incidents, output_path="incident_report.json"):
    with open(output_path, "w") as f:
        json.dump(incidents, f, indent=2, default=str)
    print(f"JSON report saved to: {output_path}")

# -----------------------------
# Main
# -----------------------------
def main():
    print("Advanced SOC Correlation & Threat Intelligence Engine")
    print("------------------------------------------------------")
    log_path = input("Enter path to log file: ").strip()
    events = load_events(log_path)

    if not events:
        print("No events loaded. Exiting.")
        return

    engine = CorrelationEngine(events)
    incidents = engine.run()

    print_human_readable_report(incidents)
    save_json_report(incidents)

if __name__ == "__main__":
    main()
