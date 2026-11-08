"""Generate the IRIS synthetic dataset.

Outputs (in the folder given as the first argument, default ./iris_dataset):
  asset_inventory.json    535 assets
  risk_register.json      2,000+ risks linked to assets and controls
  security_controls.json  120 controls mapped to NIST CSF 2.0 and MITRE ATT&CK
  siem_alerts.json        5,000+ Wazuh/Suricata alerts linked to assets, risks and controls
  siem_alerts.jsonl       the same alerts, one JSON object per line
  training_labels.json    offline session labels (sidecar, never a runtime input)
  dataset_manifest.json   counts, time window, checksums and notes

All records are synthetic. The generator is deterministic for a given seed.
"""
import hashlib
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone

SEED = 481
OUT = sys.argv[1] if len(sys.argv) > 1 else "iris_dataset"
rng = random.Random(SEED)

WINDOW_START = datetime(2026, 9, 28, 0, 0, 0, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 10, 28, 0, 0, 0, tzinfo=timezone.utc)
GENERATED_AT = "2026-10-28T05:00:00Z"
DOMAIN = "corp.example"


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def day(dt):
    return dt.strftime("%Y-%m-%d")


# ---------------------------------------------------------------- controls
# (family, name, type, NIST CSF 2.0 category, ATT&CK techniques, applies-to groups)
CONTROL_SPECS = {
    "IAM": ("Identity and access", [
        ("Enforce MFA for privileged accounts", "Preventive", "PR.AA", ["T1078", "T1110"], ["identity", "server"]),
        ("Enforce MFA for remote access (VPN)", "Preventive", "PR.AA", ["T1078", "T1110", "T1133"], ["network"]),
        ("Account lockout after 5 failed logins", "Preventive", "PR.AA", ["T1110.001", "T1110.003"], ["all"]),
        ("Quarterly privileged access review", "Detective", "PR.AA", ["T1078", "T1098"], ["identity", "server"]),
        ("Privileged access management vault", "Preventive", "PR.AA", ["T1078", "T1003"], ["identity", "server"]),
        ("Just-in-time administrative access", "Preventive", "PR.AA", ["T1078"], ["server", "cloud"]),
        ("Local administrator password solution (LAPS)", "Preventive", "PR.AA", ["T1078.003", "T1021.002"], ["endpoint", "server"]),
        ("Service account password rotation (90 days)", "Preventive", "PR.AA", ["T1558.003", "T1078"], ["identity"]),
        ("Enforce AES-only Kerberos encryption", "Preventive", "PR.PS", ["T1558.003"], ["identity"]),
        ("Disable NTLMv1 and legacy authentication", "Preventive", "PR.PS", ["T1110", "T1557"], ["identity", "endpoint"]),
        ("Joiner-mover-leaver account process", "Directive", "PR.AA", ["T1078"], ["all"]),
        ("Password policy (14+ characters, banned-password list)", "Preventive", "PR.AA", ["T1110"], ["all"]),
    ]),
    "NET": ("Network security", [
        ("Segment the network zone", "Preventive", "PR.IR", ["T1046", "T1021"], ["all"]),
        ("Restrict inbound management ports", "Preventive", "PR.IR", ["T1046", "T1021.001", "T1133"], ["server", "network"]),
        ("Tune IDS scan signatures", "Detective", "DE.CM", ["T1046", "T1595"], ["network", "server"]),
        ("IPS blocking for known scanners", "Preventive", "PR.IR", ["T1595", "T1190"], ["network", "web"]),
        ("Restrict DNS zone transfers", "Preventive", "PR.PS", ["T1590.002"], ["network", "identity"]),
        ("Network access control (802.1X)", "Preventive", "PR.AA", ["T1200"], ["endpoint", "iot", "network"]),
        ("Egress filtering by allowlist", "Preventive", "PR.IR", ["T1048", "T1071"], ["server", "cloud"]),
        ("Web application firewall", "Preventive", "PR.IR", ["T1190", "T1595.002"], ["web"]),
        ("VPN geo-restriction and IP reputation filtering", "Preventive", "PR.AA", ["T1133", "T1110.003"], ["network"]),
        ("East-west firewall rules between server tiers", "Preventive", "PR.IR", ["T1021", "T1046"], ["server"]),
        ("DDoS protection service", "Preventive", "PR.IR", ["T1498"], ["web", "network"]),
        ("Rate limiting on authentication endpoints", "Preventive", "PR.PS", ["T1110"], ["web", "network"]),
    ]),
    "VUL": ("Vulnerability and configuration", [
        ("Monthly patch cycle", "Corrective", "PR.PS", ["T1190", "T1068"], ["all"]),
        ("Critical patch SLA (14 days)", "Corrective", "PR.PS", ["T1190"], ["all"]),
        ("Authenticated vulnerability scanning (weekly)", "Detective", "ID.RA", ["T1190", "T1068"], ["all"]),
        ("External attack surface scanning", "Detective", "ID.RA", ["T1595", "T1190"], ["web", "network"]),
        ("CIS hardened baseline configuration", "Preventive", "PR.PS", ["T1046", "T1021"], ["server", "endpoint"]),
        ("Disable unused services and ports", "Preventive", "PR.PS", ["T1046"], ["server", "iot"]),
        ("Hardened golden images", "Preventive", "PR.PS", ["T1190"], ["cloud", "server"]),
        ("Configuration drift monitoring", "Detective", "DE.CM", ["T1098"], ["server", "cloud"]),
        ("Firmware update program for devices", "Corrective", "PR.PS", ["T1190"], ["iot", "network"]),
        ("Change default device credentials", "Preventive", "PR.AA", ["T1078.001"], ["iot", "network"]),
        ("Secure software development review", "Preventive", "PR.PS", ["T1190"], ["web"]),
        ("Database hardening and least-privilege roles", "Preventive", "PR.PS", ["T1190", "T1078"], ["db"]),
    ]),
    "MON": ("Logging and monitoring", [
        ("Centralized log collection to SIEM", "Detective", "DE.CM", ["T1110", "T1046"], ["all"]),
        ("Alert on repeated failed logons", "Detective", "DE.CM", ["T1110"], ["all"]),
        ("Alert on logon success after failures", "Detective", "DE.AE", ["T1110", "T1078"], ["all"]),
        ("Impossible-travel sign-in detection", "Detective", "DE.AE", ["T1078"], ["identity", "network"]),
        ("Kerberos service ticket anomaly detection", "Detective", "DE.AE", ["T1558.003"], ["identity"]),
        ("Port-scan threshold detection", "Detective", "DE.CM", ["T1046", "T1595"], ["network", "server"]),
        ("File integrity monitoring", "Detective", "DE.CM", ["T1565"], ["server"]),
        ("User and entity behavior analytics", "Detective", "DE.AE", ["T1078"], ["all"]),
        ("Honeytoken accounts", "Detective", "DE.CM", ["T1087", "T1110"], ["identity"]),
        ("Security log retention (12 months)", "Directive", "PR.PS", [], ["all"]),
        ("NTP time synchronization", "Preventive", "PR.PS", [], ["all"]),
        ("Quarterly SIEM use-case review", "Detective", "DE.AE", ["T1110", "T1046"], ["all"]),
    ]),
    "DAT": ("Data protection", [
        ("Encryption at rest (AES-256)", "Preventive", "PR.DS", ["T1005", "T1530"], ["server", "db", "cloud", "endpoint"]),
        ("TLS 1.2 or later for data in transit", "Preventive", "PR.DS", ["T1557", "T1040"], ["all"]),
        ("Data loss prevention", "Detective", "PR.DS", ["T1048", "T1567"], ["endpoint", "server"]),
        ("Daily backups (3-2-1 rule)", "Corrective", "PR.DS", ["T1486", "T1490"], ["server", "db"]),
        ("Immutable offline backup copy", "Corrective", "PR.DS", ["T1486", "T1490"], ["server", "db"]),
        ("Quarterly backup restore testing", "Corrective", "RC.RP", ["T1486"], ["server", "db"]),
        ("Data classification and labeling", "Directive", "ID.AM", ["T1048"], ["all"]),
        ("Key management service", "Preventive", "PR.DS", ["T1552"], ["cloud", "server"]),
        ("Database activity monitoring", "Detective", "DE.CM", ["T1005", "T1213"], ["db"]),
        ("Secure file transfer only (SFTP)", "Preventive", "PR.DS", ["T1040"], ["server"]),
        ("Data retention and disposal schedule", "Directive", "PR.DS", ["T1005"], ["all"]),
        ("Approval for restricted data access", "Preventive", "PR.AA", ["T1213"], ["db", "server"]),
    ]),
    "END": ("Endpoint security", [
        ("Endpoint detection and response (EDR)", "Detective", "DE.CM", ["T1059.001", "T1003", "T1486"], ["endpoint", "server"]),
        ("Next-generation antivirus", "Preventive", "PR.PS", ["T1204"], ["endpoint", "server"]),
        ("Application allowlisting", "Preventive", "PR.PS", ["T1204", "T1059"], ["endpoint", "server"]),
        ("Remove local administrator rights", "Preventive", "PR.AA", ["T1068", "T1078.003"], ["endpoint"]),
        ("Block Office macros from the internet", "Preventive", "PR.PS", ["T1204.002", "T1566.001"], ["endpoint"]),
        ("USB storage control", "Preventive", "PR.PS", ["T1091", "T1052"], ["endpoint"]),
        ("Full disk encryption", "Preventive", "PR.DS", ["T1005"], ["endpoint"]),
        ("LSASS protection (Credential Guard)", "Preventive", "PR.PS", ["T1003.001"], ["endpoint", "identity"]),
        ("PowerShell logging and constrained language mode", "Detective", "DE.CM", ["T1059.001"], ["endpoint", "server"]),
        ("Browser hardening and isolation", "Preventive", "PR.PS", ["T1189"], ["endpoint"]),
        ("Host firewall enabled", "Preventive", "PR.IR", ["T1021", "T1046"], ["endpoint", "server"]),
        ("Mobile device management", "Preventive", "PR.PS", ["T1078"], ["endpoint"]),
    ]),
    "CLD": ("Cloud and container", [
        ("Cloud security posture management", "Detective", "DE.CM", ["T1530", "T1078.004"], ["cloud"]),
        ("Least-privilege cloud IAM roles", "Preventive", "PR.AA", ["T1078.004"], ["cloud"]),
        ("Monthly security group review", "Detective", "PR.IR", ["T1046", "T1190"], ["cloud"]),
        ("Container image scanning", "Detective", "ID.RA", ["T1610", "T1190"], ["cloud"]),
        ("Kubernetes RBAC and namespace isolation", "Preventive", "PR.AA", ["T1611", "T1078"], ["cloud"]),
        ("Secrets management vault", "Preventive", "PR.DS", ["T1552"], ["cloud", "server"]),
        ("Block public storage buckets", "Preventive", "PR.DS", ["T1530"], ["cloud"]),
        ("Cloud audit logging enabled", "Detective", "DE.CM", ["T1078.004"], ["cloud"]),
        ("Runtime container security monitoring", "Detective", "DE.CM", ["T1610", "T1611"], ["cloud"]),
        ("Infrastructure-as-code security checks", "Preventive", "PR.PS", ["T1190"], ["cloud"]),
        ("Private endpoints for data services", "Preventive", "PR.IR", ["T1530"], ["cloud", "db"]),
        ("Cloud workload backup policy", "Corrective", "PR.DS", ["T1485", "T1490"], ["cloud"]),
    ]),
    "GOV": ("Governance and awareness", [
        ("Information security policy (annual review)", "Directive", "GV.PO", [], ["all"]),
        ("Annual risk assessment", "Directive", "ID.RA", [], ["all"]),
        ("Security awareness training", "Directive", "PR.AT", ["T1566", "T1078"], ["all"]),
        ("Quarterly phishing simulation", "Directive", "PR.AT", ["T1566"], ["endpoint"]),
        ("Third-party access review", "Detective", "GV.SC", ["T1199"], ["all"]),
        ("Monthly asset inventory reconciliation", "Detective", "ID.AM", [], ["all"]),
        ("Risk acceptance sign-off", "Directive", "GV.RM", [], ["all"]),
        ("Security exceptions register", "Directive", "GV.RM", [], ["all"]),
        ("Acceptable use policy", "Directive", "GV.PO", ["T1078"], ["endpoint"]),
        ("Supplier security clauses in contracts", "Directive", "GV.SC", ["T1195", "T1199"], ["all"]),
        ("Security metrics reporting to management", "Directive", "GV.OV", [], ["all"]),
        ("Internal audit of security controls", "Detective", "GV.OV", [], ["all"]),
    ]),
    "IR": ("Incident response and recovery", [
        ("Incident response plan", "Corrective", "RS.MA", [], ["all"]),
        ("Credential compromise playbook", "Corrective", "RS.MI", ["T1078", "T1110"], ["all"]),
        ("Reconnaissance triage playbook", "Corrective", "RS.AN", ["T1046", "T1595"], ["all"]),
        ("Account disable on confirmed compromise (approval required)", "Corrective", "RS.MI", ["T1078"], ["identity"]),
        ("Host isolation through EDR (approval required)", "Corrective", "RS.MI", ["T1021", "T1486"], ["endpoint", "server"]),
        ("Block malicious source IP at the perimeter", "Corrective", "RS.MI", ["T1595", "T1110"], ["network"]),
        ("Forensic readiness and evidence handling", "Corrective", "RS.AN", [], ["server", "endpoint"]),
        ("Incident escalation matrix", "Directive", "RS.CO", [], ["all"]),
        ("Biannual tabletop exercises", "Directive", "ID.IM", [], ["all"]),
        ("Post-incident lessons learned", "Corrective", "ID.IM", [], ["all"]),
        ("Ransomware recovery runbook", "Corrective", "RC.RP", ["T1486"], ["server", "db"]),
        ("Business continuity and disaster recovery plan", "Corrective", "RC.RP", ["T1485", "T1486", "T1498"], ["all"]),
    ]),
    "PHY": ("Physical, OT and IoT", [
        ("IoT network isolation (dedicated VLAN)", "Preventive", "PR.IR", ["T1046", "T1021"], ["iot"]),
        ("Device certificate authentication", "Preventive", "PR.AA", ["T1200"], ["iot", "network"]),
        ("Data center physical access control", "Preventive", "PR.AA", ["T1200"], ["server", "network"]),
        ("CCTV recording retention (90 days)", "Detective", "DE.CM", [], ["iot"]),
        ("Building management system access review", "Detective", "PR.AA", ["T1078"], ["iot"]),
        ("Printer secure configuration", "Preventive", "PR.PS", ["T1046"], ["iot"]),
        ("OT and IoT passive network monitoring", "Detective", "DE.CM", ["T1046"], ["iot"]),
        ("Server room environmental monitoring", "Detective", "DE.CM", [], ["server"]),
        ("Redundant power (UPS and generator)", "Preventive", "PR.IR", [], ["server", "network"]),
        ("Visitor management", "Preventive", "PR.AA", [], ["all"]),
        ("Secure disposal of hardware", "Preventive", "PR.DS", ["T1005"], ["all"]),
        ("Network device configuration backup", "Corrective", "PR.DS", ["T1485"], ["network"]),
    ]),
}
FAMILY_OWNER = {"IAM": "Identity team", "NET": "Network team", "VUL": "IT operations", "MON": "Security operations (SOC)",
                "DAT": "Data protection office", "END": "Endpoint team", "CLD": "Cloud platform team", "GOV": "GRC office",
                "IR": "Security operations (SOC)", "PHY": "Facilities"}
CSF_NAMES = {"GV.PO": "Policy", "GV.RM": "Risk Management Strategy", "GV.SC": "Cybersecurity Supply Chain Risk Management",
             "GV.OV": "Oversight", "ID.AM": "Asset Management", "ID.RA": "Risk Assessment", "ID.IM": "Improvement",
             "PR.AA": "Identity Management, Authentication, and Access Control", "PR.AT": "Awareness and Training",
             "PR.DS": "Data Security", "PR.PS": "Platform Security", "PR.IR": "Technology Infrastructure Resilience",
             "DE.CM": "Continuous Monitoring", "DE.AE": "Adverse Event Analysis", "RS.MA": "Incident Management",
             "RS.AN": "Incident Analysis", "RS.CO": "Incident Response Reporting and Communication",
             "RS.MI": "Incident Mitigation", "RC.RP": "Incident Recovery Plan Execution"}
MODEL2_CONTROLS = {"Enforce MFA for privileged accounts", "Account lockout after 5 failed logins",
                   "Quarterly privileged access review", "Tune IDS scan signatures",
                   "Restrict inbound management ports", "Segment the network zone"}
FREQ = {"Preventive": "Quarterly", "Detective": "Monthly", "Corrective": "Semi-annually", "Directive": "Annually"}

controls = []
CTRL_BY_NAME = {}
for fam, (fam_name, specs) in CONTROL_SPECS.items():
    for i, (name, ctype, csf, techs, groups) in enumerate(specs, 1):
        status = rng.choices(["Implemented", "Partially implemented", "Planned", "Not implemented"],
                             [55, 25, 12, 8])[0]
        if name in MODEL2_CONTROLS:
            status = "Partially implemented"
        eff = {"Implemented": rng.uniform(.65, .9), "Partially implemented": rng.uniform(.35, .6),
               "Planned": 0.0, "Not implemented": 0.0}[status]
        tested = WINDOW_START - timedelta(days=rng.randint(10, 200)) if status in ("Implemented", "Partially implemented") else None
        c = {
            "control_id": f"CTL-{fam}-{i:03d}",
            "name": name,
            "family": fam_name,
            "control_type": ctype,
            "nist_csf_2": {"category": csf, "category_name": CSF_NAMES[csf], "function": csf.split(".")[0]},
            "mitigates_attack_techniques": techs,
            "applies_to": groups,
            "owner": FAMILY_OWNER[fam],
            "implementation_status": status,
            "effectiveness": round(eff, 2),
            "test_frequency": FREQ[ctype],
            "last_tested": day(tested) if tested else None,
            "model2_held_out_positive": name in MODEL2_CONTROLS,
        }
        controls.append(c)
        CTRL_BY_NAME[name] = c
assert len(controls) == 120

# ---------------------------------------------------------------- assets
# type, label, count, hostname prefix, OS choices, criticality weights (C,H,M,L), zone, groups, internet-facing share
ASSET_TYPES = [
    ("domain_controller", "Domain controller", 6, "DC", ["Windows Server 2022"], (100, 0, 0, 0), "Server", ["server", "identity"], 0),
    ("web_server", "Web server", 40, "WEB", ["Ubuntu 22.04 LTS", "RHEL 9", "Windows Server 2019"], (15, 40, 40, 5), "DMZ", ["server", "web"], .6),
    ("database_server", "Database server", 35, "DB", ["RHEL 9", "Windows Server 2022", "Ubuntu 22.04 LTS"], (40, 45, 15, 0), "Server", ["server", "db"], 0),
    ("application_server", "Application server", 60, "APP", ["RHEL 9", "Ubuntu 22.04 LTS", "Windows Server 2022"], (15, 45, 35, 5), "Server", ["server"], .05),
    ("file_server", "File server", 12, "FS", ["Windows Server 2022", "Windows Server 2019"], (10, 60, 30, 0), "Server", ["server"], 0),
    ("mail_server", "Mail gateway", 4, "MAIL", ["Ubuntu 22.04 LTS"], (50, 50, 0, 0), "DMZ", ["server", "web"], 1),
    ("vpn_gateway", "VPN gateway", 4, "VPN", ["FortiOS 7.4"], (100, 0, 0, 0), "DMZ", ["network", "identity"], 1),
    ("firewall", "Firewall", 10, "FW", ["FortiOS 7.4", "PAN-OS 11.1"], (70, 30, 0, 0), "Management", ["network"], .3),
    ("network_device", "Switch or router", 30, "NET", ["Cisco IOS XE 17", "Aruba AOS-CX 10"], (10, 50, 40, 0), "Management", ["network"], 0),
    ("wireless_controller", "Wireless controller", 6, "WLC", ["Aruba AOS 8"], (0, 50, 50, 0), "Management", ["network"], 0),
    ("workstation", "Workstation", 150, "WS", ["Windows 11 23H2", "Windows 10 22H2", "Ubuntu 22.04 LTS"], (0, 5, 55, 40), "User", ["endpoint"], 0),
    ("laptop", "Laptop", 70, "LT", ["Windows 11 23H2", "macOS 14"], (0, 10, 60, 30), "User", ["endpoint"], 0),
    ("jump_host", "Admin jump host", 4, "JUMP", ["Windows Server 2022"], (100, 0, 0, 0), "Management", ["server", "identity"], 0),
    ("backup_server", "Backup server", 6, "BKP", ["Windows Server 2022", "RHEL 9"], (50, 50, 0, 0), "Server", ["server"], 0),
    ("security_appliance", "Security tool server", 8, "SEC", ["Ubuntu 22.04 LTS"], (40, 60, 0, 0), "Management", ["server"], 0),
    ("container_host", "Kubernetes node", 20, "K8S", ["Ubuntu 22.04 LTS"], (10, 50, 40, 0), "Cloud", ["server", "cloud"], .1),
    ("cloud_vm", "Cloud virtual machine", 30, "CVM", ["Ubuntu 22.04 LTS", "Windows Server 2022", "Amazon Linux 2023"], (10, 40, 40, 10), "Cloud", ["server", "cloud"], .3),
    ("printer", "Network printer", 15, "PRN", ["Embedded firmware"], (0, 0, 20, 80), "IoT", ["iot"], 0),
    ("cctv_recorder", "CCTV recorder", 10, "CAM", ["Embedded Linux"], (0, 20, 60, 20), "IoT", ["iot"], 0),
    ("building_management", "Building management controller", 5, "BMS", ["Embedded Linux"], (20, 60, 20, 0), "IoT", ["iot"], 0),
    ("ci_server", "Build server", 10, "CI", ["Ubuntu 22.04 LTS"], (0, 50, 50, 0), "Server", ["server"], 0),
]
TYPE_INFO = {t[0]: t for t in ASSET_TYPES}
BUSINESS_UNITS = ["Finance", "Human Resources", "IT Operations", "Academic Affairs", "Student Services", "Research",
                  "Engineering", "Digital Services", "Legal and Compliance", "Executive Office", "Library", "Facilities",
                  "Security", "Sales and Partnerships"]
BU_OWNER = {bu: f"Head of {bu}" for bu in BUSINESS_UNITS}
TYPE_BU = {"domain_controller": ["IT Operations"], "firewall": ["IT Operations"], "network_device": ["IT Operations"],
           "wireless_controller": ["IT Operations"], "vpn_gateway": ["IT Operations"], "jump_host": ["IT Operations"],
           "backup_server": ["IT Operations"], "security_appliance": ["Security"], "mail_server": ["IT Operations"],
           "printer": ["Facilities"], "cctv_recorder": ["Facilities"], "building_management": ["Facilities"],
           "ci_server": ["Engineering", "Digital Services"]}
LOCATIONS = {"Server": ["Al Ain main data center", "Abu Dhabi office server room"], "DMZ": ["Al Ain main data center"],
             "Management": ["Al Ain main data center", "Abu Dhabi office server room", "Dubai office"],
             "User": ["Al Ain campus", "Abu Dhabi office", "Dubai office"],
             "Cloud": ["Azure UAE North", "AWS me-central-1"], "IoT": ["Al Ain campus", "Abu Dhabi office"]}
SUBNET = {"Server": "10.10", "DMZ": "172.16", "Management": "10.0", "User": "10.20", "Cloud": "10.50", "IoT": "10.30"}
CLASSIFICATION_BY_CRIT = {"Critical": ["Restricted", "Confidential"], "High": ["Confidential", "Internal"],
                          "Medium": ["Internal", "Confidential"], "Low": ["Internal", "Public"]}

assets = []
used_ips = set()
ip_counters = {}


def next_ip(zone):
    base = SUBNET[zone]
    while True:
        n = ip_counters.get(zone, 10)
        ip_counters[zone] = n + 1
        ip = f"{base}.{n // 250 + 1}.{n % 250 + 1}"
        if ip not in used_ips:
            used_ips.add(ip)
            return ip


public_n = 10
an = 1
for (atype, label, count, prefix, oses, cw, zone, groups, inet) in ASSET_TYPES:
    for k in range(1, count + 1):
        crit = rng.choices(["Critical", "High", "Medium", "Low"], cw)[0]
        bu = rng.choice(TYPE_BU.get(atype, BUSINESS_UNITS))
        host = f"{prefix}-{k:02d}" if count < 100 else f"{prefix}-{k:03d}"
        internet = rng.random() < inet
        ip = next_ip(zone)
        valid_from = datetime(2023, 1, 1, tzinfo=timezone.utc) + timedelta(days=rng.randint(0, 900))
        a = {
            "asset_id": f"AST-{an:05d}",
            "hostname": host,
            "fqdn": f"{host.lower()}.{DOMAIN}",
            "ip_address": ip,
            "public_ip": f"203.0.113.{public_n}" if internet else None,
            "asset_type": atype,
            "asset_type_label": label,
            "operating_system": rng.choice(oses),
            "business_unit": bu,
            "owner": BU_OWNER[bu],
            "custodian": "IT Operations" if zone != "Cloud" else "Cloud platform team",
            "criticality": crit,
            "data_classification": rng.choice(CLASSIFICATION_BY_CRIT[crit]),
            "environment": "Production" if rng.random() < .82 or crit == "Critical" else rng.choice(["Staging", "Development"]),
            "network_zone": zone,
            "location": rng.choice(LOCATIONS[zone]),
            "internet_facing": internet,
            "control_groups": groups,
            "status": "active",
            "valid_from": iso(valid_from),
            "valid_to": None,
            "last_seen": None,
        }
        if internet:
            public_n += 1
        assets.append(a)
        an += 1

# Point-in-time cases: some assets were onboarded during the alert window, some retired before it.
for a in rng.sample([a for a in assets if a["asset_type"] in ("workstation", "laptop", "cloud_vm", "application_server")], 14):
    a["valid_from"] = iso(WINDOW_START + timedelta(days=rng.randint(3, 20), hours=rng.randint(0, 23)))
for a in rng.sample([a for a in assets if a["asset_type"] in ("workstation", "laptop", "printer") and a["valid_from"] < iso(WINDOW_START)], 8):
    a["status"] = "retired"
    a["valid_to"] = iso(WINDOW_START - timedelta(days=rng.randint(5, 60)))
ASSET_BY_ID = {a["asset_id"]: a for a in assets}
ACTIVE = [a for a in assets if a["status"] == "active"]
AUTH_TYPES = {"domain_controller", "web_server", "database_server", "application_server", "file_server", "mail_server",
              "vpn_gateway", "jump_host", "backup_server", "security_appliance", "cloud_vm", "ci_server", "container_host"}


def is_windows(a):
    return a["operating_system"].startswith("Windows")


# ---------------------------------------------------------------- risks
TEMPLATES = [
    # key, scenario, title, category, threat, vulnerability, techniques, asset types (None = all), controls
    ("cred_bruteforce", "credential_access", "Credential brute force against {h}", "Access control",
     "An attacker guessing passwords", "an authentication service with weak lockout", ["T1110.001", "T1110"], AUTH_TYPES,
     ["Account lockout after 5 failed logins", "Enforce MFA for privileged accounts", "Alert on repeated failed logons",
      "Rate limiting on authentication endpoints", "Password policy (14+ characters, banned-password list)"]),
    ("cred_spray", "credential_access", "Password spraying through {h}", "Access control",
     "An attacker trying common passwords across many accounts", "single-factor sign-in for standard users",
     ["T1110.003"], {"domain_controller", "vpn_gateway", "mail_server"},
     ["Enforce MFA for remote access (VPN)", "Account lockout after 5 failed logins", "Impossible-travel sign-in detection",
      "VPN geo-restriction and IP reputation filtering", "Honeytoken accounts"]),
    ("cred_priv", "credential_access", "Compromise of privileged credentials on {h}", "Privileged access",
     "An attacker reusing stolen administrator credentials", "standing privileged accounts", ["T1078", "T1003"],
     {"domain_controller", "jump_host", "security_appliance", "backup_server", "database_server"},
     ["Privileged access management vault", "Just-in-time administrative access", "Quarterly privileged access review",
      "Enforce MFA for privileged accounts", "LSASS protection (Credential Guard)"]),
    ("cred_kerb", "credential_access", "Kerberoasting of service accounts on {h}", "Privileged access",
     "An attacker requesting service tickets to crack offline", "service accounts with weak passwords and RC4 enabled",
     ["T1558.003"], {"domain_controller"},
     ["Enforce AES-only Kerberos encryption", "Service account password rotation (90 days)",
      "Kerberos service ticket anomaly detection", "Honeytoken accounts"]),
    ("cred_local", "credential_access", "Weak local administrator password on {h}", "Access control",
     "An attacker moving laterally with a shared local password", "reused local administrator passwords",
     ["T1078.003", "T1110"], {"workstation", "laptop"},
     ["Local administrator password solution (LAPS)", "Remove local administrator rights",
      "Password policy (14+ characters, banned-password list)", "Alert on repeated failed logons"]),
    ("cred_default", "credential_access", "Default credentials on {h}", "Access control",
     "An attacker logging in with vendor default passwords", "factory default credentials", ["T1078.001"],
     {"printer", "cctv_recorder", "building_management", "network_device", "wireless_controller", "firewall"},
     ["Change default device credentials", "Device certificate authentication", "Network access control (802.1X)"]),
    ("cred_phish", "credential_access", "Credential theft through phishing of {h} users", "Human factors",
     "A phishing campaign harvesting passwords", "users without phishing-resistant MFA", ["T1566", "T1078"],
     {"mail_server", "workstation", "laptop"},
     ["Security awareness training", "Quarterly phishing simulation", "Enforce MFA for remote access (VPN)",
      "Block Office macros from the internet"]),
    ("recon_scan", "reconnaissance", "Unauthorized network scanning of {h}", "Network security",
     "An attacker mapping open services", "unfiltered internal network paths", ["T1046"], None,
     ["Tune IDS scan signatures", "Port-scan threshold detection", "Segment the network zone", "Host firewall enabled",
      "Restrict inbound management ports"]),
    ("recon_ext", "reconnaissance", "External attack surface enumeration of {h}", "Network security",
     "An internet-based attacker probing exposed services", "internet-facing services", ["T1595", "T1595.002"], "internet",
     ["External attack surface scanning", "Web application firewall", "IPS blocking for known scanners",
      "Block malicious source IP at the perimeter"]),
    ("recon_share", "reconnaissance", "Share and account enumeration on {h}", "Network security",
     "An insider or intruder listing shares and accounts", "broad read access to directory and shares",
     ["T1135", "T1087"], {"file_server", "domain_controller"},
     ["Honeytoken accounts", "Segment the network zone", "User and entity behavior analytics", "Reconnaissance triage playbook"]),
    ("recon_web", "reconnaissance", "Web application reconnaissance against {h}", "Application security",
     "An attacker crawling for vulnerable paths", "verbose error pages and exposed admin paths", ["T1595.002"],
     {"web_server"}, ["Web application firewall", "Secure software development review", "Rate limiting on authentication endpoints"]),
    ("recon_internal", "reconnaissance", "Internal service discovery from {h}", "Network security",
     "A compromised endpoint scanning internal servers", "flat network segments", ["T1046", "T1018"],
     {"workstation", "laptop", "ci_server"},
     ["Endpoint detection and response (EDR)", "Host firewall enabled", "Segment the network zone", "Port-scan threshold detection"]),
    ("vuln", "other", "Unpatched critical vulnerabilities on {h}", "Vulnerability management",
     "An attacker exploiting a known vulnerability", "missing security patches", ["T1190", "T1068"], None,
     ["Monthly patch cycle", "Critical patch SLA (14 days)", "Authenticated vulnerability scanning (weekly)"]),
    ("ransom", "other", "Ransomware encryption of {h}", "Malware",
     "A ransomware operator encrypting systems", "limited recovery capability", ["T1486", "T1490"],
     {"file_server", "database_server", "application_server", "workstation", "laptop", "backup_server"},
     ["Endpoint detection and response (EDR)", "Daily backups (3-2-1 rule)", "Immutable offline backup copy",
      "Ransomware recovery runbook"]),
    ("exfil", "other", "Data exfiltration from {h}", "Data protection",
     "An attacker or insider copying sensitive data out", "unrestricted outbound traffic", ["T1048", "T1567"],
     {"database_server", "file_server", "application_server", "cloud_vm"},
     ["Data loss prevention", "Egress filtering by allowlist", "Database activity monitoring", "Data classification and labeling"]),
    ("misconfig", "other", "Insecure configuration of {h}", "Configuration management",
     "An attacker abusing an insecure default", "configuration drift from the baseline", ["T1190"], None,
     ["CIS hardened baseline configuration", "Configuration drift monitoring", "Disable unused services and ports"]),
    ("logging", "other", "Insufficient security logging on {h}", "Monitoring",
     "An intrusion going unnoticed", "incomplete log forwarding", [], None,
     ["Centralized log collection to SIEM", "Security log retention (12 months)", "NTP time synchronization"]),
    ("backup", "other", "Backup failure for {h}", "Resilience",
     "Data loss after an outage or attack", "untested backups", ["T1490"],
     {"database_server", "file_server", "application_server", "mail_server", "domain_controller"},
     ["Daily backups (3-2-1 rule)", "Quarterly backup restore testing", "Immutable offline backup copy"]),
    ("ddos", "other", "Denial of service against {h}", "Availability",
     "A volumetric or application-layer flood", "limited upstream filtering", ["T1498"],
     {"web_server", "vpn_gateway", "firewall", "mail_server"},
     ["DDoS protection service", "Rate limiting on authentication endpoints", "Business continuity and disaster recovery plan"]),
    ("insider", "other", "Insider misuse of access to {h}", "Access control",
     "An authorized user abusing access", "excessive standing permissions", ["T1078"],
     {"database_server", "file_server", "application_server"},
     ["User and entity behavior analytics", "Approval for restricted data access", "Joiner-mover-leaver account process"]),
    ("thirdparty", "other", "Third-party access abuse on {h}", "Supplier risk",
     "A supplier account being misused", "unmanaged vendor remote access", ["T1199"],
     {"application_server", "cloud_vm", "building_management"},
     ["Third-party access review", "Supplier security clauses in contracts", "Just-in-time administrative access"]),
    ("malware", "other", "Malware infection on {h}", "Malware",
     "A user running a malicious file", "unrestricted software execution", ["T1204"], {"workstation", "laptop"},
     ["Next-generation antivirus", "Application allowlisting", "Endpoint detection and response (EDR)", "Browser hardening and isolation"]),
    ("container", "other", "Container escape on {h}", "Cloud security",
     "An attacker breaking out of a container", "privileged containers", ["T1611", "T1610"], {"container_host"},
     ["Kubernetes RBAC and namespace isolation", "Runtime container security monitoring", "Container image scanning"]),
    ("cloudexp", "other", "Public exposure of cloud storage used by {h}", "Cloud security",
     "Anyone on the internet reading stored data", "storage access policies that allow public reads", ["T1530"], {"cloud_vm"},
     ["Block public storage buckets", "Cloud security posture management", "Private endpoints for data services"]),
    ("physical", "other", "Physical tampering with {h}", "Physical security",
     "An unauthorized person accessing hardware", "weak physical access control", ["T1200"],
     {"printer", "cctv_recorder", "building_management", "network_device", "firewall"},
     ["Data center physical access control", "Visitor management", "Device certificate authentication"]),
    ("firmware", "other", "Outdated firmware on {h}", "Vulnerability management",
     "An attacker exploiting old device firmware", "no firmware update schedule", ["T1190"],
     {"printer", "cctv_recorder", "building_management", "network_device", "wireless_controller", "firewall"},
     ["Firmware update program for devices", "OT and IoT passive network monitoring"]),
]


def applicable(t, a):
    types = t[7]
    if types is None:
        return True
    if types == "internet":
        return a["internet_facing"]
    return a["asset_type"] in types


def rating(score):
    return "Critical" if score >= 20 else "High" if score >= 12 else "Medium" if score >= 6 else "Low"


IMPACT = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}
risks = []
RISKS_BY_ASSET = {}
rn = 1
for a in assets:
    pool = [t for t in TEMPLATES if applicable(t, a)]
    chosen = []
    for scen in ("credential_access", "reconnaissance"):
        opts = [t for t in pool if t[1] == scen]
        if opts:
            chosen.append(rng.choice(opts))
    others = [t for t in pool if t[1] == "other"]
    n_other = 3 if a["criticality"] in ("Critical", "High") else 2
    chosen += rng.sample(others, min(n_other, len(others)))
    if a["asset_type"] == "domain_controller":
        chosen += [t for t in pool if t[0] in ("cred_kerb", "cred_spray") and t not in chosen]
    for t in chosen:
        key, scen, title, cat, threat, vuln, techs, _, ctrl_names = t
        base = 3 if scen != "other" else 2
        L = base + (1 if a["internet_facing"] else 0) + rng.choice([-1, 0, 0, 1])
        L = max(1, min(5, L))
        I = IMPACT[a["criticality"]] + (1 if a["data_classification"] == "Restricted" and a["criticality"] != "Critical" else 0) - (1 if rng.random() < .2 else 0)
        I = max(1, min(5, I))
        cands = [CTRL_BY_NAME[n] for n in ctrl_names]
        existing = [c for c in cands if c["implementation_status"] in ("Implemented", "Partially implemented")]
        existing = rng.sample(existing, min(len(existing), rng.randint(1, 3))) if existing else []
        planned = [c for c in cands if c not in existing and c["implementation_status"] in ("Planned", "Not implemented")]
        planned = planned[:1]
        eff = max((c["effectiveness"] for c in existing), default=0)
        RL = max(1, round(L * (1 - eff * .6)))
        RI = I if key not in ("backup", "ransom") or not existing else max(1, I - 1)
        inherent = L * I
        treatment = "Accept" if rating(inherent) == "Low" else rng.choices(["Mitigate", "Transfer", "Avoid"], [88, 9, 3])[0]
        if key in ("ddos", "thirdparty") and treatment == "Mitigate" and rng.random() < .3:
            treatment = "Transfer"
        status = ("Accepted" if treatment == "Accept" else
                  rng.choices(["Open", "In treatment", "Monitoring", "Closed"], [40, 35, 20, 5])[0])
        identified = max(datetime.fromisoformat(a["valid_from"].replace("Z", "+00:00")),
                         datetime(2025, 1, 6, tzinfo=timezone.utc)) + timedelta(days=rng.randint(0, 200))
        if identified > WINDOW_START:
            identified = WINDOW_START - timedelta(days=rng.randint(1, 30))
        reviewed = min(WINDOW_START - timedelta(days=1), identified + timedelta(days=rng.randint(30, 400)))
        history = [{"valid_from": iso(identified), "likelihood": max(1, L - (1 if rng.random() < .3 else 0)), "impact": I,
                    "status": "Open"}]
        if reviewed > identified:
            history.append({"valid_from": iso(reviewed), "likelihood": L, "impact": I, "status": status})
        # ~8% of risks were re-assessed during the alert window (exercises point-in-time enrichment)
        if rng.random() < .08 and status != "Closed":
            mid = WINDOW_START + timedelta(days=rng.randint(4, 26), hours=rng.randint(0, 23))
            L2 = max(1, min(5, L + rng.choice([-1, 1])))
            history.append({"valid_from": iso(mid), "likelihood": L2, "impact": I, "status": status})
            L, reviewed = L2, mid
            inherent = L * I
            RL = max(1, round(L * (1 - eff * .6)))
        r = {
            "risk_id": f"RSK-{rn:05d}",
            "title": title.format(h=a["hostname"]),
            "description": f"{threat} could exploit {vuln} on {a['hostname']} ({a['asset_type_label'].lower()}), "
                           f"affecting {a['business_unit']} services.",
            "category": cat,
            "scenario_tag": scen,
            "asset_id": a["asset_id"],
            "business_unit": a["business_unit"],
            "risk_owner": a["owner"],
            "threat": threat,
            "vulnerability": vuln[0].upper() + vuln[1:],
            "mitre_attack_techniques": techs,
            "inherent": {"likelihood": L, "impact": I, "score": inherent, "rating": rating(inherent)},
            "existing_control_ids": [c["control_id"] for c in existing],
            "planned_control_ids": [c["control_id"] for c in planned],
            "residual": {"likelihood": RL, "impact": RI, "score": RL * RI, "rating": rating(RL * RI)},
            "treatment": treatment,
            "status": status,
            "date_identified": day(identified),
            "last_reviewed": iso(reviewed),
            "next_review": day(reviewed + timedelta(days=90 if rating(inherent) in ("Critical", "High") else 180)),
            "history": history,
        }
        risks.append(r)
        RISKS_BY_ASSET.setdefault(a["asset_id"], []).append(r)
        rn += 1

# ---------------------------------------------------------------- alerts
# rule id, name, source, level (Wazuh) or priority (Suricata), category, technique, tactic
R = {
    "ssh_nouser": ("5710", "sshd: Attempt to login using a non-existent user", "wazuh", 5, "authentication_failed", "T1110.001", "Credential Access"),
    "ssh_fail": ("5716", "sshd: authentication failed", "wazuh", 5, "authentication_failed", "T1110.001", "Credential Access"),
    "ssh_brute": ("5712", "sshd: brute force trying to get access to the system", "wazuh", 10, "brute_force", "T1110", "Credential Access"),
    "ssh_ok": ("5715", "sshd: authentication success", "wazuh", 3, "authentication_success", "T1078", "Initial Access"),
    "win_fail": ("60122", "Logon failure - unknown user or bad password", "wazuh", 5, "authentication_failed", "T1110.001", "Credential Access"),
    "win_multi": ("60204", "Multiple Windows logon failures", "wazuh", 10, "brute_force", "T1110", "Credential Access"),
    "win_ok": ("60106", "Windows logon success", "wazuh", 3, "authentication_success", "T1078", "Initial Access"),
    "kerb_rc4": ("100201", "Kerberos service ticket requested with RC4 encryption (4769)", "wazuh", 10, "kerberos", "T1558.003", "Credential Access"),
    "spray": ("100210", "Password spraying: one source failing against many accounts", "wazuh", 12, "brute_force", "T1110.003", "Credential Access"),
    "vpn_fail": ("100220", "VPN authentication failure", "wazuh", 5, "authentication_failed", "T1110", "Credential Access"),
    "vpn_ok_after": ("100221", "VPN login success after repeated failures", "wazuh", 12, "authentication_success", "T1078", "Initial Access"),
    "web_login_fail": ("100230", "Web application login failure burst", "wazuh", 8, "authentication_failed", "T1110", "Credential Access"),
    "ldap_enum": ("100240", "Directory account enumeration (bulk LDAP queries)", "wazuh", 8, "enumeration", "T1087.002", "Discovery"),
    "smb_enum": ("100241", "SMB share enumeration from a workstation", "wazuh", 8, "enumeration", "T1135", "Discovery"),
    "web_400": ("31101", "Web server 400 error code", "wazuh", 5, "web_scan", "T1595.002", "Reconnaissance"),
    "web_400_multi": ("31151", "Multiple web server 400 error codes from same source ip", "wazuh", 10, "web_scan", "T1595.002", "Reconnaissance"),
    "et_ssh_scan": ("2001219", "ET SCAN Potential SSH Scan", "suricata", 2, "network_scan", "T1046", "Discovery"),
    "et_nmap_ss": ("2009582", "ET SCAN NMAP -sS window 1024", "suricata", 2, "network_scan", "T1046", "Discovery"),
    "et_mssql": ("2010935", "ET SCAN Suspicious inbound to MSSQL port 1433", "suricata", 2, "network_scan", "T1046", "Discovery"),
    "et_mysql": ("2010937", "ET SCAN Suspicious inbound to mySQL port 3306", "suricata", 2, "network_scan", "T1046", "Discovery"),
    "et_pgsql": ("2010939", "ET SCAN Suspicious inbound to PostgreSQL port 5432", "suricata", 2, "network_scan", "T1046", "Discovery"),
    "et_vnc": ("2002911", "ET SCAN Potential VNC Scan 5900-5920", "suricata", 2, "network_scan", "T1046", "Discovery"),
    "et_445": ("2001569", "ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection", "suricata", 2, "network_scan", "T1046", "Discovery"),
    "et_rdp_ns": ("2023753", "ET SCAN MS Terminal Server Traffic on Non-standard Port", "suricata", 2, "network_scan", "T1046", "Discovery"),
    "et_nmap_ua": ("2024364", "ET SCAN Possible Nmap User-Agent Observed", "suricata", 2, "web_scan", "T1595.002", "Reconnaissance"),
    "et_curl": ("2013028", "ET POLICY curl User-Agent Outbound", "suricata", 3, "policy", None, None),
    "stream_retx": ("2210054", "SURICATA STREAM excessive retransmissions", "suricata", 3, "network_anomaly", None, None),
    "pkg": ("2902", "New dpkg (Debian Package) installed.", "wazuh", 7, "system", None, None),
    "fim": ("550", "Integrity checksum changed.", "wazuh", 7, "system", None, None),
    "agent_start": ("503", "Wazuh agent started.", "wazuh", 3, "system", None, None),
    "sched": ("100300", "Scheduled task executed", "wazuh", 3, "system", None, None),
    "auth_scan": ("100310", "Authorized vulnerability scan observed", "wazuh", 3, "policy", "T1046", "Discovery"),
}
SCAN_PORTS = {"et_ssh_scan": 22, "et_nmap_ss": None, "et_mssql": 1433, "et_mysql": 3306, "et_pgsql": 5432, "et_vnc": 5900,
              "et_445": 445, "et_rdp_ns": 3390, "et_nmap_ua": 443}


def severity(src, lvl):
    if src == "wazuh":
        return "critical" if lvl >= 12 else "high" if lvl >= 8 else "medium" if lvl >= 5 else "low"
    return {1: "high", 2: "medium", 3: "low"}[lvl]


EXTERNAL_IPS = [f"198.51.100.{i}" for i in range(10, 70)] + [f"192.0.2.{i}" for i in range(20, 60)]
WORKSTATIONS = [a for a in ACTIVE if a["asset_type"] in ("workstation", "laptop")]
SCANNERS = [a for a in assets if a["asset_type"] == "security_appliance"][:2]
USERS = [f"u{n:05d}" for n in rng.sample(range(10000, 99999), 900)]
ADMINS = [f"adm-{u}" for u in USERS[:60]]
SVC = ["svc-backup", "svc-sql", "svc-web", "svc-ci", "svc-monitor", "svc-print", "svc-erp", "svc-crm"]

# Attackers form campaigns: each one runs several sessions (training is grouped by campaign).
attackers = []
for i in range(70):
    external = i < 45
    attackers.append({"campaign_id": f"CMP-{i + 1:03d}", "external": external,
                      "ip": rng.choice(EXTERNAL_IPS) if external else rng.choice(WORKSTATIONS)["ip_address"],
                      "kind": "credential_access" if i % 2 == 0 else "reconnaissance"})

alerts = []
labels = []
sn = 1


def valid_at(a, t):
    vf = datetime.fromisoformat(a["valid_from"].replace("Z", "+00:00"))
    return t >= vf


def session_start(a, business=False):
    for _ in range(50):
        t = WINDOW_START + timedelta(seconds=rng.randint(0, int((WINDOW_END - WINDOW_START).total_seconds()) - 7200))
        if business:
            t = t.replace(hour=rng.choice([4, 5, 6, 7, 8, 9, 10, 11, 12]))  # 08:00-16:00 Gulf time
        if valid_at(a, t):
            return t
    return datetime.fromisoformat(a["valid_from"].replace("Z", "+00:00")) + timedelta(hours=2)


def emit(sid, key, t, a, src_ip, dst_port=None, user=None, msg=None, dst_ip=None):
    rid, name, src, lvl, cat, tech, tactic = R[key]
    if dst_port is None:
        dst_port = SCAN_PORTS.get(key) or rng.choice([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080, 8443])
    alerts.append({
        "timestamp": iso(t),
        "source": src,
        "rule_id": rid,
        "rule_name": name,
        "source_severity": lvl,
        "severity": severity(src, lvl),
        "category": cat,
        "mitre_technique": tech,
        "mitre_tactic": tactic,
        "src_ip": src_ip,
        "src_port": rng.randint(32768, 60999),
        "dst_ip": dst_ip or (a["ip_address"] if a else None),
        "dst_port": dst_port,
        "protocol": "udp" if dst_port in (53, 123, 161) else "tcp",
        "hostname": a["hostname"] if a else None,
        "agent_name": (a["hostname"] if a else None) if src == "wazuh" else None,
        "sensor": None if src == "wazuh" else rng.choice(["suricata-dmz-01", "suricata-core-01", "suricata-core-02"]),
        "user": user,
        "session_id": sid,
        "message": msg or name,
        "_asset": a,
    })


def cred_session(sid, a, att):
    t = session_start(a)
    src = att["ip"] if (att["external"] and a["internet_facing"]) else rng.choice(WORKSTATIONS)["ip_address"]
    atype = a["asset_type"]
    if atype == "vpn_gateway":
        users = rng.sample(USERS, rng.randint(1, 8))
        for k in range(rng.randint(4, 12)):
            emit(sid, "vpn_fail", t, a, src, 443, rng.choice(users)); t += timedelta(seconds=rng.randint(4, 40))
        if len(users) > 3:
            emit(sid, "spray", t, a, src, 443, None, f"Password spraying against {len(users)} VPN accounts")
        if rng.random() < .35:
            t += timedelta(seconds=rng.randint(20, 300)); emit(sid, "vpn_ok_after", t, a, src, 443, rng.choice(users))
    elif atype == "domain_controller" and rng.random() < .35:
        acct_src = rng.choice(WORKSTATIONS)
        for k in range(rng.randint(3, 8)):
            emit(sid, "kerb_rc4", t, a, acct_src["ip_address"], 88, rng.choice(SVC),
                 f"RC4 service ticket requested for {rng.choice(SVC)} by {rng.choice(USERS)}")
            t += timedelta(seconds=rng.randint(1, 20))
    elif is_windows(a):
        spray = rng.random() < .3
        users = rng.sample(USERS, rng.randint(6, 15)) if spray else [rng.choice(ADMINS + USERS[:200])]
        port = rng.choice([3389, 445]) if atype not in ("web_server", "mail_server") else 443
        for k in range(rng.randint(4, 11)):
            emit(sid, "win_fail", t, a, src, port, rng.choice(users)); t += timedelta(seconds=rng.randint(2, 30))
        emit(sid, "spray" if spray else "win_multi", t, a, src, port, None if spray else users[0])
        if rng.random() < .3:
            t += timedelta(seconds=rng.randint(10, 200)); emit(sid, "win_ok", t, a, src, port, rng.choice(users),
                                                                 "Windows logon success after repeated failures")
    elif atype in ("web_server", "application_server", "cloud_vm") and rng.random() < .4:
        for k in range(rng.randint(5, 12)):
            emit(sid, "web_login_fail", t, a, src, 443, rng.choice(USERS)); t += timedelta(seconds=rng.randint(1, 15))
    else:
        users = [rng.choice(["root", "admin", "ubuntu", "oracle", "test"] + USERS[:50]) for _ in range(rng.randint(2, 6))]
        for k in range(rng.randint(4, 12)):
            emit(sid, rng.choice(["ssh_fail", "ssh_fail", "ssh_nouser"]), t, a, src, 22, rng.choice(users))
            t += timedelta(seconds=rng.randint(1, 20))
        emit(sid, "ssh_brute", t, a, src, 22, users[0])
        if rng.random() < .25:
            t += timedelta(seconds=rng.randint(10, 200)); emit(sid, "ssh_ok", t, a, src, 22, users[0],
                                                                 "sshd: authentication success after brute force")


def recon_session(sid, a, att):
    t = session_start(a)
    src = att["ip"] if (att["external"] and a["internet_facing"]) else rng.choice(WORKSTATIONS)["ip_address"]
    targets = [a]
    if not a["internet_facing"] and rng.random() < .25:  # internal sweep across the same zone
        same = [x for x in ACTIVE if x["network_zone"] == a["network_zone"] and x is not a and valid_at(x, t)]
        targets += rng.sample(same, min(len(same), rng.randint(1, 3)))
    if a["asset_type"] == "web_server" and rng.random() < .6:
        for k in range(rng.randint(4, 10)):
            emit(sid, "web_400", t, a, src, 443, None, f"Web server 400 error code for /{rng.choice(['admin', 'wp-login.php', '.env', 'phpmyadmin', 'api/v1/users', 'backup.zip', 'cgi-bin/test'])}")
            t += timedelta(seconds=rng.randint(1, 8))
        emit(sid, "web_400_multi", t, a, src, 443)
        if rng.random() < .5:
            emit(sid, "et_nmap_ua", t + timedelta(seconds=3), a, src, 443)
        return
    if a["asset_type"] in ("file_server", "domain_controller") and rng.random() < .5:
        for k in range(rng.randint(3, 7)):
            emit(sid, "smb_enum" if a["asset_type"] == "file_server" else "ldap_enum", t, a, src,
                 445 if a["asset_type"] == "file_server" else 389, rng.choice(USERS))
            t += timedelta(seconds=rng.randint(5, 60))
        return
    for tgt in targets:
        for k in range(rng.randint(2, 6)):
            key = rng.choice(["et_nmap_ss", "et_ssh_scan", "et_445", "et_vnc", "et_rdp_ns",
                              {"database_server": rng.choice(["et_mssql", "et_mysql", "et_pgsql"])}.get(tgt["asset_type"], "et_nmap_ss")])
            emit(sid, key, t, tgt, src); t += timedelta(seconds=rng.randint(0, 6))


def benign_session(sid, a):
    t = session_start(a, business=True)
    kind = rng.random()
    if kind < .18 and a["asset_type"] not in ("printer", "cctv_recorder", "building_management"):
        # authorized vulnerability scanning: looks like recon but is benign
        sc = rng.choice(SCANNERS)
        emit(sid, "auth_scan", t, a, sc["ip_address"], None, None, f"Authorized vulnerability scan from {sc['hostname']}")
        for k in range(rng.randint(0, 2)):
            t += timedelta(seconds=rng.randint(1, 30)); emit(sid, "et_nmap_ss", t, a, sc["ip_address"])
    elif kind < .4 and a["asset_type"] in AUTH_TYPES | {"workstation", "laptop"}:
        # user mistypes a password once, then signs in
        u = rng.choice(USERS)
        src = rng.choice(WORKSTATIONS)["ip_address"]
        fail, ok, port = ("win_fail", "win_ok", 3389) if is_windows(a) else ("ssh_fail", "ssh_ok", 22)
        emit(sid, fail, t, a, src, port, u); t += timedelta(seconds=rng.randint(5, 40)); emit(sid, ok, t, a, src, port, u)
    else:
        for k in range(rng.randint(1, 3)):
            key = rng.choice(["win_ok" if is_windows(a) else "ssh_ok", "sched", "pkg" if not is_windows(a) else "sched",
                              "fim", "agent_start", "stream_retx", "et_curl"])
            src = (rng.choice([x for x in assets if x["asset_type"] == "jump_host"])["ip_address"]
                   if key in ("win_ok", "ssh_ok") else a["ip_address"])
            emit(sid, key, t, a, src, 3389 if key == "win_ok" else 22 if key == "ssh_ok" else None,
                 rng.choice(ADMINS + SVC) if key in ("win_ok", "ssh_ok", "sched") else None)
            t += timedelta(minutes=rng.randint(1, 50))


cred_targets = [a for a in ACTIVE if a["asset_type"] in AUTH_TYPES]
cred_weights = [6 if a["asset_type"] in ("domain_controller", "vpn_gateway", "jump_host", "mail_server") else
                3 if a["internet_facing"] or a["criticality"] == "Critical" else 1 for a in cred_targets]
recon_targets = ACTIVE
recon_weights = [5 if a["internet_facing"] else 2 if a["asset_type"] in ("file_server", "domain_controller", "database_server") else 1
                 for a in recon_targets]

plan = ["benign"] * 520 + ["credential_access"] * 380 + ["reconnaissance"] * 380
rng.shuffle(plan)
for scen in plan:
    sid = f"SES-{sn:05d}"
    if scen == "benign":
        a = rng.choice(ACTIVE)
        benign_session(sid, a)
        camp = None
    else:
        att = rng.choice([x for x in attackers if x["kind"] == scen])
        if scen == "credential_access":
            a = rng.choices(cred_targets, cred_weights)[0]
            cred_session(sid, a, att)
        else:
            a = rng.choices(recon_targets, recon_weights)[0]
            recon_session(sid, a, att)
        camp = att["campaign_id"]
    labels.append({"session_id": sid, "scenario": scen, "primary_asset_id": a["asset_id"], "campaign_id": camp})
    sn += 1

# Alerts against IPs that are not in the inventory (exercise quarantine of unknown assets)
for k in range(60):
    sid = f"SES-{sn:05d}"
    t = WINDOW_START + timedelta(seconds=rng.randint(0, 29 * 86400))
    ghost = f"10.20.{rng.randint(240, 250)}.{rng.randint(2, 250)}"
    for j in range(rng.randint(1, 3)):
        emit(sid, rng.choice(["et_nmap_ss", "et_445", "stream_retx"]), t + timedelta(seconds=j * 4), None,
             rng.choice(EXTERNAL_IPS + [w["ip_address"] for w in WORKSTATIONS[:20]]), dst_ip=ghost)
    labels.append({"session_id": sid, "scenario": "unknown_asset", "primary_asset_id": None, "campaign_id": None})
    sn += 1

# Exact duplicate deliveries of ~1.5% of events (exercise deduplication)
dups = [dict(x) for x in rng.sample(alerts, int(len(alerts) * .015))]
alerts += dups
alerts.sort(key=lambda x: (x["timestamp"], x["session_id"]))


def tech_match(alert_tech, risk_techs):
    if not alert_tech:
        return False
    base = alert_tech.split(".")[0]
    return any(rt == alert_tech or rt.split(".")[0] == base for rt in risk_techs)


for i, x in enumerate(alerts, 1):
    x["alert_id"] = f"ALR-{i:06d}"
    a = x.pop("_asset")
    risk_ids, control_ids = [], []
    if a:
        ts = x["timestamp"]
        for r in RISKS_BY_ASSET.get(a["asset_id"], []):
            if r["date_identified"] <= ts[:10] and tech_match(x["mitre_technique"], r["mitre_attack_techniques"]):
                risk_ids.append(r["risk_id"])
                for cid in r["existing_control_ids"] + r["planned_control_ids"]:
                    if cid not in control_ids:
                        control_ids.append(cid)
    x["associations"] = {"asset_id": a["asset_id"] if a else None, "risk_ids": risk_ids, "control_ids": control_ids[:6]}

ORDER = ["alert_id", "timestamp", "source", "rule_id", "rule_name", "source_severity", "severity", "category",
         "mitre_technique", "mitre_tactic", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "hostname",
         "agent_name", "sensor", "user", "session_id", "message", "associations"]
alerts = [{k: x[k] for k in ORDER} for x in alerts]

# last_seen for assets
last = {}
for x in alerts:
    aid = x["associations"]["asset_id"]
    if aid:
        last[aid] = max(last.get(aid, ""), x["timestamp"])
for a in assets:
    a["last_seen"] = last.get(a["asset_id"]) or (None if a["status"] == "retired" else iso(WINDOW_END - timedelta(hours=rng.randint(1, 72))))
    if a["status"] == "retired":
        a["last_seen"] = a["valid_to"]

# ---------------------------------------------------------------- write
os.makedirs(OUT, exist_ok=True)
common = {"dataset": "IRIS synthetic dataset", "version": "2.0", "generated_at": GENERATED_AT, "seed": SEED,
          "synthetic": True, "organization": "Synthetic organization (corp.example)"}


def write(name, key, rows, extra=None):
    meta = dict(common, record_count=len(rows), **(extra or {}))
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"metadata": meta, key: rows}, f, ensure_ascii=False, indent=1)
    return path


files = [
    write("asset_inventory.json", "assets", assets,
          {"description": "Asset inventory. Point-in-time validity uses valid_from and valid_to."}),
    write("risk_register.json", "risks", risks,
          {"description": "Risk register on a 5x5 likelihood x impact scale. 'history' holds dated assessments for point-in-time enrichment.",
           "rating_bands": {"Low": "1-5", "Medium": "6-11", "High": "12-19", "Critical": "20-25"}}),
    write("security_controls.json", "controls", controls,
          {"description": "Security control catalogue mapped to NIST CSF 2.0 categories and MITRE ATT&CK techniques.",
           "families": {k: v[0] for k, v in CONTROL_SPECS.items()}}),
    write("siem_alerts.json", "alerts", alerts,
          {"description": "Wazuh and Suricata alerts. 'associations' links each alert to its asset and to risks and controls that share its ATT&CK technique.",
           "time_window": {"start": iso(WINDOW_START), "end": iso(WINDOW_END)},
           "note": "Rule IDs follow Wazuh and Suricata ET Open conventions; custom detections use the Wazuh 100000+ local range. Verify against your deployed rulesets."}),
    write("training_labels.json", "labels", labels,
          {"description": "Offline annotation sidecar: one label per session. Not a runtime input; preparation and prediction must not read it."}),
]
jsonl = os.path.join(OUT, "siem_alerts.jsonl")
with open(jsonl, "w", encoding="utf-8") as f:
    for x in alerts:
        f.write(json.dumps(x, ensure_ascii=False) + "\n")
files.append(jsonl)


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


scen_counts = {}
for l in labels:
    scen_counts[l["scenario"]] = scen_counts.get(l["scenario"], 0) + 1
manifest = dict(common, counts={
    "assets": len(assets), "assets_active": len(ACTIVE), "assets_retired": len(assets) - len(ACTIVE),
    "risks": len(risks), "controls": len(controls), "alerts": len(alerts), "alerts_duplicates": len(dups),
    "alerts_unknown_asset": sum(1 for x in alerts if x["associations"]["asset_id"] is None),
    "alerts_linked_to_risks": sum(1 for x in alerts if x["associations"]["risk_ids"]),
    "sessions": len(labels), "sessions_by_scenario": scen_counts, "campaigns": len(attackers)},
    time_window={"start": iso(WINDOW_START), "end": iso(WINDOW_END)},
    files=[{"file": os.path.basename(p), "bytes": os.path.getsize(p), "sha256": sha(p)} for p in files],
    notes=["All records are synthetic and use reserved ranges: 10/8, 172.16/12, RFC 5737 documentation addresses and corp.example.",
           "siem_alerts.jsonl holds the same alerts as siem_alerts.json, one per line, for the three-input pipeline.",
           "About 1.5% of alerts are exact duplicate deliveries with new alert IDs, to exercise deduplication.",
           "Alerts with associations.asset_id = null target IP addresses missing from the inventory, to exercise quarantine.",
           "Authorized vulnerability scans and single mistyped passwords are labelled benign on purpose (hard negatives).",
           "training_labels.json is an offline sidecar, not a fourth runtime input."])
with open(os.path.join(OUT, "dataset_manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=1)
print(json.dumps(manifest["counts"], indent=1))
