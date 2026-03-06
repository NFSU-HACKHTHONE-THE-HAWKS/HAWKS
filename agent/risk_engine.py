import os
import datetime

class RiskEngine:
    def __init__(self):
        self.SYSTEM_WHITELIST = ["services.exe", "lsass.exe", "svchost.exe", "searchindexer.exe", "eventvwr.exe"]
        self.SUSPICIOUS_KEYWORDS = ["wevtutil", "cl ", "clear-", "delete", "remove-item", "vssadmin", "set-auditpolicy"]
        self.CRITICAL_LOGS = ["security.evtx", "system.evtx", "setup.evtx", "application.evtx"]
        self.SUSPICIOUS_PROCS = ["powershell.exe", "cmd.exe", "wsmprovhost.exe", "psexec.exe", "python.exe"]
        self.honeypots = ["admin_backup_logs.evtx", "sql_connection_debug.log", "vault_access.key"]
        
        # --- YE DONO LINES YAHAN DALO ---
        self.REGISTRY_TAMPER_SCORE = 60
        self.UNTRUSTED_PROCESS_SCORE = 40
        # ------------------------------
        self.history = {} 
        self.recent_events = [] 
        self.agent_id = "WIN-AGENT-01" 

    def evaluate(self, event):
        # CHANGE 1: Match 'risk_score' from your monitor.py
        base_score = event.get("risk_score", 0) 
        reasons = [event.get("description", "Observation detected")]
        
        proc_name = event.get("process_name", "unknown").lower()
        cmd_line = event.get("command_line", "").lower()
        file_path = event.get("file_path", "").lower()
        file_name = os.path.basename(file_path)

        if proc_name != "unknown" and proc_name not in self.SYSTEM_WHITELIST:
            base_score += 30
            reasons.append(f"Non-system process execution: {proc_name}")

        if any(key in cmd_line for key in self.SUSPICIOUS_KEYWORDS):
            base_score += 50
            reasons.append("Anti-forensic keywords detected in command line")

        if event.get("event_type") == "file_modified" and any(log in file_name for log in self.CRITICAL_LOGS):
            prev_size = self.history.get(file_path, 0)
            current_size = event.get("file_size", 0)
            if current_size < prev_size and prev_size > 0:
                base_score += 60
                reasons.append(f"LOG TRUNCATION: Size dropped from {prev_size} to {current_size} bytes")
            self.history[file_path] = current_size

        if file_name in self.honeypots:
            base_score = 100
            reasons.append(f"CRITICAL: Honeypot file {file_name} accessed!")

        if event.get("event_type") in ["suspicious_driver_load", "integrity_violation"]:
            base_score += 40
            reasons.append("Kernel-level or Integrity tampering detected")

        final_score = self.correlate_events(base_score, event, reasons)

        # CHANGE 2: Return 'description' to match your Server Models/Routes
        return {
            "agent_id": self.agent_id,
            "event_type": event.get("event_type"),
            "file_path": file_path,
            "process_name": proc_name,
            "command_line": cmd_line if cmd_line else "N/A",
            "risk_score": min(final_score, 100),
            "severity": self.get_severity(min(final_score, 100)),
            "description": " | ".join(reasons), # Renamed from 'analysis'
            "timestamp": datetime.datetime.now().isoformat()
        }

    def correlate_events(self, current_score, new_event, reasons):
        is_deletion = new_event.get("event_type") == "file_deleted"
        
        for old_event in self.recent_events:
            if is_deletion and "powershell" in old_event.get("process_name", "").lower():
                current_score = 100
                reasons.append("CORRELATION: PowerShell execution + File deletion detected")
            
            if new_event.get("event_type") == "honeypot_triggered":
                current_score = 100

        self.recent_events.append(new_event)
        if len(self.recent_events) > 10:
            self.recent_events.pop(0)
            
        return current_score

    def get_severity(self, score):
        if score >= 71: return "HIGH"
        if score >= 31: return "MEDIUM"
        return "LOW"