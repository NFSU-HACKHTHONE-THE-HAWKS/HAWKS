import threading
import time
import requests
import json
import uuid  # Added to identify this specific computer
from datetime import datetime
from monitor import FileMonitor
from risk_engine import RiskEngine
from etw_monitor import ETWMonitor
from deception import DeceptionManager
from policy_monitor import PolicyMonitor
from process_verifier import ProcessVerifier

# --- UPDATED CONFIGURATION ---
# Base URL for the server
BASE_URL = "http://10.116.33.19:8000" 
# Generate a unique ID for this agent (or use socket.gethostname())
AGENT_ID = f"PC-{uuid.uuid4().hex[:6].upper()}"
HEARTBEAT_INTERVAL = 30 
# -----------------------------

class DAFDNAgent:
    def __init__(self):
        self.policy = PolicyMonitor(self.handle_alert) # Registry monitor start karne ke liye
        self.verifier = ProcessVerifier()               # Process check karne ke liye
        self.is_running = True
        self.risk_engine = RiskEngine()
        # Ensure MONITOR_PATH is consistent
        self.monitor_path = "C:/DAFDN_Demo"
        self.file_monitor = FileMonitor(self.monitor_path, self.handle_alert)
        self.etw = ETWMonitor(self.handle_alert)
        self.deception = DeceptionManager(self.monitor_path)
        print(f"[*] DAFDN Agent [{AGENT_ID}] Initialized. Monitoring: {self.monitor_path}")

    def handle_alert(self, event_data):
        """Processes raw events and decides if they should be sent to the server."""
        # Layer 3: Calculate Risk
        risk_report = self.risk_engine.evaluate(event_data)
        event_data.update(risk_report)
        
        # Layer 4: Deception Check (Force risk to 100 if honeypot touched)
        if self.deception.is_honeypot(event_data.get('file_path', '')):
            event_data['risk_score'] = 100
            event_data['description'] = "CRITICAL: Honeypot Tampering Detected!"

        # Add Metadata
        event_data["agent_id"] = AGENT_ID
        event_data["timestamp"] = datetime.now().isoformat()

        # --- HACKATHON FILTER ---
        # Only send to backend if Risk is 50 or higher to save bandwidth/DB space
        if event_data.get('risk_score', 0) >= 50:
            self.send_to_backend(event_data, "/alerts")
        else:
            # Optional: Print low risk events locally only
            print(f"[.] Low Risk Event (Ignored): {event_data['event_type']} ({event_data['risk_score']})")

            # handle_alert ke andar
        pid = event_data.get('process_id')
        if pid:
         is_safe, proc_name = self.verifier.verify(pid)
         if not is_safe:
            event_data['risk_score'] += self.risk_engine.UNTRUSTED_PROCESS_SCORE
            event_data['description'] += f" [Alert: Process {proc_name} is suspicious]"

        if event_data.get('type') == 'policy_violation':
            event_data['risk_score'] += self.risk_engine.REGISTRY_TAMPER_SCORE

    def send_to_backend(self, data, endpoint):
        """Dispatches data to the correct FastAPI route."""
        try:
            url = f"{BASE_URL}{endpoint}"
            response = requests.post(url, json=data, timeout=5)
            if response.status_code == 200:
                # Log success based on endpoint
                if endpoint == "/alerts":
                    print(f"[+] ALERT UPLOADED: {data['event_type']} | Risk: {data['risk_score']}")
        except Exception as e:
            print(f"[!] Server unreachable at {endpoint}: {e}")

    def heartbeat(self):
        """Sends a ping to the specific heartbeat route."""
        print(f"[*] Heartbeat thread started for {AGENT_ID}")
        while self.is_running:
            try:
                # Matches your @router.post("/heartbeat/{agent_id}")
                url = f"{BASE_URL}/heartbeat/{AGENT_ID}"
                requests.post(url, timeout=5)
            except:
                pass 
            time.sleep(HEARTBEAT_INTERVAL)

    def start(self):
        # 1. Start Heartbeat thread
        hb_thread = threading.Thread(target=self.heartbeat, daemon=True)
        hb_thread.start()

        # 2. Start File Monitoring thread
        file_thread = threading.Thread(target=self.file_monitor.start, daemon=True)
        file_thread.start()

        # 3. Start Deception & ETW
        self.deception.deploy() 
        self.etw.start() 

        #4. Start Registry Monitoring      
        self.policy.start() # Isse registry monitoring active ho jayegi
        print("[>] DAFDN Agent is Live. Monitoring Anti-Forensics Activity...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[!] Shutting down agent...")
        self.is_running = False
        self.file_monitor.stop()

if __name__ == "__main__":
    agent = DAFDNAgent()
    agent.start()