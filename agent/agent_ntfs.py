import os
import time
import requests
from ntfs_analyzer import NTFSAnalyzer

# --- CONFIGURATION ---
MAC_IP = "10.116.33.19" 
SERVER_URL = f"http://{MAC_IP}:8000/alerts"
TARGET_FILE = "C:\\DAFDN_Demo\\rehant.txt" 

analyzer = NTFSAnalyzer()
last_seen_mtime = 0  # Isse hum track karenge ki file kab badli

def run_agent():
    global last_seen_mtime
    print(f"[*] The Hawks Agent Active. Monitoring: {TARGET_FILE}")
    
    # Pehle base time set kar lo
    if os.path.exists(TARGET_FILE):
        last_seen_mtime = os.path.getmtime(TARGET_FILE)

    while True:
        try:
            if os.path.exists(TARGET_FILE):
                current_mtime = os.path.getmtime(TARGET_FILE)

                if current_mtime != last_seen_mtime:
                    # Simple Logic: SI Time (MFT) vs USN Time (Live Event)
                    si_time = current_mtime
                    usn_time = time.time() 

                    result = analyzer.analyze(si_time, si_time, usn_time)

                    if result["is_tampered"]:
                        payload = {
                            "agent_id": "REHANT-CHAUDHRY",
                            "event_type": "NTFS_TAMPER", 
                            "file_path": TARGET_FILE,
                            "risk_score": 99, # Max risk for red blinking
                            "description": "CRITICAL: Timestomping Detected! File metadata does not match live system time."
                        }
                 
                        try:
                            requests.post(SERVER_URL, json=payload)
                            print("[+] Red Alert sent to Mac!")
                        except:
                            print("[-] Check Network")

                    # Loop Control
                    last_seen_mtime = current_mtime

                    time.sleep(1) # Fast checking
        except Exception as e:
                        print(f"Error: {e}")
                        time.sleep(2)

if __name__ == "__main__":
    run_agent()