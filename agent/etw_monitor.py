import win32evtlog
import win32api
import threading
import time

class ETWMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.is_running = True
        self.tamper_ids = [1102, 104] # Log cleared events
        self.suspicious_keywords = ["wevtutil", "cl ", "clear-eventlog"]

    def get_command_line(self, pid):
        try:
            # Event 4688 se command nikalne ka forensic logic
            query = f"*[System[(EventID=4688)] and EventData[Data[@Name='NewProcessId']='{hex(pid)}']]"
            hand = win32evtlog.EvtQuery("Security", win32evtlog.EvtQuerySystemWide, query, None)
            event = win32evtlog.EvtNext(hand, 1)
            if event:
                xml = win32evtlog.EvtRender(event[0], win32evtlog.EvtRenderEventXml)
                if 'CommandLine">' in xml:
                    return xml.split('CommandLine">')[1].split('<')[0]
        except: 
            return "Unknown Command"
        return "Unknown Command"

    def monitor_logs(self):
        start_time = time.time() # Sirf naye events pakadne ke liye
        print("[*] ETW Monitor: Listening for Kernel Events...")
        
        try:
            hand_sec = win32evtlog.OpenEventLog(None, "Security")
        except: 
            print("[!] ETW Admin error: Run as Administrator!")
            return

        while self.is_running:
            try:
                events = win32evtlog.ReadEventLog(hand_sec, 
                    win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
                
                for event in events:
                    if event.TimeGenerated.timestamp() < start_time:
                        continue # Purane events ignore karo
                    
                    if event.EventID in self.tamper_ids:
                        pid = getattr(event, "ProcessID", 0)
                        command = self.get_command_line(pid)
                        self.callback({
                            "event_type": "kernel_log_tampering",
                            "description": "Critical: Event log was cleared",
                            "process_id": pid,
                            "command_line": command,
                            "risk_score": 100 
                        })
            except:
                hand_sec = win32evtlog.OpenEventLog(None, "Security")
                continue
            time.sleep(1)

    def start(self):
        t = threading.Thread(target=self.monitor_logs, daemon=True)
        t.start()