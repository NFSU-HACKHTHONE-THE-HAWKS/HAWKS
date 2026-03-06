import win32api
import win32con
import time
import threading

class PolicyMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.is_running = True
        # Path to the Security Log settings in Registry
        self.registry_path = r"SYSTEM\CurrentControlSet\Services\EventLog\Security"
        
        # We store the "Healthy" state of the system
        self.last_max_size = self.get_max_log_size()

    def get_max_log_size(self):
        """Reads the maximum allowed size of the Security Log."""
        try:
            key = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, self.registry_path, 0, win32con.KEY_READ)
            value, _ = win32api.RegQueryValueEx(key, "MaxSize")
            win32api.RegCloseKey(key)
            return value
        except Exception as e:
            print(f"[!] Registry Error: {e}")
            return None

    def monitor_registry(self):
        """Checks every 10 seconds if a hacker changed the log size limits."""
        print("[*] Policy Monitor: Watching Registry for MaxSize manipulation...")
        while self.is_running:
            current_size = self.get_max_log_size()
            
            if self.last_max_size is not None and current_size != self.last_max_size:
                # If the new size is tiny, it's a clear anti-forensics move
                if current_size < 1024 * 1024: # Less than 1MB
                    # Change this inside the monitor_registry method
                    self.callback({
                    "event_type": "policy_manipulation",
                    "file_path": "Registry: EventLog/Security/MaxSize",
                    "description": f"CRITICAL: Max Log Size reduced from {self.last_max_size} to {current_size} bytes!",
                    "risk_score": 90  # Changed from base_risk to risk_score
                     })
                
                self.last_max_size = current_size
            
            time.sleep(10)

    def start(self):
        t = threading.Thread(target=self.monitor_registry, daemon=True)
        t.start()

    def stop(self):
        self.is_running = False