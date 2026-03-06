import psutil
import os

class ProcessVerifier:
    def __init__(self):
        # Trusted system names that handle logs
        self.system_whitelist = [
            "services.exe", "lsass.exe", "svchost.exe", 
            "eventvwr.exe", "dllhost.exe", "wininit.exe"
        ]
        # Standard system paths
        self.system_path = os.environ.get('SystemRoot', 'C:\\Windows').lower()

    def is_system_process(self, pid):
        """
        Performs a 3-layer check to verify if the process is 
        a legitimate Windows system process.
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()
            exe_path = proc.exe().lower()
            username = proc.username().lower()

            # Layer 1: Check if name is in whitelist
            if name in self.system_whitelist:
                # Layer 2: Check if it's running from C:\Windows\System32
                if self.system_path in exe_path:
                    # Layer 3: Check if it's running as SYSTEM or LOCAL SERVICE
                    if "system" in username or "service" in username:
                        return True, "Verified System Process"
            
            return False, f"Non-system process detected: {name} ({username})"
        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False, "Process terminated or access denied (High Suspicion)"
        except Exception as e:
            return False, f"Verification error: {str(e)}"

    def get_risk_multiplier(self, pid):
        """
        Returns a score multiplier. 
        If it's a hacker tool (cmd/powershell), the risk is higher.
        """
        is_system, _ = self.is_system_process(pid)
        if is_system:
            return 0.2  # Drastically reduce risk for system actions
        
        # Check for common hacker entry points
        try:
            name = psutil.Process(pid).name().lower()
            if name in ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe"]:
                return 2.5  # Increase risk significantly
        except:
            pass
            
        return 1.5 # Moderate increase for unknown apps