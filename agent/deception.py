import os

class DeceptionManager:
    def __init__(self, honeypot_dir):
        self.honeypot_dir = honeypot_dir
        self.honeypots = [
            "admin_backup_logs.evtx",
            "sql_connection_debug.log",
            "vault_access.key"
        ]

    def deploy(self):
        """Creates fake files to lure attackers."""
        if not os.path.exists(self.honeypot_dir):
            os.makedirs(self.honeypot_dir)

        for honey in self.honeypots:
            path = os.path.join(self.honeypot_dir, honey)
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write("CONFIDENTIAL_DEBUG_DATA_DO_NOT_DELETE")
        print(f"[*] Deception Layer Active: {len(self.honeypots)} honeypots deployed.")

    def is_honeypot(self, file_path):
        """Checks if a detected event happened to a honeypot."""
        name = os.path.basename(file_path)
        return name in self.honeypots