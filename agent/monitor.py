import os
import hashlib
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileMonitor:
    def __init__(self, watch_path, callback):
        self.watch_path = watch_path
        self.callback = callback
        self.observer = Observer()
        self.honeypots = ["admin_backup_logs.evtx", "sql_connection_debug.log", "vault_access.key"]

    def get_file_hash(self, filepath):
        """Layer 1: Generates SHA-256 hash."""
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None

    def start(self):
        # We now initialize the database connection before starting
        event_handler = Handler(self.callback, self.get_file_hash, self.honeypots)
        self.observer.schedule(event_handler, self.watch_path, recursive=False)
        self.observer.start()
        print(f"[*] File Monitor: Watching {self.watch_path} with Tiered DB Storage...")

    def stop(self):
        self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    def __init__(self, callback, hash_func, honeypots, ram_limit=500):
        self.callback = callback
        self.hash_func = hash_func
        self.honeypots = honeypots
        self.ram_limit = ram_limit
        self.last_hashes = {} # RAM Cache
        
        # --- LOCAL DB SETUP ---
        # Stores 'Cold' hashes that don't fit in RAM
        self.db_conn = sqlite3.connect("local_baseline.db", check_same_thread=False)
        self.cursor = self.db_conn.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS baseline (path TEXT PRIMARY KEY, hash TEXT)")
        self.db_conn.commit()

    def get_stored_hash(self, path):
        """Tiered Lookup: Check RAM, then check Local DB."""
        if path in self.last_hashes:
            return self.last_hashes[path]
        
        self.cursor.execute("SELECT hash FROM baseline WHERE path=?", (path,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def update_hash_storage(self, path, new_hash):
        """Tiered Storage: RAM first, Overflow to DB."""
        # If RAM exceeds limit, move the oldest entry to DB
        if len(self.last_hashes) >= self.ram_limit:
            old_path, old_hash = self.last_hashes.popitem()
            self.cursor.execute("INSERT OR REPLACE INTO baseline VALUES (?, ?)", (old_path, old_hash))
            self.db_conn.commit()
        
        self.last_hashes[path] = new_hash

    def purge_hash(self, path):
        """Cleanup: Remove from RAM and DB when file is deleted."""
        if path in self.last_hashes:
            del self.last_hashes[path]
        self.cursor.execute("DELETE FROM baseline WHERE path=?", (path,))
        self.db_conn.commit()

    def check_honeypot(self, filepath):
        return os.path.basename(filepath) in self.honeypots

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            new_hash = self.hash_func(file_path)
            old_hash = self.get_stored_hash(file_path) # Tiered check
            
            is_honeypot = self.check_honeypot(file_path)
            risk = 100 if is_honeypot else 20
            desc = "CRITICAL: Honeypot Modified!" if is_honeypot else "File content changed."
            
            # Compare using Tiered Logic
            if old_hash and old_hash != new_hash:
                desc += " (Integrity Violation: Hash Changed)"
                risk += 20

            self.update_hash_storage(file_path, new_hash)
            
            self.callback({
                "event_type": "file_modified",
                "file_path": file_path,
                "description": desc,
                "risk_score": min(risk, 100) # Ensure key is 'risk_score' for server
            })

    def on_deleted(self, event):
        if not event.is_directory:
            is_honeypot = self.check_honeypot(event.src_path)
            
            # CLEARANCE: Wipe hash from RAM and DB
            self.purge_hash(event.src_path)
            
            self.callback({
                "event_type": "file_deleted",
                "file_path": event.src_path,
                "description": "CRITICAL: Honeypot Deleted!" if is_honeypot else "Log file removed!",
                "risk_score": 100 if is_honeypot else 80
            })

    def on_created(self, event):
        if not event.is_directory:
            new_hash = self.hash_func(event.src_path)
            self.update_hash_storage(event.src_path, new_hash)
            self.callback({
                "event_type": "file_created",
                "file_path": event.src_path,
                "description": "New file created.",
                "risk_score": 10
            })