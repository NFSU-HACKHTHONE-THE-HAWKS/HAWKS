import threading
import datetime
import time
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from database import engine, Base, SessionLocal
from routes import router
from models import Alert 

# 1. Create tables in the database
# IMPORTANT: Delete your old forensics.db file first so it recreates with the 'description' column!
Base.metadata.create_all(bind=engine)

app = FastAPI(title="DAFDN Command Center")
# --- CORS FIX START ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Isse browser block nahi karega
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# --- CORS FIX END ---
# --- Automated Log Rotation Logic ---
def automated_rotation():
    """
    Background task that wipes the Alert table every 24 hours.
    This ensures the dashboard stays fast and only shows recent threats.
    """
    last_cleanup_day = datetime.datetime.now().day
    
    while True:
        # Check every 10 minutes
        time.sleep(600) 
        
        current_time = datetime.datetime.now()
        current_day = current_time.day
        
        # If the day has rolled over
        if current_day != last_cleanup_day:
            print(f"[*] {current_time}: NEW DAY DETECTED. Rotating Forensic Logs...")
            try:
                # Use a fresh session for the background task
                db = SessionLocal()
                # Targets only the Alerts history, keeping AgentStatus intact
                db.query(Alert).delete() 
                db.commit()
                db.close()
                print("[+] Command Center Database: Alert history cleared for the new day.")
            except Exception as e:
                print(f"[!] Rotation Failed: {e}")
            
            last_cleanup_day = current_day

# Start the rotation thread as a 'daemon'
rotation_thread = threading.Thread(target=automated_rotation, daemon=True)
rotation_thread.start()
# ------------------------------------

# Include our API routes
app.include_router(router)

@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "DAFDN Server is running. Monitoring for Anti-Forensics behavior."
    }