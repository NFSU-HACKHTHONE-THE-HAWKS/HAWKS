from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import Alert, AgentStatus
import time
from datetime import datetime

router = APIRouter()

@router.post("/alerts")
async def create_alert(data: dict, db: Session = Depends(get_db)):
    try:
        # Step A: Check if this is an NTFS event to add Metadata wording
        event_type = data.get("event_type")
        description = data.get("description")
        
        if event_type == "NTFS_TAMPER":
            
            description = "CRITICAL TIMESTOMP: Unauthorized modification of file timestamps detected."

        new_alert = Alert(
            agent_id=data.get("agent_id"),
            event_type=event_type,
            risk_score=data.get("risk_score"),
            description=description, 
            process_name=data.get("process_name", "Unknown"),
            command_line=data.get("command_line", "N/A"),
            file_path=data.get("file_path") 
        )
        db.add(new_alert)
        # AI Verdict logic (if score >= 80)
        if new_alert.risk_score >= 80:
            # ... (purana AI logic yahan rahega) ...
            pass

        db.commit()
        return {"status": "success"}
    except Exception as e:
        db.rollback()
        return {"status": "error", "message": str(e)}
@router.post("/ntfs-alert")
async def create_ntfs_alert(data: dict, db: Session = Depends(get_db)):
    try:
        new_alert = Alert(
            agent_id=data.get("agent_id", "REHANT-CHAUDHARI"),
            event_type="NTFS_TAMPER",
            file_path=data.get("file_path"),
            risk_score=data.get("risk_score", 95),
            description=data.get("description")
        )
        db.add(new_alert)
        db.commit()
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.post("/heartbeat/{agent_id}")
async def update_heartbeat(agent_id: str, db: Session = Depends(get_db)):
    status_entry = db.query(AgentStatus).filter(AgentStatus.agent_id == agent_id).first()
    if not status_entry:
        status_entry = AgentStatus(agent_id=agent_id, last_seen=time.time(), status="Online")
        db.add(status_entry)
    else:
        status_entry.last_seen = time.time()
        status_entry.status = "Online"
    db.commit()
    return {"status": "alive"}

@router.get("/dashboard-stats")
async def get_stats(db: Session = Depends(get_db)):
    latest_alerts = db.query(Alert).order_by(Alert.id.desc()).limit(10).all()
    current_time = time.time()
    active_agents = db.query(AgentStatus).filter(AgentStatus.last_seen > (current_time - 60)).count()
    critical_threats = db.query(Alert).filter(Alert.risk_score >= 80).count()
    
    return {
        "active_agents": active_agents,
        "critical_threats": critical_threats,
        "latest_alerts": latest_alerts, 
        "system_status": "Stable" if critical_threats == 0 else "Under Attack"
    }