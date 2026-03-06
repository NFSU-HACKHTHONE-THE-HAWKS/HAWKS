from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from database import Base
import datetime

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String)
    event_type = Column(String)
    risk_score = Column(Integer)
    # --- NEW: Added description column to store the forensic message ---
    description = Column(String, nullable=True) 
    # -----------------------------------------------------------------
    process_name = Column(String)
    command_line = Column(Text) # This can store process arguments or overflow data
    ai_verdict = Column(Text, nullable=True)
    file_path = Column(String, nullable=True)
    # Using utcnow for consistent forensic timelines
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class AgentStatus(Base):
    __tablename__ = "agent_status"
    
    agent_id = Column(String, primary_key=True)
    last_seen = Column(Float)
    status = Column(String, default="Online")

class NTFSAlert(Base):
    __tablename__ = "ntfs_alerts"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String)
    file_path = Column(String)
    si_time = Column(Float)
    fn_time = Column(Float)
    usn_time = Column(Float)
    risk_score = Column(Integer)
    description = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)