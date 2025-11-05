from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON
from sqlalchemy.sql import func
from .database import Base

class AttackEvent(Base):
    __tablename__ = "attack_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Attack details
    service = Column(String(20), index=True)  # ssh, ftp, http
    source_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    payload = Column(Text, nullable=True)
    command = Column(String(500), nullable=True)
    
    # Severity classification
    severity = Column(String(20), index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # AI/ML predictions
    ai_label = Column(String(20), nullable=True)  # benign, anomaly, malicious
    threat_score = Column(Float, default=0.0)
    
    # Additional metadata
    geolocation = Column(JSON, nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    def __repr__(self):
        return f"<AttackEvent {self.id} - {self.service} from {self.source_ip}>"
