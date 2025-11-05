# Pydantic schemas (placeholder)
from pydantic import BaseModel

class AttackEventCreate(BaseModel):
    source_ip: str
    service: str
    severity: str
