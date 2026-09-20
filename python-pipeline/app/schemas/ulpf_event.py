from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class ULPFEvent(BaseModel):
    event_id: str
    raw_event_id: str
    timestamp: Optional[datetime] = None
    source_type: str = "unknown"
    source_vendor: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    message: str
    fields: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.0
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    schema_version: str = "1.0"
    processing_status: str = "normalized"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
