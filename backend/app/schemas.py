from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime

class SessionCreateResponse(BaseModel):
    session_id: str
    expires_at: datetime
    max_logs: int
    max_explain_calls: int

class IngestRequest(BaseModel):
    session_id: str
    source_type: str = Field(..., description="Must be one of: 'nginx', 'auth', 'syslog', 'custom'")
    logs: List[str]

class IngestResponse(BaseModel):
    status: str
    job_id: str
    ingested_count: int
    remaining_quota: int

class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    total_logs: int
    processed_logs: int
    failed_logs: int
    percent_complete: int

class Threat(BaseModel):
    id: str
    session_id: str
    threat_type: str
    severity: str
    severity_score: int
    confidence: float
    source_ip: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    is_private_ip: bool = False
    summary: Optional[str] = None
    explanation: Optional[str] = None
    classification_source: str
    attack_pattern: Optional[str] = None
    model_name: Optional[str] = None
    evidence: Optional[List[str]] = None
    detected_at: datetime

class ThreatResponse(BaseModel):
    threats: List[Threat]
    total: int
    by_severity: Dict[str, int]
    next_cursor: Optional[str] = None

class ExplainRequest(BaseModel):
    session_id: str
    threat_id: str

class ExplainResponse(BaseModel):
    threat_id: str
    explanation: str
    mitre_tactic: str
    recommended_actions: List[str]
    cached: bool

class SessionQuotaResponse(BaseModel):
    max_logs: int
    used_logs: int
    max_explain_calls: int
    used_explain_calls: int
