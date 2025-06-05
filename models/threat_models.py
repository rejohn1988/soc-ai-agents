"""
Threat models for SOC system
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

class ThreatType(Enum):
    """Types of threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "dos"
    INSIDER_THREAT = "insider_threat"
    VULNERABILITY = "vulnerability"
    UNKNOWN = "unknown"

@dataclass
class ThreatIndicator:
    """Threat indicator (IoC)"""
    type: str  # ip, domain, hash, email, etc.
    value: str
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class ThreatActor:
    """Threat actor profile"""
    name: str
    aliases: List[str]
    motivation: str
    capabilities: List[str]
    targets: List[str]
    ttps: List[str]  # Tactics, Techniques, and Procedures
    active: bool
    first_seen: datetime
    last_seen: datetime

@dataclass
class ThreatModel:
    """Comprehensive threat model"""
    id: str
    name: str
    type: ThreatType
    description: str
    severity: str
    confidence: float
    indicators: List[ThreatIndicator]
    affected_systems: List[str]
    mitigation_steps: List[str]
    detected_at: datetime
    updated_at: datetime
    threat_actor: Optional[ThreatActor] = None
    false_positive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type.value,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'indicators': [
                {
                    'type': ind.type,
                    'value': ind.value,
                    'confidence': ind.confidence
                } for ind in self.indicators
            ],
            'affected_systems': self.affected_systems,
            'mitigation_steps': self.mitigation_steps,
            'detected_at': self.detected_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'threat_actor': self.threat_actor.name if self.threat_actor else None,
            'false_positive': self.false_positive
        }
    
    def calculate_risk_score(self) -> float:
        """Calculate risk score"""
        severity_scores = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.3,
            'info': 0.1
        }
        
        base_score = severity_scores.get(self.severity.lower(), 0.5)
        return base_score * self.confidence
