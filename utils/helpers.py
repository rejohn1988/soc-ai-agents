"""
Helper utilities for SOC system
"""

from datetime import datetime
from typing import Dict, Any, Optional
import json
import re

def format_alert(alert: Dict[str, Any]) -> str:
    """Format alert for display"""
    severity_emoji = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'info': 'ℹ️'
    }
    
    severity = alert.get('severity', 'medium')
    emoji = severity_emoji.get(severity, '⚪')
    
    return f"{emoji} [{severity.upper()}] {alert.get('type', 'Unknown')} - {alert.get('description', 'No description')}"

def validate_config(config: Dict[str, Any]) -> bool:
    """Validate configuration dictionary"""
    required_keys = ['agents', 'database', 'logging']
    
    for key in required_keys:
        if key not in config:
            return False
    
    return True

def parse_timestamp(timestamp: str) -> Optional[datetime]:
    """Parse timestamp string to datetime object"""
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp, fmt)
        except ValueError:
            continue
    
    return None

def sanitize_input(input_str: str) -> str:
    """Sanitize user input"""
    # Remove potentially dangerous characters
    return re.sub(r'[<>&"'`]', '', input_str)

def calculate_risk_score(severity: str, confidence: float) -> float:
    """Calculate risk score based on severity and confidence"""
    severity_scores = {
        'critical': 1.0,
        'high': 0.8,
        'medium': 0.5,
        'low': 0.3,
        'info': 0.1
    }
    
    base_score = severity_scores.get(severity, 0.5)
    return base_score * confidence
