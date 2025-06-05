"""
User Behavior Analysis Agent
Specialized AI agent for detecting anomalous user behavior and insider threats
"""

import asyncio
import json
import sqlite3
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque
from enum import Enum

from .base_agent import BaseAgent, AgentMessage, ThreatEvent


class BehaviorAnomalyType(Enum):
    """Types of behavior anomalies"""
    TIME_ANOMALY = "time_anomaly"
    ACCESS_ANOMALY = "access_anomaly"
    VOLUME_ANOMALY = "volume_anomaly"
    LOCATION_ANOMALY = "location_anomaly"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"


class RiskLevel(Enum):
    """User risk levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class UserProfile:
    """User behavior profile"""
    user_id: str
    typical_login_hours: List[int]
    typical_systems: List[str]
    typical_locations: List[str]
    average_session_duration: float
    average_file_accesses: int
    baseline_data_volume: float
    last_updated: datetime
    risk_level: RiskLevel = RiskLevel.LOW


@dataclass
class BehaviorAnomaly:
    """Detected behavior anomaly"""
    anomaly_id: str
    user_id: str
    anomaly_type: BehaviorAnomalyType
    description: str
    severity_score: float
    evidence: Dict[str, Any]
    baseline_comparison: Dict[str, Any]
    detected_at: datetime
    status: str = "active"


class UserBehaviorAnalysisAgent(BaseAgent):
    """AI Agent specialized in user behavior analysis and insider threat detection"""
    
    def __init__(self, agent_id: str = "behavior_analyst", config: Dict[str, Any] = None):
        super().__init__(agent_id, "UserBehaviorAnalysisAgent", config)
        
        self.capabilities.update({
            'analyze_behavior': True,
            'detect_anomalies': True,
            'profile_users': True,
            'insider_threat_detection': True
        })
        
        self.user_profiles: Dict[str, UserProfile] = {}
        self.active_anomalies: Dict[str, BehaviorAnomaly] = {}
        self.recent_activities: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        self.anomaly_threshold = 2.5
    
    async def initialize(self):
        """Initialize user behavior analysis agent"""
        self.logger.info("Initializing User Behavior Analysis Agent...")
        
        try:
            self.behavior_db = sqlite3.connect(':memory:')  # Use in-memory DB for testing
            cursor = self.behavior_db.cursor()
            
            cursor.execute('''
                CREATE TABLE user_profiles (
                    user_id TEXT PRIMARY KEY,
                    profile_data TEXT,
                    last_updated TEXT,
                    risk_level TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE anomalies (
                    anomaly_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    anomaly_type TEXT,
                    severity_score REAL,
                    description TEXT,
                    detected_at TEXT,
                    status TEXT
                )
            ''')
            
            self.behavior_db.commit()
            self.logger.info("User Behavior Analysis Agent initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize behavior agent: {e}")
    
    async def process_message(self, message: AgentMessage):
        """Process incoming messages"""
        try:
            if message.message_type == "user_login":
                await self._analyze_login_behavior(message)
            elif message.message_type == "file_access":
                await self._analyze_file_access(message)
            else:
                self.logger.warning(f"Unknown message type: {message.message_type}")
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    async def _analyze_login_behavior(self, message: AgentMessage):
        """Analyze user login behavior for anomalies"""
        try:
            event_data = message.content
            user_id = event_data.get('user_id')
            login_time = datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat()))
            location = event_data.get('location', 'unknown')
            
            if not user_id:
                return
            
            profile = await self._get_or_create_user_profile(user_id)
            
            login_hour = login_time.hour
            
            # Check for time anomaly (outside business hours)
            if login_hour < 6 or login_hour > 22:
                anomaly = BehaviorAnomaly(
                    anomaly_id=f"TA-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    user_id=user_id,
                    anomaly_type=BehaviorAnomalyType.TIME_ANOMALY,
                    description=f"Login at unusual hour: {login_hour}:00",
                    severity_score=6.0,
                    evidence={'login_hour': login_hour, 'location': location},
                    baseline_comparison={'typical_hours': profile.typical_login_hours},
                    detected_at=datetime.now()
                )
                await self._create_behavior_anomaly(anomaly)
            
            # Check for location anomaly
            if location not in profile.typical_locations and location != 'unknown':
                anomaly = BehaviorAnomaly(
                    anomaly_id=f"LA-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    user_id=user_id,
                    anomaly_type=BehaviorAnomalyType.LOCATION_ANOMALY,
                    description=f"Login from unusual location: {location}",
                    severity_score=5.5,
                    evidence={'location': location},
                    baseline_comparison={'typical_locations': profile.typical_locations},
                    detected_at=datetime.now()
                )
                await self._create_behavior_anomaly(anomaly)
            
        except Exception as e:
            self.logger.error(f"Error analyzing login behavior: {e}")
    
    async def _analyze_file_access(self, message: AgentMessage):
        """Analyze file access patterns for anomalies"""
        try:
            event_data = message.content
            user_id = event_data.get('user_id')
            file_path = event_data.get('file_path', '')
            
            if not user_id:
                return
            
            # Check for sensitive file access
            sensitive_indicators = ['password', 'secret', 'confidential', 'passwd']
            is_sensitive = any(indicator in file_path.lower() for indicator in sensitive_indicators)
            
            if is_sensitive:
                current_hour = datetime.now().hour
                if current_hour < 6 or current_hour > 22:  # After hours
                    anomaly = BehaviorAnomaly(
                        anomaly_id=f"FA-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        user_id=user_id,
                        anomaly_type=BehaviorAnomalyType.ACCESS_ANOMALY,
                        description=f"After-hours access to sensitive file: {file_path}",
                        severity_score=7.5,
                        evidence={'file_path': file_path, 'access_time': datetime.now().isoformat()},
                        baseline_comparison={},
                        detected_at=datetime.now()
                    )
                    await self._create_behavior_anomaly(anomaly)
            
        except Exception as e:
            self.logger.error(f"Error analyzing file access: {e}")
    
    async def _get_or_create_user_profile(self, user_id: str) -> UserProfile:
        """Get existing user profile or create new one"""
        if user_id in self.user_profiles:
            return self.user_profiles[user_id]
        
        profile = UserProfile(
            user_id=user_id,
            typical_login_hours=[9, 10, 11, 12, 13, 14, 15, 16, 17],
            typical_systems=[],
            typical_locations=['Office', 'VPN'],
            average_session_duration=240.0,
            average_file_accesses=10,
            baseline_data_volume=1000000.0,
            last_updated=datetime.now()
        )
        
        self.user_profiles[user_id] = profile
        self.logger.info(f"Created new user profile for {user_id}")
        return profile
    
    async def _create_behavior_anomaly(self, anomaly: BehaviorAnomaly):
        """Create and store a behavior anomaly"""
        try:
            self.active_anomalies[anomaly.anomaly_id] = anomaly
            
            self.logger.warning(
                f"BEHAVIOR ANOMALY: {anomaly.anomaly_id} - "
                f"User: {anomaly.user_id} - {anomaly.description}"
            )
            
            # Update metrics
            self.update_metrics('anomalies_detected', 1)
            
        except Exception as e:
            self.logger.error(f"Error creating behavior anomaly: {e}")
    
    async def get_user_risk_summary(self) -> Dict[str, Any]:
        """Get summary of user risk levels"""
        risk_summary = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for profile in self.user_profiles.values():
            risk_summary[profile.risk_level.value] += 1
        
        return {
            'total_users': len(self.user_profiles),
            'risk_breakdown': risk_summary,
            'high_risk_users': []
        }
    
    async def get_active_anomalies(self) -> List[Dict[str, Any]]:
        """Get all active behavior anomalies"""
        return [
            {
                'anomaly_id': a.anomaly_id,
                'user_id': a.user_id,
                'type': a.anomaly_type.value,
                'description': a.description,
                'severity_score': a.severity_score,
                'detected_at': a.detected_at.isoformat(),
                'status': a.status
            }
            for a in self.active_anomalies.values()
        ]
    
    async def analyze_event(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze threat event for user behavior implications"""
        return {
            'behavior_indicators': [],
            'requires_behavioral_analysis': False
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Cleaning up User Behavior Analysis Agent")
        if hasattr(self, 'behavior_db'):
            self.behavior_db.close()


# Test function
async def test_behavior_agent():
    """Test the user behavior analysis agent"""
    agent = UserBehaviorAnalysisAgent()
    await agent.start()
    
    test_message = AgentMessage(
        agent_id="security_monitor",
        message_type="user_login",
        content={
            'user_id': 'john.doe',
            'timestamp': datetime.now().replace(hour=2).isoformat(),
            'location': 'Unknown_Location'
        },
        timestamp=datetime.now()
    )
    
    await agent.receive_message(test_message)
    await asyncio.sleep(1)
    
    anomalies = await agent.get_active_anomalies()
    print(f"Behavior agent detected {len(anomalies)} anomalies")
    
    await agent.stop()
    return len(anomalies) > 0


if __name__ == "__main__":
    asyncio.run(test_behavior_agent())
