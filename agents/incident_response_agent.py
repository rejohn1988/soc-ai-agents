import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass

from .base_agent import BaseAgent, AgentMessage, ThreatEvent


@dataclass
class SimpleIncident:
    """Simple incident structure"""
    incident_id: str
    threat_event_id: str
    severity: str
    threat_score: float
    created_at: datetime
    status: str = "open"
    response_actions: List[str] = None
    
    def __post_init__(self):
        if self.response_actions is None:
            self.response_actions = []


class IncidentResponseAgent(BaseAgent):
    """Simple Incident Response Agent"""
    
    def __init__(self, agent_id: str = "incident_responder", config: Dict[str, Any] = None):
        super().__init__(agent_id, "IncidentResponseAgent", config)
        
        self.capabilities.update({
            'respond_incidents': True,
            'generate_reports': True
        })
        
        self.active_incidents: Dict[str, SimpleIncident] = {}
        
    async def initialize(self):
        """Initialize incident response agent"""
        self.logger.info("Initializing Simple Incident Response Agent...")
        self.logger.info("Simple Incident Response Agent initialized")
    
    async def process_message(self, message: AgentMessage):
        """Process incoming messages"""
        try:
            if message.message_type == "threat_detected":
                await self._handle_threat_detection(message)
            else:
                self.logger.warning(f"Unknown message type: {message.message_type}")
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    async def _handle_threat_detection(self, message: AgentMessage):
        """Handle threat detection messages"""
        try:
            content = message.content
            threat_event_data = content.get('event', {})
            analysis_result = content.get('analysis', {})
            
            # Create incident
            incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            threat_score = analysis_result.get('threat_score', 0.0)
            
            # Determine severity
            if threat_score >= 9.0:
                severity = "critical"
            elif threat_score >= 7.0:
                severity = "high"
            elif threat_score >= 4.0:
                severity = "medium"
            else:
                severity = "low"
            
            incident = SimpleIncident(
                incident_id=incident_id,
                threat_event_id=threat_event_data.get('event_id', 'unknown'),
                severity=severity,
                threat_score=threat_score,
                created_at=datetime.now()
            )
            
            # Store incident
            self.active_incidents[incident_id] = incident
            
            # Determine response actions
            response_actions = self._determine_response_actions(incident)
            incident.response_actions = response_actions
            
            # Execute responses
            await self._execute_responses(incident)
            
            self.logger.info(f"Created incident {incident_id} with {len(response_actions)} response actions")
            
        except Exception as e:
            self.logger.error(f"Error handling threat detection: {e}")
    
    def _determine_response_actions(self, incident: SimpleIncident) -> List[str]:
        """Determine response actions based on incident"""
        actions = ["alert"]  # Always alert
        
        if incident.threat_score >= 8.0:
            actions.extend(["block_ip", "escalate"])
        elif incident.threat_score >= 6.0:
            actions.extend(["monitor", "investigate"])
        elif incident.threat_score >= 4.0:
            actions.append("monitor")
        
        if incident.severity == "critical":
            actions.append("isolate")
        
        return list(set(actions))  # Remove duplicates
    
    async def _execute_responses(self, incident: SimpleIncident):
        """Execute response actions"""
        for action in incident.response_actions:
            try:
                result = await self._execute_action(action, incident)
                self.logger.info(f"Executed {action}: {result}")
            except Exception as e:
                self.logger.error(f"Failed to execute {action}: {e}")
    
    async def _execute_action(self, action: str, incident: SimpleIncident) -> str:
        """Execute a specific action"""
        if action == "alert":
            message = f"🚨 INCIDENT: {incident.incident_id} - Severity: {incident.severity.upper()}"
            self.logger.warning(message)
            return "Alert sent"
        
        elif action == "block_ip":
            self.logger.info("Simulated: IP blocked at firewall")
            return "IP blocked"
        
        elif action == "isolate":
            self.logger.info("Simulated: Host isolated from network")
            return "Host isolated"
        
        elif action == "escalate":
            self.logger.critical(f"ESCALATED: Incident {incident.incident_id}")
            return "Incident escalated"
        
        elif action == "monitor":
            self.logger.info("Enhanced monitoring activated")
            return "Monitoring enhanced"
        
        elif action == "investigate":
            self.logger.info("Automated investigation initiated")
            return "Investigation started"
        
        else:
            return f"Unknown action: {action}"
    
    async def get_active_incidents(self) -> List[Dict[str, Any]]:
        """Get all active incidents"""
        return [
            {
                'incident_id': inc.incident_id,
                'severity': inc.severity,
                'threat_score': inc.threat_score,
                'created_at': inc.created_at.isoformat(),
                'status': inc.status,
                'response_actions': inc.response_actions
            }
            for inc in self.active_incidents.values()
        ]
    
    async def get_incident_status(self, incident_id: str) -> Dict[str, Any]:
        """Get status of specific incident"""
        if incident_id in self.active_incidents:
            incident = self.active_incidents[incident_id]
            return {
                'incident_id': incident.incident_id,
                'severity': incident.severity,
                'threat_score': incident.threat_score,
                'status': incident.status,
                'response_actions': incident.response_actions,
                'created_at': incident.created_at.isoformat()
            }
        return {'error': 'Incident not found'}
    
    async def analyze_event(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze event for incident response"""
        return {
            'response_capability': True,
            'recommended_actions': ['alert', 'monitor']
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Cleaning up Incident Response Agent")
