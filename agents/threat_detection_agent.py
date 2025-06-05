"""
Threat Detection Agent
Specialized AI agent for detecting and analyzing security threats
"""

import asyncio
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque

from .base_agent import BaseAgent, AgentMessage, ThreatEvent


class ThreatDetectionAgent(BaseAgent):
    """
    AI Agent specialized in threat detection and analysis
    Uses pattern matching, anomaly detection, and threat intelligence
    """
    
    def __init__(self, agent_id: str = "threat_detector", config: Dict[str, Any] = None):
        super().__init__(agent_id, "ThreatDetectionAgent", config)
        
        # Set capabilities
        self.capabilities.update({
            'analyze_threats': True,
            'correlate_events': True,
            'generate_reports': True
        })
        
        # Threat detection configuration
        self.detection_rules = self._load_detection_rules()
        self.threat_scores = defaultdict(float)
        self.event_history = deque(maxlen=10000)  # Keep last 10k events
        self.ip_reputation = {}
        
        # Anomaly detection parameters
        self.baseline_metrics = {
            'login_attempts_per_hour': 50,
            'failed_logins_threshold': 10,
            'data_transfer_threshold': 1000000,  # 1MB
            'unusual_ports': [1433, 3389, 22, 23, 445]
        }
        
        # Threat patterns (simplified - in production use ML models)
        self.threat_patterns = {
            'brute_force': {
                'pattern': r'failed.*login.*attempt',
                'threshold': 5,
                'time_window': 300  # 5 minutes
            },
            'sql_injection': {
                'pattern': r'(union.*select|drop.*table|insert.*into)',
                'threshold': 1,
                'severity': 'high'
            },
            'malware_communication': {
                'pattern': r'\.exe.*download|suspicious.*payload',
                'threshold': 1,
                'severity': 'critical'
            },
            'port_scan': {
                'pattern': r'port.*scan|nmap',
                'threshold': 3,
                'time_window': 60
            }
        }
    
    async def initialize(self):
        """Initialize threat detection resources"""
        self.logger.info("Initializing Threat Detection Agent...")
        
        # Load threat intelligence feeds (simulated)
        await self._load_threat_intelligence()
        
        # Initialize ML models (simulated)
        await self._initialize_ml_models()
        
        self.logger.info("Threat Detection Agent initialized successfully")
    
    async def _load_threat_intelligence(self):
        """Load threat intelligence data"""
        # Simulated threat intelligence - in production, load from feeds
        self.known_bad_ips = {
            '192.168.1.100': 'known_malware_c2',
            '10.0.0.50': 'brute_force_source',
            '172.16.1.200': 'data_exfiltration'
        }
        
        self.suspicious_domains = [
            'malicious-site.com',
            'phishing-example.org',
            'suspicious-download.net'
        ]
        
        self.logger.info(f"Loaded {len(self.known_bad_ips)} malicious IPs")
    
    async def _initialize_ml_models(self):
        """Initialize machine learning models for anomaly detection"""
        # Placeholder for ML model initialization
        self.anomaly_model = {
            'trained': True,
            'accuracy': 0.95,
            'last_updated': datetime.now()
        }
        self.logger.info("ML models initialized")
    
    def _load_detection_rules(self) -> List[Dict[str, Any]]:
        """Load threat detection rules"""
        return [
            {
                'name': 'Multiple Failed Logins',
                'condition': 'failed_login_count > 5 AND time_window < 300',
                'severity': 'medium',
                'action': 'alert'
            },
            {
                'name': 'Suspicious File Download',
                'condition': 'file_extension in [".exe", ".bat", ".ps1"] AND source_external',
                'severity': 'high',
                'action': 'block_and_alert'
            },
            {
                'name': 'Unusual Data Transfer',
                'condition': 'data_transfer > baseline * 10',
                'severity': 'medium',
                'action': 'monitor'
            }
        ]
    
    async def process_message(self, message: AgentMessage):
        """Process incoming messages"""
        try:
            if message.message_type == "threat_event":
                event_data = message.content.get("event", {})
                event = ThreatEvent(**event_data)
                result = await self.analyze_event(event)
                
                if result.get('is_threat', False):
                    await self._handle_threat_detection(event, result)
            
            elif message.message_type == "batch_analysis":
                events = message.content.get("events", [])
                await self._analyze_event_batch(events)
            
            elif message.message_type == "update_intelligence":
                await self._update_threat_intelligence(message.content)
            
            else:
                self.logger.warning(f"Unknown message type: {message.message_type}")
        
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    async def analyze_event(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze a single security event for threats"""
        start_time = datetime.now()
        
        try:
            # Add event to history
            self.event_history.append(event)
            self.update_metrics('events_processed', 1)
            
            # Analysis results
            analysis_result = {
                'event_id': event.event_id,
                'is_threat': False,
                'threat_score': 0.0,
                'threat_types': [],
                'recommendations': [],
                'confidence': 0.0
            }
            
            # 1. IP Reputation Check
            ip_score = await self._check_ip_reputation(event.source_ip)
            analysis_result['threat_score'] += ip_score
            
            # 2. Pattern Matching
            pattern_score = await self._pattern_analysis(event)
            analysis_result['threat_score'] += pattern_score['score']
            analysis_result['threat_types'].extend(pattern_score['types'])
            
            # 3. Anomaly Detection
            anomaly_score = await self._anomaly_detection(event)
            analysis_result['threat_score'] += anomaly_score
            
            # 4. Behavioral Analysis
            behavior_score = await self._behavioral_analysis(event)
            analysis_result['threat_score'] += behavior_score
            
            # 5. Correlation with Historical Events
            correlation_score = await self._event_correlation(event)
            analysis_result['threat_score'] += correlation_score
            
            # Determine if it's a threat
            if analysis_result['threat_score'] > 7.0:
                analysis_result['is_threat'] = True
                analysis_result['confidence'] = min(analysis_result['threat_score'] / 10.0, 1.0)
                self.update_metrics('threats_detected', 1)
            
            # Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
            
            # Update response time metrics
            response_time = (datetime.now() - start_time).total_seconds()
            current_avg = self.metrics['response_time_avg']
            processed = self.metrics['events_processed']
            self.metrics['response_time_avg'] = (current_avg * (processed - 1) + response_time) / processed
            
            return analysis_result
        
        except Exception as e:
            self.logger.error(f"Error analyzing event {event.event_id}: {e}")
            return {'event_id': event.event_id, 'is_threat': False, 'error': str(e)}
    
    async def _check_ip_reputation(self, ip_address: str) -> float:
        """Check IP address against threat intelligence"""
        score = 0.0
        
        if ip_address in self.known_bad_ips:
            score += 5.0
            self.logger.warning(f"Known malicious IP detected: {ip_address}")
        
        # Check if IP is from suspicious geolocation (simulated)
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                score += 0.0  # Private IPs are less suspicious
            else:
                score += 1.0  # External IPs get slight score increase
        except ValueError:
            score += 2.0  # Invalid IP format is suspicious
        
        return score
    
    async def _pattern_analysis(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze event against known threat patterns"""
        result = {'score': 0.0, 'types': []}
        
        event_text = f"{event.description} {event.event_type}".lower()
        
        for threat_type, pattern_config in self.threat_patterns.items():
            pattern = pattern_config['pattern']
            
            if re.search(pattern, event_text, re.IGNORECASE):
                threat_score = pattern_config.get('severity_score', 3.0)
                result['score'] += threat_score
                result['types'].append(threat_type)
                
                self.logger.info(f"Pattern match: {threat_type} in event {event.event_id}")
        
        return result
    
    async def _anomaly_detection(self, event: ThreatEvent) -> float:
        """Detect anomalies using statistical analysis"""
        score = 0.0
        
        # Check for unusual timing patterns
        hour = event.timestamp.hour
        if hour < 6 or hour > 22:  # Outside business hours
            score += 1.0
        
        # Check for unusual ports
        if 'port' in event.raw_data:
            port = event.raw_data['port']
            if port in self.baseline_metrics['unusual_ports']:
                score += 2.0
        
        # Check for high frequency events from same source
        recent_events = [
            e for e in self.event_history 
            if e.source_ip == event.source_ip and 
            (datetime.now() - e.timestamp).total_seconds() < 300
        ]
        
        if len(recent_events) > 10:
            score += 2.0
        
        return score
    
    async def _behavioral_analysis(self, event: ThreatEvent) -> float:
        """Analyze behavioral patterns"""
        score = 0.0
        
        # Analyze user behavior patterns (simulated)
        if event.event_type == 'login':
            # Check for unusual login patterns
            if 'failed' in event.description.lower():
                score += 1.0
            
            # Check for multiple simultaneous sessions
            if 'concurrent_sessions' in event.raw_data:
                if event.raw_data['concurrent_sessions'] > 3:
                    score += 1.5
        
        elif event.event_type == 'file_access':
            # Check for sensitive file access
            if any(sensitive in event.description.lower() 
                   for sensitive in ['passwd', 'shadow', 'config', 'secret']):
                score += 2.0
        
        return score
    
    async def _event_correlation(self, event: ThreatEvent) -> float:
        """Correlate current event with historical events"""
        score = 0.0
        
        # Look for related events in recent history
        related_events = [
            e for e in self.event_history 
            if (e.source_ip == event.source_ip or e.destination_ip == event.destination_ip) and
            (datetime.now() - e.timestamp).total_seconds() < 3600  # Last hour
        ]
        
        # Score based on number of related events
        if len(related_events) > 5:
            score += 1.5
        elif len(related_events) > 2:
            score += 1.0
        
        # Check for escalation patterns
        severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        if len(related_events) >= 2:
            current_severity = severity_levels.get(event.severity, 1)
            prev_severity = severity_levels.get(related_events[-1].severity, 1)
            
            if current_severity > prev_severity:
                score += 1.0  # Escalating severity
        
        return score
    
    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        threat_score = analysis_result['threat_score']
        threat_types = analysis_result['threat_types']
        
        if threat_score > 8.0:
            recommendations.append("IMMEDIATE ACTION: Isolate affected systems")
            recommendations.append("Notify incident response team")
        
        elif threat_score > 5.0:
            recommendations.append("Increase monitoring for related activities")
            recommendations.append("Review system logs for additional indicators")
        
        if 'brute_force' in threat_types:
            recommendations.append("Consider implementing account lockout policies")
            recommendations.append("Review authentication logs")
        
        if 'sql_injection' in threat_types:
            recommendations.append("Check web application security")
            recommendations.append("Review database access logs")
        
        if 'malware_communication' in threat_types:
            recommendations.append("Scan affected systems for malware")
            recommendations.append("Block suspicious network communications")
        
        return recommendations
    
    async def _handle_threat_detection(self, event: ThreatEvent, analysis_result: Dict[str, Any]):
        """Handle detected threats"""
        threat_score = analysis_result['threat_score']
        
        # Send alert to incident response agent
        await self.send_message(
            "incident_responder",
            "threat_detected",
            {
                'event': event.__dict__,
                'analysis': analysis_result,
                'priority': 'high' if threat_score > 7.0 else 'medium'
            }
        )
        
        # Log the threat
        self.logger.warning(
            f"THREAT DETECTED: {event.event_id} - Score: {threat_score:.2f} - "
            f"Types: {', '.join(analysis_result['threat_types'])}"
        )
    
    async def _analyze_event_batch(self, events: List[Dict[str, Any]]):
        """Analyze multiple events efficiently"""
        results = []
        
        for event_data in events:
            event = ThreatEvent(**event_data)
            result = await self.analyze_event(event)
            results.append(result)
        
        # Send batch results
        await self.send_message(
            "orchestrator",
            "batch_analysis_complete",
            {'results': results, 'total_processed': len(events)}
        )
    
    async def _update_threat_intelligence(self, update_data: Dict[str, Any]):
        """Update threat intelligence data"""
        if 'malicious_ips' in update_data:
            self.known_bad_ips.update(update_data['malicious_ips'])
        
        if 'suspicious_domains' in update_data:
            self.suspicious_domains.extend(update_data['suspicious_domains'])
        
        self.logger.info("Threat intelligence updated")
    
    async def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Cleaning up Threat Detection Agent resources")
        self.event_history.clear()
        self.threat_scores.clear()


# Example usage
async def main():
    # Create and test the threat detection agent
    agent = ThreatDetectionAgent()
    await agent.start()
    
    # Create a test event
    test_event = ThreatEvent(
        event_id="test_001",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        event_type="login",
        severity="medium",
        description="failed login attempt from external IP",
        timestamp=datetime.now(),
        raw_data={"port": 22, "user": "admin"}
    )
    
    # Analyze the event
    result = await agent.analyze_event(test_event)
    print(f"Analysis result: {result}")
    
    await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
