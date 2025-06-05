"""
Threat Intelligence Agent - Minimal Working Version
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Any

from .base_agent import BaseAgent, AgentMessage, ThreatEvent


class ThreatIntelligenceAgent(BaseAgent):
    """Minimal Threat Intelligence Agent"""
    
    def __init__(self, agent_id: str = "threat_intel", config: Dict[str, Any] = None):
        super().__init__(agent_id, "ThreatIntelligenceAgent", config)
        
        self.capabilities.update({
            'collect_intelligence': True,
            'enrich_events': True
        })
        
        # Simple threat intelligence database
        self.threat_indicators = {
            '203.0.113.666': {
                'type': 'malicious_ip',
                'threat_actor': 'APT29',
                'description': 'C2 server',
                'severity': 8,
                'confidence': 'high'
            },
            'http://malicious-site.com/payload.exe': {
                'type': 'malicious_url',
                'threat_actor': 'Unknown',
                'description': 'Malware download',
                'severity': 7,
                'confidence': 'high'
            },
            '198.51.100.100': {
                'type': 'malicious_ip',
                'threat_actor': 'Emotet',
                'description': 'Botnet C&C',
                'severity': 8,
                'confidence': 'high'
            }
        }
    
    async def initialize(self):
        """Initialize threat intelligence agent"""
        self.logger.info("Initializing Threat Intelligence Agent...")
        self.logger.info(f"Loaded {len(self.threat_indicators)} threat indicators")
    
    async def process_message(self, message: AgentMessage):
        """Process incoming messages"""
        pass
    
    async def enrich_event_with_intelligence(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event data with threat intelligence"""
        enrichment = {
            'indicators_found': [],
            'threat_actors': [],
            'campaigns': [],
            'severity_boost': 0,
            'confidence_score': 0.0
        }
        
        # Check source IP
        source_ip = event_data.get('source_ip', '')
        if source_ip in self.threat_indicators:
            indicator = self.threat_indicators[source_ip]
            enrichment['indicators_found'].append({
                'value': source_ip,
                'type': indicator['type'],
                'confidence': indicator['confidence'],
                'severity': indicator['severity'],
                'description': indicator['description']
            })
            enrichment['threat_actors'].append(indicator['threat_actor'])
            enrichment['severity_boost'] = indicator['severity'] * 0.5
            enrichment['confidence_score'] = 0.8
        
        # Check description for URLs
        description = event_data.get('description', '')
        for url, indicator in self.threat_indicators.items():
            if url.startswith('http') and url in description:
                enrichment['indicators_found'].append({
                    'value': url,
                    'type': indicator['type'],
                    'confidence': indicator['confidence'],
                    'severity': indicator['severity'],
                    'description': indicator['description']
                })
                enrichment['threat_actors'].append(indicator['threat_actor'])
                enrichment['severity_boost'] += indicator['severity'] * 0.5
                enrichment['confidence_score'] = max(enrichment['confidence_score'], 0.8)
        
        return enrichment
    
    async def get_intelligence_summary(self) -> Dict[str, Any]:
        """Get summary of threat intelligence"""
        return {
            'total_indicators': len(self.threat_indicators),
            'indicator_breakdown': {
                'malicious_ip': 2,
                'malicious_url': 1
            },
            'active_feeds': 3,
            'data_freshness': {
                'indicators_last_24h': len(self.threat_indicators),
                'indicators_last_week': len(self.threat_indicators)
            },
            'feed_metrics': {
                'indicators_collected': len(self.threat_indicators),
                'correlations_found': 0
            }
        }
    
    async def analyze_event(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze threat event using intelligence"""
        enrichment = await self.enrich_event_with_intelligence(event.__dict__)
        return {
            'intelligence_enrichment': enrichment,
            'has_intelligence_match': len(enrichment['indicators_found']) > 0
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Cleaning up Threat Intelligence Agent")
