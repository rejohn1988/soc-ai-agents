#!/usr/bin/env python3
"""
Complete AI SOC System Demonstration
"""

import asyncio
import sys
from datetime import datetime
sys.path.insert(0, '.')

async def demonstrate_complete_soc():
    print("🚀 COMPLETE AI SOC SYSTEM DEMONSTRATION")
    print("="*60)
    
    try:
        # Import all agents
        from agents.base_agent import ThreatEvent, AgentMessage, AgentOrchestrator
        from agents.threat_detection_agent import ThreatDetectionAgent
        from agents.threat_intelligence_agent import ThreatIntelligenceAgent
        
        print("✅ AI agents loaded successfully")
        
        # Create SOC system
        orchestrator = AgentOrchestrator()
        threat_agent = ThreatDetectionAgent()
        intel_agent = ThreatIntelligenceAgent()
        
        orchestrator.register_agent(threat_agent)
        orchestrator.register_agent(intel_agent)
        
        await orchestrator.start_all_agents()
        await asyncio.sleep(1)
        
        print("🟢 SOC system operational")
        
        # Demonstrate threat detection with intelligence
        print("\n🎯 DEMONSTRATION: Intelligence-Enhanced Detection")
        print("-" * 50)
        
        apt_event = ThreatEvent(
            event_id="demo_001",
            source_ip="203.0.113.666",  # Known malicious IP
            destination_ip="10.0.0.1",
            event_type="connection",
            severity="high",
            description="Connection to http://malicious-site.com/payload.exe",
            timestamp=datetime.now(),
            raw_data={}
        )
        
        print(f"📍 Event: {apt_event.description}")
        
        # Intelligence enrichment
        intel_result = await intel_agent.enrich_event_with_intelligence(apt_event.__dict__)
        print(f"🌐 Intelligence: {len(intel_result['indicators_found'])} indicators")
        print(f"   Threat Actors: {intel_result['threat_actors']}")
        print(f"   Boost: +{intel_result['severity_boost']:.1f}")
        
        # Enhanced threat detection
        threat_result = await threat_agent.analyze_event(apt_event)
        enhanced_score = threat_result.get('threat_score', 0) + intel_result['severity_boost']
        
        print(f"🧠 Detection: {enhanced_score:.2f} (enhanced score)")
        print(f"   Status: {'🚨 CRITICAL THREAT' if enhanced_score > 8 else '⚠️ HIGH RISK'}")
        
        await orchestrator.stop_all_agents()
        
        print(f"\n🎉 DEMONSTRATION COMPLETED!")
        print("🚀 Your AI SOC Features:")
        print("• 🧠 AI threat detection")
        print("• 🌐 Threat intelligence")
        print("• 🔗 Multi-agent coordination")
        print("• 📈 Enhanced risk scoring")
        
        return True
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(demonstrate_complete_soc())
    print(f"\nDemo {'PASSED' if success else 'FAILED'}")
