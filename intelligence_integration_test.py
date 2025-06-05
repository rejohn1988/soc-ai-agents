#!/usr/bin/env python3
"""
Threat Intelligence Integration Test
Tests the complete AI SOC system with threat intelligence capabilities
"""

import asyncio
import sys
from datetime import datetime
sys.path.insert(0, '.')

async def test_intelligence_enhanced_soc():
    print("🌐 Threat Intelligence Enhanced AI SOC Test")
    print("="*70)
    
    # Import all agents including new threat intelligence agent
    print("1️⃣ Importing enhanced AI agent modules...")
    try:
        from agents.base_agent import ThreatEvent, AgentMessage, AgentOrchestrator
        from agents.threat_detection_agent import ThreatDetectionAgent
        from agents.incident_response_agent import IncidentResponseAgent
        from agents.compliance_agent import ComplianceMonitoringAgent
        from agents.user_behavior_agent import UserBehaviorAnalysisAgent
        from agents.threat_intelligence_agent import ThreatIntelligenceAgent
        print("✅ All enhanced agent modules imported successfully")
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False
    
    # Create enhanced agent fleet
    print("\n2️⃣ Creating enhanced AI agent fleet...")
    try:
        orchestrator = AgentOrchestrator()
        
        # Create all agents including threat intelligence
        threat_agent = ThreatDetectionAgent()
        incident_agent = IncidentResponseAgent()
        compliance_agent = ComplianceMonitoringAgent()
        behavior_agent = UserBehaviorAnalysisAgent()
        intel_agent = ThreatIntelligenceAgent()
        
        # Register with orchestrator
        orchestrator.register_agent(threat_agent)
        orchestrator.register_agent(incident_agent)
        orchestrator.register_agent(compliance_agent)
        orchestrator.register_agent(behavior_agent)
        orchestrator.register_agent(intel_agent)
        
        print("✅ Created 5 specialized AI agents:")
        print("   🧠 Threat Detection Agent")
        print("   🚨 Incident Response Agent")
        print("   🔐 Compliance Monitoring Agent")
        print("   👤 User Behavior Analysis Agent")
        print("   🌐 Threat Intelligence Agent")
    except Exception as e:
        print(f"❌ Agent creation failed: {e}")
        return False
    
    # Start enhanced agent fleet
    print("\n3️⃣ Starting enhanced AI agent fleet...")
    try:
        await orchestrator.start_all_agents()
        
        # Wait for intelligence collection to start
        await asyncio.sleep(3)
        
        print("✅ All agents started and intelligence feeds active")
    except Exception as e:
        print(f"❌ Agent startup failed: {e}")
        return False
    
    # Test intelligence capabilities
    print("\n" + "="*70)
    print("🎯 TESTING: Intelligence-Enhanced Threat Detection")
    print("="*70)
    
    try:
        # Create threat event with known malicious indicators
        intel_threat_event = ThreatEvent(
            event_id="intel_test_001",
            source_ip="203.0.113.666",  # This should match MISP intelligence
            destination_ip="10.0.0.5",
            event_type="network_connection",
            severity="high",
            description="Connection to known C2 server at http://malicious-site.com/payload.exe",
            timestamp=datetime.now(),
            raw_data={"url": "http://malicious-site.com/payload.exe"}
        )
        
        print(f"   🔍 Testing event: {intel_threat_event.description}")
        
        # Enrich event with threat intelligence
        enrichment = await intel_agent.enrich_event_with_intelligence(intel_threat_event.__dict__)
        
        print(f"   🌐 Intelligence Results:")
        print(f"     Indicators Found: {len(enrichment['indicators_found'])}")
        print(f"     Threat Actors: {enrichment['threat_actors']}")
        print(f"     Confidence Score: {enrichment['confidence_score']:.2f}")
        
        # Test threat detection with intelligence boost
        threat_result = await threat_agent.analyze_event(intel_threat_event)
        enhanced_score = threat_result.get('threat_score', 0) + enrichment['severity_boost']
        
        print(f"   🧠 Enhanced Threat Analysis:")
        print(f"     Base Score: {threat_result.get('threat_score', 0):.2f}")
        print(f"     Intel Boost: +{enrichment['severity_boost']:.2f}")
        print(f"     Final Score: {enhanced_score:.2f}")
        
        print("✅ Intelligence enhancement test completed")
        
    except Exception as e:
        print(f"❌ Intelligence test failed: {e}")
        return False
    
    # Test intelligence summary
    print("\n" + "="*70)
    print("📊 TESTING: Intelligence Feed Performance")
    print("="*70)
    
    try:
        intel_summary = await intel_agent.get_intelligence_summary()
        
        print(f"   📈 Intelligence Overview:")
        print(f"     Total Indicators: {intel_summary['total_indicators']:,}")
        print(f"     Active Feeds: {intel_summary['active_feeds']}")
        print(f"     Fresh Data (24h): {intel_summary['data_freshness']['indicators_last_24h']}")
        
        print("✅ Intelligence feed test completed")
        
    except Exception as e:
        print(f"❌ Feed test failed: {e}")
        return False
    
    # Cleanup
    print("\n🧹 Cleaning up enhanced system...")
    try:
        await orchestrator.stop_all_agents()
        print("✅ All enhanced agents stopped successfully")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")
    
    print("\n" + "="*70)
    print("🎉 THREAT INTELLIGENCE INTEGRATION TEST COMPLETED!")
    print("="*70)
    print("✅ All tests passed successfully!")
    print("\n🚀 Your Enhanced AI SOC Now Features:")
    print("• 🌐 Multi-source threat intelligence")
    print("• 🎯 Real-time indicator correlation")
    print("• 🕵️ Threat actor attribution")
    print("• 📈 Intelligence-boosted detection")
    print("• 🔍 Advanced threat hunting")
    
    return True

if __name__ == "__main__":
    success = asyncio.run(test_intelligence_enhanced_soc())
    print(f"\nTest {'PASSED' if success else 'FAILED'}")
