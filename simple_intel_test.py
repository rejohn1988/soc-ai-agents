#!/usr/bin/env python3
import asyncio
import sys
sys.path.insert(0, '.')

async def test_intel_agent():
    print("🌐 Testing Threat Intelligence Agent")
    
    try:
        from agents.threat_intelligence_agent import ThreatIntelligenceAgent
        print("✅ Import successful")
        
        # Create and start agent
        agent = ThreatIntelligenceAgent()
        await agent.start()
        print("✅ Agent started")
        
        # Test enrichment
        test_event = {
            'source_ip': '203.0.113.666',  # Known malicious IP
            'description': 'Connection to http://malicious-site.com/payload.exe'
        }
        
        enrichment = await agent.enrich_event_with_intelligence(test_event)
        print(f"✅ Enrichment completed")
        print(f"   Indicators found: {len(enrichment['indicators_found'])}")
        print(f"   Threat actors: {enrichment['threat_actors']}")
        print(f"   Severity boost: +{enrichment['severity_boost']:.1f}")
        
        # Get summary
        summary = await agent.get_intelligence_summary()
        print(f"✅ Intelligence summary:")
        print(f"   Total indicators: {summary['total_indicators']}")
        print(f"   Active feeds: {summary['active_feeds']}")
        
        await agent.stop()
        print("✅ Test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_intel_agent())
    print(f"Result: {'PASSED' if success else 'FAILED'}")
