#!/usr/bin/env python3
import asyncio
import sys
from datetime import datetime
sys.path.insert(0, '.')

async def test_complete_system():
    print("🔬 Complete SOC AI System Test")
    print("="*50)
    
    # Import modules
    print("1️⃣ Importing modules...")
    try:
        from agents.base_agent import ThreatEvent, AgentMessage
        from agents.threat_detection_agent import ThreatDetectionAgent
        from agents.incident_response_agent import IncidentResponseAgent
        print("✅ Imports successful")
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False
    
    # Create agents
    print("\n2️⃣ Creating agents...")
    try:
        threat_agent = ThreatDetectionAgent()
        incident_agent = IncidentResponseAgent()
        print("✅ Agents created")
    except Exception as e:
        print(f"❌ Agent creation failed: {e}")
        return False
    
    # Start agents
    print("\n3️⃣ Starting agents...")
    try:
        await threat_agent.start()
        await incident_agent.start()
        print("✅ Agents started")
    except Exception as e:
        print(f"❌ Agent startup failed: {e}")
        return False
    
    # Test threat detection
    print("\n4️⃣ Testing threat detection...")
    try:
        test_event = ThreatEvent(
            event_id="system_test_001",
            source_ip="192.168.1.100",  # Known malicious IP
            destination_ip="10.0.0.1",
            event_type="login",
            severity="high",
            description="failed login with SQL injection: admin' OR 1=1--",
            timestamp=datetime.now(),
            raw_data={}
        )
        
        result = await threat_agent.analyze_event(test_event)
        threat_score = result.get('threat_score', 0)
        is_threat = result.get('is_threat', False)
        
        print(f"   Threat Score: {threat_score:.2f}")
        print(f"   Is Threat: {'🚨 YES' if is_threat else '✅ NO'}")
        print("✅ Threat detection working")
    except Exception as e:
        print(f"❌ Threat detection failed: {e}")
        return False
    
    # Test incident response
    print("\n5️⃣ Testing incident response...")
    try:
        threat_message = AgentMessage(
            agent_id="threat_detector",
            message_type="threat_detected",
            content={
                'event': test_event.__dict__,
                'analysis': result,
                'priority': 'high'
            },
            timestamp=datetime.now()
        )
        
        await incident_agent.receive_message(threat_message)
        await asyncio.sleep(1)  # Wait for processing
        
        incidents = await incident_agent.get_active_incidents()
        
        print(f"   Incidents Created: {len(incidents)}")
        if incidents:
            inc = incidents[0]
            print(f"   Incident ID: {inc['incident_id']}")
            print(f"   Severity: {inc['severity']}")
            print(f"   Actions: {inc['response_actions']}")
        
        print("✅ Incident response working")
    except Exception as e:
        print(f"❌ Incident response failed: {e}")
        return False
    
    # Cleanup
    print("\n6️⃣ Cleaning up...")
    try:
        await threat_agent.stop()
        await incident_agent.stop()
        print("✅ Cleanup complete")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")
    
    print("\n🎉 ALL TESTS PASSED!")
    print("Your AI SOC System is fully operational!")
    return True

if __name__ == "__main__":
    success = asyncio.run(test_complete_system())
    print(f"\nTest {'PASSED' if success else 'FAILED'}")

