#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')

print("🔬 Mini SOC AI System Test")
print("="*40)

# Test 1: Imports
print("\n1️⃣ Testing imports...")
try:
    from agents.base_agent import ThreatEvent
    from agents.threat_detection_agent import ThreatDetectionAgent
    from agents.incident_response_agent import IncidentResponseAgent
    print("✅ Imports successful")
except Exception as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

# Test 2: Agent creation
print("\n2️⃣ Testing agent creation...")
try:
    threat_agent = ThreatDetectionAgent()
    incident_agent = IncidentResponseAgent()
    print("✅ Agents created")
except Exception as e:
    print(f"❌ Agent creation failed: {e}")
    sys.exit(1)

print("\n🎉 Basic functionality working!")
print("Your AI SOC agents are ready!")
