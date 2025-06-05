#!/usr/bin/env python3
"""
Simple SOC AI System Test
Quick test to verify the complete system works
"""

import asyncio
import sys
import os
from datetime import datetime

# Add current directory to path
sys.path.insert(0, '.')

def test_imports():
    """Test if all modules can be imported"""
    print("🔍 Testing imports...")
    try:
        from agents.base_agent import BaseAgent, AgentMessage, ThreatEvent, AgentOrchestrator
        from agents.threat_detection_agent import ThreatDetectionAgent
        from agents.incident_response_agent import IncidentResponseAgent
        print("✅ All imports successful")
        return True, (BaseAgent, AgentMessage, ThreatEvent, AgentOrchestrator, ThreatDetectionAgent, IncidentResponseAgent)
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False, None
