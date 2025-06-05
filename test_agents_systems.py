#!/usr/bin/env python3
"""
Test Script for SOC AI Agents
This script tests the base agent and threat detection agent functionality
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta
import json

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.base_agent import BaseAgent, AgentMessage, ThreatEvent, AgentOrchestrator
from agents.threat_detection_agent import ThreatDetectionAgent


class TestAgent(BaseAgent):
    """Simple test agent for testing communication"""
    
    def __init__(self):
        super().__init__("test_agent", "TestAgent")
        self.received_messages = []
    
    async def initialize(self):
        self.logger.info("Test Agent initialized")
    
    async def process_message(self, message: AgentMessage):
        self.received_messages.append(message)
        self.logger.info(f"Received message: {message.message_type}")
    
    async def analyze_event(self, event: ThreatEvent):
        return {"test": True, "event_id": event.event_id}
    
    async def cleanup(self):
        self.logger.info("Test Agent cleaned up")


async def test_base_agent():
    """Test basic agent functionality"""
    print("\n" + "="*60)
    print("TESTING BASE AGENT FUNCTIONALITY")
    print("="*60)
    
    # Create test agent
    test_agent = TestAgent()
    
    # Test agent creation
    print(f"✓ Agent created: {test_agent.name}")
    print(f"✓ Agent ID: {test_agent.agent_id}")
    print(f"✓ Initial status: {test_agent.get_status()}")
    
    # Test agent start/stop
    await test_agent.start()
    print(f"✓ Agent started successfully")
    
    # Test health check
    health = await test_agent.health_check()
    print(f"✓ Health check: {'PASS' if health else 'FAIL'}")
    
    # Test message creation
    message = await test_agent.send_message(
        "test_recipient", 
        "test_message", 
        {"data": "test"}
    )
    print(f"✓ Message created: {message.message_type}")
    
    # Stop agent
    await test_agent.stop()
    print(f"✓ Agent stopped successfully")
    
    return True


async def test_threat_detection_agent():
    """Test threat detection agent functionality"""
    print("\n" + "="*60)
    print("TESTING THREAT DETECTION AGENT")
    print("="*60)
    
    # Create threat detection agent
    threat_agent = ThreatDetectionAgent()
    await threat_agent.start()
    
    print(f"✓ Threat Detection Agent started")
    print(f"✓ Capabilities: {threat_agent.capabilities}")
    
    # Create test events
    test_events = [
        # Normal event
        ThreatEvent(
            event_id="normal_001",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            event_type="login",
            severity="low",
            description="successful user login",
            timestamp=datetime.now(),
            raw_data={"user": "john.doe", "port": 80}
        ),
        
        # Suspicious event - known bad IP
        ThreatEvent(
            event_id="suspicious_001",
            source_ip="192.168.1.100",  # This is in the known bad IPs
            destination_ip="10.0.0.1",
            event_type="login",
            severity="medium",
            description="failed login attempt",
            timestamp=datetime.now(),
            raw_data={"user": "admin", "port": 22}
        ),
        
        # High threat event - SQL injection pattern
        ThreatEvent(
            event_id="threat_001",
            source_ip="203.0.113.5",
            destination_ip="10.0.0.5",
            event_type="web_request",
            severity="high",
            description="web request with union select statement detected",
            timestamp=datetime.now(),
            raw_data={"url": "/login?id=1' UNION SELECT * FROM users--", "port": 80}
        ),
        
        # Brute force pattern
        ThreatEvent(
            event_id="bruteforce_001",
            source_ip="198.51.100.10",
            destination_ip="10.0.0.1",
            event_type="login",
            severity="medium",
            description="failed login attempt - invalid credentials",
            timestamp=datetime.now(),
            raw_data={"user": "admin", "attempt": 6, "port": 22}
        )
    ]
    
    print(f"\n📊 Testing {len(test_events)} events...")
    
    # Test each event
    results = []
    for i, event in enumerate(test_events, 1):
        print(f"\n--- Test Event {i}: {event.event_id} ---")
        print(f"Source IP: {event.source_ip}")
        print(f"Event Type: {event.event_type}")
        print(f"Description: {event.description}")
        
        # Analyze the event
        result = await threat_agent.analyze_event(event)
        results.append(result)
        
        print(f"🔍 Analysis Results:")
        print(f"   Threat Score: {result.get('threat_score', 0):.2f}")
        print(f"   Is Threat: {'🚨 YES' if result.get('is_threat', False) else '✅ NO'}")
        print(f"   Threat Types: {result.get('threat_types', [])}")
        print(f"   Confidence: {result.get('confidence', 0):.2f}")
        
        if result.get('recommendations'):
            print(f"   Recommendations:")
            for rec in result['recommendations']:
                print(f"     • {rec}")
    
    # Test agent metrics
    print(f"\n📈 Agent Performance Metrics:")
    metrics = threat_agent.metrics
    for metric, value in metrics.items():
        print(f"   {metric}: {value}")
    
    # Test batch processing
    print(f"\n🔄 Testing batch processing...")
    batch_events = [event.__dict__ for event in test_events[:2]]
    await threat_agent._analyze_event_batch(batch_events)
    print(f"   ✓ Batch processing completed")
    
    await threat_agent.stop()
    print(f"\n✓ Threat Detection Agent stopped")
    
    return results


async def test_agent_orchestrator():
    """Test agent orchestrator functionality"""
    print("\n" + "="*60)
    print("TESTING AGENT ORCHESTRATOR")
    print("="*60)
    
    # Create orchestrator
    orchestrator = AgentOrchestrator()
    
    # Create agents
    test_agent = TestAgent()
    threat_agent = ThreatDetectionAgent()
    
    # Register agents
    orchestrator.register_agent(test_agent)
    orchestrator.register_agent(threat_agent)
    
    print(f"✓ Registered {len(orchestrator.agents)} agents")
    
    # Start all agents
    await orchestrator.start_all_agents()
    print(f"✓ All agents started")
    
    # Test system status
    status = orchestrator.get_system_status()
    print(f"✓ System Status:")
    print(f"   Total Agents: {status['total_agents']}")
    print(f"   Active Agents: {status['active_agents']}")
    
    # Test event broadcasting
    test_event = ThreatEvent(
        event_id="broadcast_test",
        source_ip="192.168.1.200",
        destination_ip="10.0.0.1",
        event_type="test",
        severity="low",
        description="test event for broadcasting",
        timestamp=datetime.now(),
        raw_data={}
    )
    
    print(f"\n📡 Broadcasting test event...")
    await orchestrator.broadcast_event(test_event)
    
    # Wait a moment for processing
    await asyncio.sleep(1)
    
    print(f"✓ Event broadcast completed")
    
    # Stop all agents
    await orchestrator.stop_all_agents()
    print(f"✓ All agents stopped")
    
    return True


async def test_message_communication():
    """Test inter-agent communication"""
    print("\n" + "="*60)
    print("TESTING INTER-AGENT COMMUNICATION")
    print("="*60)
    
    # Create agents
    sender = TestAgent()
    receiver = TestAgent()
    
    # Start agents
    await sender.start()
    await receiver.start()
    
    # Test message sending
    message = AgentMessage(
        agent_id=sender.agent_id,
        message_type="test_communication",
        content={"message": "Hello from sender!"},
        timestamp=datetime.now()
    )
    
    print(f"📤 Sending message from {sender.name} to {receiver.name}")
    await receiver.receive_message(message)
    
    # Wait for message processing
    await asyncio.sleep(1)
    
    # Check if message was received
    if receiver.received_messages:
        print(f"✓ Message received successfully")
        received_msg = receiver.received_messages[0]
        print(f"   Message Type: {received_msg.message_type}")
        print(f"   Content: {received_msg.content}")
    else:
        print(f"❌ Message not received")
    
    await sender.stop()
    await receiver.stop()
    
    return len(receiver.received_messages) > 0


def print_test_summary(results):
    """Print test summary"""
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    all_passed = all(results.values())
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    print(f"\nOverall Result: {'🎉 ALL TESTS PASSED!' if all_passed else '⚠️  SOME TESTS FAILED'}")
    
    if all_passed:
        print("\n🚀 Your AI agents are ready for integration!")
        print("Next steps:")
        print("1. Integrate with your existing SOC system")
        print("2. Create the Incident Response Agent")
        print("3. Set up real-time monitoring")
    
    return all_passed


async def main():
    """Run all tests"""
    print("🔬 Starting AI Agent Testing Suite...")
    print(f"Timestamp: {datetime.now()}")
    
    results = {}
    
    try:
        # Run tests
        results["Base Agent"] = await test_base_agent()
        results["Threat Detection"] = bool(await test_threat_detection_agent())
        results["Agent Orchestrator"] = await test_agent_orchestrator()
        results["Message Communication"] = await test_message_communication()
        
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Print summary
    return print_test_summary(results)


if __name__ == "__main__":
    # Run the test suite
    success = asyncio.run(main())
    sys.exit(0 if success else 1)#!/usr/bin/env python3
"""
Test Script for SOC AI Agents
This script tests the base agent and threat detection agent functionality
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta
import json

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.base_agent import BaseAgent, AgentMessage, ThreatEvent, AgentOrchestrator
from agents.threat_detection_agent import ThreatDetectionAgent


class TestAgent(BaseAgent):
    """Simple test agent for testing communication"""
    
    def __init__(self):
        super().__init__("test_agent", "TestAgent")
        self.received_messages = []
    
    async def initialize(self):
        self.logger.info("Test Agent initialized")
    
    async def process_message(self, message: AgentMessage):
        self.received_messages.append(message)
        self.logger.info(f"Received message: {message.message_type}")
    
    async def analyze_event(self, event: ThreatEvent):
        return {"test": True, "event_id": event.event_id}
    
    async def cleanup(self):
        self.logger.info("Test Agent cleaned up")


async def test_base_agent():
    """Test basic agent functionality"""
    print("\n" + "="*60)
    print("TESTING BASE AGENT FUNCTIONALITY")
    print("="*60)
    
    # Create test agent
    test_agent = TestAgent()
    
    # Test agent creation
    print(f"✓ Agent created: {test_agent.name}")
    print(f"✓ Agent ID: {test_agent.agent_id}")
    print(f"✓ Initial status: {test_agent.get_status()}")
    
    # Test agent start/stop
    await test_agent.start()
    print(f"✓ Agent started successfully")
    
    # Test health check
    health = await test_agent.health_check()
    print(f"✓ Health check: {'PASS' if health else 'FAIL'}")
    
    # Test message creation
    message = await test_agent.send_message(
        "test_recipient", 
        "test_message", 
        {"data": "test"}
    )
    print(f"✓ Message created: {message.message_type}")
    
    # Stop agent
    await test_agent.stop()
    print(f"✓ Agent stopped successfully")
    
    return True


async def test_threat_detection_agent():
    """Test threat detection agent functionality"""
    print("\n" + "="*60)
    print("TESTING THREAT DETECTION AGENT")
    print("="*60)
    
    # Create threat detection agent
    threat_agent = ThreatDetectionAgent()
    await threat_agent.start()
    
    print(f"✓ Threat Detection Agent started")
    print(f"✓ Capabilities: {threat_agent.capabilities}")
    
    # Create test events
    test_events = [
        # Normal event
        ThreatEvent(
            event_id="normal_001",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            event_type="login",
            severity="low",
            description="successful user login",
            timestamp=datetime.now(),
            raw_data={"user": "john.doe", "port": 80}
        ),
        
        # Suspicious event - known bad IP
        ThreatEvent(
            event_id="suspicious_001",
            source_ip="192.168.1.100",  # This is in the known bad IPs
            destination_ip="10.0.0.1",
            event_type="login",
            severity="medium",
            description="failed login attempt",
            timestamp=datetime.now(),
            raw_data={"user": "admin", "port": 22}
        ),
        
        # High threat event - SQL injection pattern
        ThreatEvent(
            event_id="threat_001",
            source_ip="203.0.113.5",
            destination_ip="10.0.0.5",
            event_type="web_request",
            severity="high",
            description="web request with union select statement detected",
            timestamp=datetime.now(),
            raw_data={"url": "/login?id=1' UNION SELECT * FROM users--", "port": 80}
        ),
        
        # Brute force pattern
        ThreatEvent(
            event_id="bruteforce_001",
            source_ip="198.51.100.10",
            destination_ip="10.0.0.1",
            event_type="login",
            severity="medium",
            description="failed login attempt - invalid credentials",
            timestamp=datetime.now(),
            raw_data={"user": "admin", "attempt": 6, "port": 22}
        )
    ]
    
    print(f"\n📊 Testing {len(test_events)} events...")
    
    # Test each event
    results = []
    for i, event in enumerate(test_events, 1):
        print(f"\n--- Test Event {i}: {event.event_id} ---")
        print(f"Source IP: {event.source_ip}")
        print(f"Event Type: {event.event_type}")
        print(f"Description: {event.description}")
        
        # Analyze the event
        result = await threat_agent.analyze_event(event)
        results.append(result)
        
        print(f"🔍 Analysis Results:")
        print(f"   Threat Score: {result.get('threat_score', 0):.2f}")
        print(f"   Is Threat: {'🚨 YES' if result.get('is_threat', False) else '✅ NO'}")
        print(f"   Threat Types: {result.get('threat_types', [])}")
        print(f"   Confidence: {result.get('confidence', 0):.2f}")
        
        if result.get('recommendations'):
            print(f"   Recommendations:")
            for rec in result['recommendations']:
                print(f"     • {rec}")
    
    # Test agent metrics
    print(f"\n📈 Agent Performance Metrics:")
    metrics = threat_agent.metrics
    for metric, value in metrics.items():
        print(f"   {metric}: {value}")
    
    # Test batch processing
    print(f"\n🔄 Testing batch processing...")
    batch_events = [event.__dict__ for event in test_events[:2]]
    await threat_agent._analyze_event_batch(batch_events)
    print(f"   ✓ Batch processing completed")
    
    await threat_agent.stop()
    print(f"\n✓ Threat Detection Agent stopped")
    
    return results


async def test_agent_orchestrator():
    """Test agent orchestrator functionality"""
    print("\n" + "="*60)
    print("TESTING AGENT ORCHESTRATOR")
    print("="*60)
    
    # Create orchestrator
    orchestrator = AgentOrchestrator()
    
    # Create agents
    test_agent = TestAgent()
    threat_agent = ThreatDetectionAgent()
    
    # Register agents
    orchestrator.register_agent(test_agent)
    orchestrator.register_agent(threat_agent)
    
    print(f"✓ Registered {len(orchestrator.agents)} agents")
    
    # Start all agents
    await orchestrator.start_all_agents()
    print(f"✓ All agents started")
    
    # Test system status
    status = orchestrator.get_system_status()
    print(f"✓ System Status:")
    print(f"   Total Agents: {status['total_agents']}")
    print(f"   Active Agents: {status['active_agents']}")
    
    # Test event broadcasting
    test_event = ThreatEvent(
        event_id="broadcast_test",
        source_ip="192.168.1.200",
        destination_ip="10.0.0.1",
        event_type="test",
        severity="low",
        description="test event for broadcasting",
        timestamp=datetime.now(),
        raw_data={}
    )
    
    print(f"\n📡 Broadcasting test event...")
    await orchestrator.broadcast_event(test_event)
    
    # Wait a moment for processing
    await asyncio.sleep(1)
    
    print(f"✓ Event broadcast completed")
    
    # Stop all agents
    await orchestrator.stop_all_agents()
    print(f"✓ All agents stopped")
    
    return True


async def test_message_communication():
    """Test inter-agent communication"""
    print("\n" + "="*60)
    print("TESTING INTER-AGENT COMMUNICATION")
    print("="*60)
    
    # Create agents
    sender = TestAgent()
    receiver = TestAgent()
    
    # Start agents
    await sender.start()
    await receiver.start()
    
    # Test message sending
    message = AgentMessage(
        agent_id=sender.agent_id,
        message_type="test_communication",
        content={"message": "Hello from sender!"},
        timestamp=datetime.now()
    )
    
    print(f"📤 Sending message from {sender.name} to {receiver.name}")
    await receiver.receive_message(message)
    
    # Wait for message processing
    await asyncio.sleep(1)
    
    # Check if message was received
    if receiver.received_messages:
        print(f"✓ Message received successfully")
        received_msg = receiver.received_messages[0]
        print(f"   Message Type: {received_msg.message_type}")
        print(f"   Content: {received_msg.content}")
    else:
        print(f"❌ Message not received")
    
    await sender.stop()
    await receiver.stop()
    
    return len(receiver.received_messages) > 0


def print_test_summary(results):
    """Print test summary"""
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    all_passed = all(results.values())
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    print(f"\nOverall Result: {'🎉 ALL TESTS PASSED!' if all_passed else '⚠️  SOME TESTS FAILED'}")
    
    if all_passed:
        print("\n🚀 Your AI agents are ready for integration!")
        print("Next steps:")
        print("1. Integrate with your existing SOC system")
        print("2. Create the Incident Response Agent")
        print("3. Set up real-time monitoring")
    
    return all_passed


async def main():
    """Run all tests"""
    print("🔬 Starting AI Agent Testing Suite...")
    print(f"Timestamp: {datetime.now()}")
    
    results = {}
    
    try:
        # Run tests
        results["Base Agent"] = await test_base_agent()
        results["Threat Detection"] = bool(await test_threat_detection_agent())
        results["Agent Orchestrator"] = await test_agent_orchestrator()
        results["Message Communication"] = await test_message_communication()
        
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Print summary
    return print_test_summary(results)


if __name__ == "__main__":
    # Run the test suite
    success = asyncio.run(main())
    sys.exit(0 if success else 1)#!/usr/bin/env python3
"""
SOC AI Agent Integration Test
Tests integration between AI agents and existing SOC system
"""

import asyncio
import sqlite3
import sys
import os
from datetime import datetime
import json

# Add agents to path
sys.path.append('.')

from agents.base_agent import ThreatEvent, AgentOrchestrator
from agents.threat_detection_agent import ThreatDetectionAgent


class SOCIntegrationTest:
    """Test integration with existing SOC database and systems"""
    
    def __init__(self, db_path="soc_alerts.db"):
        self.db_path = db_path
        self.orchestrator = AgentOrchestrator()
        self.threat_agent = None
    
    async def setup(self):
        """Setup the integration test environment"""
        print("🔧 Setting up SOC Integration Test...")
        
        # Create threat detection agent
        self.threat_agent = ThreatDetectionAgent()
        self.orchestrator.register_agent(self.threat_agent)
        
        # Start agents
        await self.orchestrator.start_all_agents()
        
        print("✅ Integration test environment ready")
    
    def connect_to_soc_db(self):
        """Connect to existing SOC database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            print(f"✅ Connected to SOC database: {self.db_path}")
            return conn
        except Exception as e:
            print(f"❌ Failed to connect to SOC database: {e}")
            return None
    
    def get_recent_alerts(self, conn, limit=10):
        """Get recent alerts from SOC database"""
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            alerts = cursor.fetchall()
            print(f"📊 Retrieved {len(alerts)} recent alerts from SOC database")
            return alerts
        
        except Exception as e:
            print(f"❌ Failed to retrieve alerts: {e}")
            return []
    
    def convert_alert_to_threat_event(self, alert):
        """Convert SOC alert to ThreatEvent format"""
        try:
            # Map SOC alert fields to ThreatEvent
            threat_event = ThreatEvent(
                event_id=f"soc_alert_{alert['id']}",
                source_ip=alert.get('source_ip', 'unknown'),
                destination_ip=alert.get('target_ip', 'unknown'),
                event_type=alert.get('alert_type', 'unknown'),
                severity=alert.get('severity', 'medium'),
                description=alert.get('message', 'SOC alert'),
                timestamp=datetime.fromisoformat(alert['timestamp']),
                raw_data={
                    'original_alert_id': alert['id'],
                    'rule_id': alert.get('rule_id'),
                    'confidence': alert.get('confidence'),
                    'source_table': 'alerts'
                }
            )
            return threat_event
        
        except Exception as e:
            print(f"❌ Failed to convert alert {alert.get('id', 'unknown')}: {e}")
            return None
    
    async def test_alert_analysis(self):
        """Test AI analysis of existing SOC alerts"""
        print("\n🔍 Testing AI Analysis of SOC Alerts...")
        
        # Connect to database
        conn = self.connect_to_soc_db()
        if not conn:
            return False
        
        # Get recent alerts
        alerts = self.get_recent_alerts(conn, limit=5)
        if not alerts:
            print("ℹ️  No alerts found in database")
            conn.close()
            return True
        
        # Analyze each alert with AI
        analysis_results = []
        
        for alert in alerts:
            print(f"\n--- Analyzing Alert ID: {alert['id']} ---")
            print(f"Alert Type: {alert.get('alert_type', 'unknown')}")
            print(f"Severity: {alert.get('severity', 'unknown')}")
            print(f"Message: {alert.get('message', 'no message')[:100]}...")
            
            # Convert to ThreatEvent
            threat_event = self.convert_alert_to_threat_event(alert)
            if not threat_event:
                continue
            
            # Analyze with AI agent
            try:
                result = await self.threat_agent.analyze_event(threat_event)
                analysis_results.append(result)
                
                print(f"🤖 AI Analysis:")
                print(f"   Threat Score: {result.get('threat_score', 0):.2f}")
                print(f"   Is Threat: {'🚨 YES' if result.get('is_threat', False) else '✅ NO'}")
                print(f"   AI Confidence: {result.get('confidence', 0):.2f}")
                
                if result.get('threat_types'):
                    print(f"   Threat Types: {', '.join(result['threat_types'])}")
                
                if result.get('recommendations'):
                    print(f"   AI Recommendations:")
                    for rec in result['recommendations'][:3]:  # Show first 3
                        print(f"     • {rec}")
            
            except Exception as e:
                print(f"❌ AI analysis failed: {e}")
        
        conn.close()
        
        print(f"\n📈 Analysis Summary:")
        print(f"   Total alerts analyzed: {len(analysis_results)}")
        threats_detected = sum(1 for r in analysis_results if r.get('is_threat', False))
        print(f"   Threats detected by AI: {threats_detected}")
        
        if analysis_results:
            avg_score = sum(r.get('threat_score', 0) for r in analysis_results) / len(analysis_results)
            print(f"   Average threat score: {avg_score:.2f}")
        
        return True
    
    async def test_real_time_monitoring(self):
        """Test real-time monitoring simulation"""
        print("\n⏰ Testing Real-time Monitoring Simulation...")
        
        # Simulate real-time events
        simulated_events = [
            {
                'source_ip': '192.168.1.75',
                'event_type': 'login',
                'description': 'user login from workstation',
                'severity': 'low'
            },
            {
                'source_ip': '203.0.113.100',
                'event_type': 'file_access',
                'description': 'access to sensitive configuration file',
                'severity': 'medium'
            },
            {
                'source_ip': '192.168.1.100',  # Known bad IP
                'event_type': 'network_scan',
                'description': 'port scanning activity detected',
                'severity': 'high'
            }
        ]
        
        print(f"🎭 Simulating {len(simulated_events)} real-time events...")
        
        for i, event_data in enumerate(simulated_events, 1):
            print(f"\n📡 Processing Event {i}:")
            print(f"   Source: {event_data['source_ip']}")
            print(f"   Type: {event_data['event_type']}")
            print(f"   Description: {event_data['description']}")
            
            # Create threat event
            threat_event = ThreatEvent(
                event_id=f"realtime_{i}",
                source_ip=event_data['source_ip'],
                destination_ip='10.0.0.1',
                event_type=event_data['event_type'],
                severity=event_data['severity'],
                description=event_data['description'],
                timestamp=datetime.now(),
                raw_data={'simulated': True}
            )
            
            # Process with orchestrator
            await self.orchestrator.broadcast_event(threat_event)
            
            # Small delay to simulate real-time processing
            await asyncio.sleep(0.5)
        
        print("✅ Real-time monitoring simulation completed")
        return True
    
    async def test_performance_metrics(self):
        """Test performance metrics collection"""
        print("\n📊 Testing Performance Metrics...")
        
        # Get agent metrics
        if self.threat_agent:
            metrics = self.threat_agent.get_status()
            
            print(f"🤖 Threat Detection Agent Metrics:")
            print(f"   Status: {'🟢 Active' if metrics['is_active'] else '🔴 Inactive'}")
            print(f"   Events Processed: {metrics['metrics']['events_processed']}")
            print(f"   Threats Detected: {metrics['metrics']['threats_detected']}")
            print(f"   Average Response Time: {metrics['metrics']['response_time_avg']:.3f}s")
            print(f"   Message Queue Size: {metrics['queue_size']}")
            
            # Test health check
            health = await self.threat_agent.health_check()
            print(f"   Health Status: {'🟢 Healthy' if health else '🔴 Unhealthy'}")
        
        # Get system-wide metrics
        system_status = self.orchestrator.get_system_status()
        print(f"\n🏗️  System-wide Metrics:")
        print(f"   Total Agents: {system_status['total_agents']}")
        print(f"   Active Agents: {system_status['active_agents']}")
        
        return True
    
    async def cleanup(self):
        """Cleanup test environment"""
        print("\n🧹 Cleaning up test environment...")
        await self.orchestrator.stop_all_agents()
        print("✅ Cleanup completed")


async def main():
    """Run SOC integration tests"""
    print("🔬 Starting SOC AI Agent Integration Tests...")
    print(f"Timestamp: {datetime.now()}")
    print("="*70)
    
    # Create integration test
    integration_test = SOCIntegrationTest()
    
    try:
        # Setup
        await integration_test.setup()
        
        # Run tests
        tests = [
            ("Alert Analysis", integration_test.test_alert_analysis),
            ("Real-time Monitoring", integration_test.test_real_time_monitoring),
            ("Performance Metrics", integration_test.test_performance_metrics)
        ]
        
        results = {}
        for test_name, test_func in tests:
            try:
                print(f"\n{'='*50}")
                print(f"Running: {test_name}")
                print('='*50)
                
                result = await test_func()
                results[test_name] = result
                
                status = "✅ PASSED" if result else "❌ FAILED"
                print(f"\n{test_name}: {status}")
                
            except Exception as e:
                print(f"❌ {test_name} failed with error: {e}")
                results[test_name] = False
        
        # Print final summary
        print("\n" + "="*70)
        print("INTEGRATION TEST SUMMARY")
        print("="*70)
        
        all_passed = all(results.values())
        
        for test_name, passed in results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"{test_name}: {status}")
        
        print(f"\nOverall Result: {'🎉 ALL INTEGRATION TESTS PASSED!' if all_passed else '⚠️  SOME TESTS FAILED'}")
        
        if all_passed:
            print("\n🚀 Integration successful! Your AI agents are working with your SOC system!")
        
    except Exception as e:
        print(f"❌ Integration test suite failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await integration_test.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
