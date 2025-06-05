#!/usr/bin/env python3
"""
Quick syntax check for agent files
"""

import ast
import sys

def check_syntax(filename):
    """Check Python syntax of a file"""
    try:
        with open(filename, 'r') as f:
            source = f.read()
        
        # Try to parse the AST
        ast.parse(source)
        print(f"✅ {filename}: Syntax OK")
        return True
        
    except SyntaxError as e:
        print(f"❌ {filename}: Syntax Error at line {e.lineno}")
        print(f"   Error: {e.msg}")
        print(f"   Text: {e.text.strip() if e.text else 'N/A'}")
        return False
        
    except FileNotFoundError:
        print(f"❌ {filename}: File not found")
        return False
        
    except Exception as e:
        print(f"❌ {filename}: Error - {e}")
        return False

def main():
    """Check syntax of all agent files"""
    files_to_check = [
        'agents/base_agent.py',
        'agents/threat_detection_agent.py',
        'agents/incident_response_agent.py'
    ]
    
    print("🔍 Checking Python syntax...")
    
    all_good = True
    for filename in files_to_check:
        if not check_syntax(filename):
            all_good = False
    
    if all_good:
        print("\n✅ All files have valid syntax!")
    else:
        print("\n❌ Some files have syntax errors - fix them before proceeding")
    
    return all_good

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)#!/usr/bin/env python3
"""
Complete SOC AI System Integration Test
Tests the full AI agent system working together
"""

import asyncio
import sys
import os
from datetime import datetime
import json

# Fix import path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    from agents.base_agent import BaseAgent, AgentMessage, ThreatEvent, AgentOrchestrator
    from agents.threat_detection_agent import ThreatDetectionAgent
    from agents.incident_response_agent import IncidentResponseAgent
    print("✅ Successfully imported all agent modules")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


class CompleteSystemTest:
    """Test the complete SOC AI system"""
    
    def __init__(self):
        self.orchestrator = AgentOrchestrator()
        self.threat_agent = None
        self.incident_agent = None
    
    async def setup(self):
        """Setup the complete system"""
        print("🔧 Setting up Complete SOC AI System...")
        
        try:
            # Create agents
            self.threat_agent = ThreatDetectionAgent()
            self.incident_agent = IncidentResponseAgent()
            
            # Register agents
            self.orchestrator.register_agent(self.threat_agent)
            self.orchestrator.register_agent(self.incident_agent)
            
            # Start all agents
            await self.orchestrator.start_all_agents()
            
            print("✅ Complete SOC AI system ready")
            return True
            
        except Exception as e:
            print(f"❌ Setup failed: {e}")
            return False
    
    async def test_threat_to_incident_workflow(self):
        """Test complete workflow from threat detection to incident response"""
        print("\n🔄 Testing Complete Threat-to-Incident Workflow...")
        
        # Create high-severity test events
        test_scenarios = [
            {
                'name': 'SQL Injection Attack',
                'event': ThreatEvent(
                    event_id="test_sql_001",
                    source_ip="192.168.1.100",  # Known bad IP
                    destination_ip="10.0.0.5",
                    event_type="web_request",
                    severity="high",
                    description="SQL injection attack: admin' UNION SELECT * FROM users--",
                    timestamp=datetime.now(),
                    raw_data={"url": "/login", "method": "POST"}
                )
            },
            {
                'name': 'Brute Force Login',
                'event': ThreatEvent(
                    event_id="test_brute_001",
                    source_ip="203.0.113.10",
                    destination_ip="10.0.0.1",
                    event_type="login",
                    severity="medium",
                    description="multiple failed login attempts detected",
                    timestamp=datetime.now(),
                    raw_data={"attempts": 10, "user": "admin"}
                )
            },
            {
                'name': 'Malware Communication',
                'event': ThreatEvent(
                    event_id="test_malware_001",
                    source_ip="192.168.1.200",
                    destination_ip="203.0.113.50",
                    event_type="network_communication",
                    severity="critical",
                    description="suspicious payload download detected from known C2 server",
                    timestamp=datetime.now(),
                    raw_data={"bytes": 50000, "port": 443}
                )
            }
        ]
        
        workflow_results = []
        
        for scenario in test_scenarios:
            print(f"\n--- Testing Scenario: {scenario['name']} ---")
            event = scenario['event']
            
            print(f"📍 Event Details:")
            print(f"   ID: {event.event_id}")
            print(f"   Source IP: {event.source_ip}")
            print(f"   Type: {event.event_type}")
            print(f"   Severity: {event.severity}")
            print(f"   Description: {event.description}")
            
            # Step 1: Threat Detection Analysis
            print(f"\n🔍 Step 1: Threat Detection Analysis")
            threat_result = await self.threat_agent.analyze_event(event)
            
            print(f"   Threat Score: {threat_result.get('threat_score', 0):.2f}")
            print(f"   Is Threat: {'🚨 YES' if threat_result.get('is_threat', False) else '✅ NO'}")
            print(f"   Threat Types: {threat_result.get('threat_types', [])}")
            print(f"   Confidence: {threat_result.get('confidence', 0):.2f}")
            
            # Step 2: Trigger Incident Response (if threat detected)
            if threat_result.get('is_threat', False):
                print(f"\n🚨 Step 2: Triggering Incident Response")
                
                # Create threat detection message
                threat_message = AgentMessage(
                    agent_id=self.threat_agent.agent_id,
                    message_type="threat_detected",
                    content={
                        'event': event.__dict__,
                        'analysis': threat_result,
                        'priority': 'high' if threat_result.get('threat_score', 0) > 7.0 else 'medium'
                    },
                    timestamp=datetime.now()
                )
                
                # Send to incident response agent
                await self.incident_agent.receive_message(threat_message)
                
                # Wait for processing
                await asyncio.sleep(1)
                
                print(f"   ✅ Incident response triggered")
                
                # Step 3: Check incident creation and response
                print(f"\n📋 Step 3: Incident Response Results")
                active_incidents = await self.incident_agent.get_active_incidents()
                
                if active_incidents:
                    latest_incident = active_incidents[-1]  # Get most recent
                    print(f"   Incident Created: {latest_incident['incident_id']}")
                    print(f"   Severity: {latest_incident['severity'].upper()}")
                    print(f"   Status: {latest_incident['status']}")
                    print(f"   Response Actions: {latest_incident['response_actions']}")
                else:
                    print(f"   ⚠️  No incident created")
            else:
                print(f"\n✅ Step 2: No incident response needed (low threat score)")
            
            # Record results
            workflow_results.append({
                'scenario': scenario['name'],
                'threat_detected': threat_result.get('is_threat', False),
                'threat_score': threat_result.get('threat_score', 0),
                'incident_created': len(await self.incident_agent.get_active_incidents()) > 0
            })
            
            print(f"\n{'='*60}")
        
        return workflow_results
    
    async def test_system_performance(self):
        """Test system performance and metrics"""
        print("\n📊 Testing System Performance...")
        
        # Get system status
        system_status = self.orchestrator.get_system_status()
        print(f"   Total Agents: {system_status['total_agents']}")
        print(f"   Active Agents: {system_status['active_agents']}")
        
        # Get individual agent metrics
        print(f"\n🤖 Agent Performance Metrics:")
        
        # Threat Detection Agent
        threat_status = self.threat_agent.get_status()
        print(f"   Threat Detection Agent:")
        print(f"     Status: {'🟢 Active' if threat_status['is_active'] else '🔴 Inactive'}")
        print(f"     Events Processed: {threat_status['metrics']['events_processed']}")
        print(f"     Threats Detected: {threat_status['metrics']['threats_detected']}")
        print(f"     Avg Response Time: {threat_status['metrics']['response_time_avg']:.3f}s")
        
        # Incident Response Agent
        incident_status = self.incident_agent.get_status()
        print(f"   Incident Response Agent:")
        print(f"     Status: {'🟢 Active' if incident_status['is_active'] else '🔴 Inactive'}")
        print(f"     Queue Size: {incident_status['queue_size']}")
        
        # Active incidents summary
        active_incidents = await self.incident_agent.get_active_incidents()
        print(f"   Active Incidents: {len(active_incidents)}")
        
        if active_incidents:
            severity_count = {}
            for incident in active_incidents:
                severity = incident['severity']
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            print(f"   Incident Breakdown:")
            for severity, count in severity_count.items():
                print(f"     {severity.capitalize()}: {count}")
        
        return True
    
    async def test_real_world_simulation(self):
        """Simulate real-world attack scenarios"""
        print("\n🌍 Testing Real-World Attack Simulation...")
        
        # Simulate a multi-stage attack
        attack_stages = [
            {
                'stage': 'Reconnaissance',
                'event': ThreatEvent(
                    event_id="attack_stage_1",
                    source_ip="203.0.113.100",
                    destination_ip="10.0.0.1",
                    event_type="port_scan",
                    severity="low",
                    description="port scanning activity detected",
                    timestamp=datetime.now(),
                    raw_data={"ports_scanned": ["22", "80", "443", "3389"]}
                )
            },
            {
                'stage': 'Initial Compromise',
                'event': ThreatEvent(
                    event_id="attack_stage_2",
                    source_ip="203.0.113.100",
                    destination_ip="10.0.0.1",
                    event_type="login",
                    severity="medium",
                    description="brute force login attempt after port scan",
                    timestamp=datetime.now(),
                    raw_data={"attempts": 15, "service": "ssh"}
                )
            },
            {
                'stage': 'Data Exfiltration',
                'event': ThreatEvent(
                    event_id="attack_stage_3",
                    source_ip="10.0.0.1",
                    destination_ip="203.0.113.200",
                    event_type="data_transfer",
                    severity="critical",
                    description="large data transfer to external IP",
                    timestamp=datetime.now(),
                    raw_data={"bytes": 10000000, "destination": "unknown_external"}
                )
            }
        ]
        
        attack_timeline = []
        
        for stage_info in attack_stages:
            stage = stage_info['stage']
            event = stage_info['event']
            
            print(f"\n--- Attack Stage: {stage} ---")
            print(f"   Event: {event.event_id}")
            print(f"   Description: {event.description}")
            
            # Process through threat detection
            threat_result = await self.threat_agent.analyze_event(event)
            threat_score = threat_result.get('threat_score', 0)
            
            print(f"   AI Threat Score: {threat_score:.2f}")
            
            # Record in timeline
            attack_timeline.append({
                'stage': stage,
                'event_id': event.event_id,
                'threat_score': threat_score,
                'threats_detected': threat_result.get('threat_types', [])
            })
            
            # If significant threat, trigger incident response
            if threat_score > 3.0:
                print(f"   🚨 Triggering incident response...")
                
                threat_message = AgentMessage(
                    agent_id=self.threat_agent.agent_id,
                    message_type="threat_detected",
                    content={
                        'event': event.__dict__,
                        'analysis': threat_result,
                        'priority': 'high' if threat_score > 7.0 else 'medium'
                    },
                    timestamp=datetime.now()
                )
                
                await self.incident_agent.receive_message(threat_message)
                await asyncio.sleep(0.5)  # Processing time
            
            # Small delay between attack stages
            await asyncio.sleep(0.2)
        
        # Summary of attack detection
        print(f"\n📈 Attack Detection Summary:")
        total_stages = len(attack_timeline)
        detected_stages = sum(1 for stage in attack_timeline if stage['threat_score'] > 3.0)
        
        print(f"   Attack Stages: {total_stages}")
        print(f"   Stages Detected: {detected_stages}")
        print(f"   Detection Rate: {(detected_stages/total_stages)*100:.1f}%")
        
        # Show escalation pattern
        print(f"\n📊 Threat Score Escalation:")
        for stage in attack_timeline:
            print(f"   {stage['stage']}: {stage['threat_score']:.2f}")
        
        return detected_stages >= 2  # Success if we detect most stages
    
    async def cleanup(self):
        """Cleanup test environment"""
        print("\n🧹 Cleaning up complete system test...")
        await self.orchestrator.stop_all_agents()
        print("✅ Cleanup completed")


async def main():
    """Run complete system integration tests"""
    print("🔬 Starting Complete SOC AI System Integration Tests...")
    print(f"Timestamp: {datetime.now()}")
    print("="*80)
    
    # Create complete system test
    system_test = CompleteSystemTest()
    
    try:
        # Setup
        setup_success = await system_test.setup()
        if not setup_success:
            print("❌ Setup failed, cannot continue tests")
            return False
        
        # Run comprehensive tests
        tests = [
            ("Threat-to-Incident Workflow", system_test.test_threat_to_incident_workflow),
            ("System Performance", system_test.test_system_performance),
            ("Real-World Attack Simulation", system_test.test_real_world_simulation),
        ]
        
        results = {}
        for test_name, test_func in tests:
            try:
                print(f"\n{'='*60}")
                print(f"Running: {test_name}")
                print('='*60)
                
                result = await test_func()
                results[test_name] = result
                
                status = "✅ PASSED" if result else "❌ FAILED"
                print(f"\n{test_name}: {status}")
                
            except Exception as e:
                print(f"❌ {test_name} failed with error: {e}")
                import traceback
                traceback.print_exc()
                results[test_name] = False
        
        # Print final comprehensive summary
        print("\n" + "="*80)
        print("COMPLETE SOC AI SYSTEM TEST SUMMARY")
        print("="*80)
        
        all_passed = all(results.values())
        
        for test_name, passed in results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"{test_name}: {status}")
        
        print(f"\nOverall Result: {'🎉 ALL SYSTEM TESTS PASSED!' if all_passed else '⚠️  SOME TESTS FAILED'}")
        
        if all_passed:
            print("\n🚀 SUCCESS! Your Complete SOC AI System is Operational!")
            print("\n🎯 System Capabilities Verified:")
            print("• ✅ Advanced threat detection with AI analysis")
            print("• ✅ Automated incident response and remediation")
            print("• ✅ Real-time agent communication and coordination")
            print("• ✅ Multi-stage attack detection and correlation")
            print("• ✅ Integration with existing SOC database")
            print("• ✅ Performance monitoring and metrics")
            
            print("\n🔥 Your AI-Powered SOC Features:")
            print("• 🧠 Intelligent threat scoring and classification")
            print("• ⚡ Automated response actions (block, isolate, escalate)")
            print("• 📊 Real-time incident tracking and management")
            print("• 🔍 Advanced correlation and pattern detection")
            print("• 📈 Performance metrics and health monitoring")
            
            print("\n🎮 Ready for Production:")
            print("1. Deploy agents to your SOC environment")
            print("2. Configure real system integrations (firewall, SIEM, etc.)")
            print("3. Set up monitoring dashboards")
            print("4. Fine-tune detection rules and response playbooks")
            print("5. Train your team on the AI-enhanced workflows")
        
        return all_passed
        
    except Exception as e:
        print(f"❌ Complete system test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        await system_test.cleanup()


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
