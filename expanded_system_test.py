#!/usr/bin/env python3
"""
Expanded AI SOC System Test
Tests all AI agents working together: Threat Detection, Incident Response, 
Compliance Monitoring, and User Behavior Analysis
"""

import asyncio
import sys
from datetime import datetime
sys.path.insert(0, '.')

async def test_expanded_soc_system():
    print("🔬 Expanded AI SOC System Test")
    print("="*60)
    
    # Import all agents
    print("1️⃣ Importing all AI agent modules...")
    try:
        from agents.base_agent import ThreatEvent, AgentMessage, AgentOrchestrator
        from agents.threat_detection_agent import ThreatDetectionAgent
        from agents.incident_response_agent import IncidentResponseAgent
        from agents.compliance_agent import ComplianceMonitoringAgent
        from agents.user_behavior_agent import UserBehaviorAnalysisAgent
        print("✅ All agent modules imported successfully")
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False
    
    # Create and register all agents
    print("\n2️⃣ Creating AI agent fleet...")
    try:
        orchestrator = AgentOrchestrator()
        
        # Create all agents
        threat_agent = ThreatDetectionAgent()
        incident_agent = IncidentResponseAgent()
        compliance_agent = ComplianceMonitoringAgent()
        behavior_agent = UserBehaviorAnalysisAgent()
        
        # Register with orchestrator
        orchestrator.register_agent(threat_agent)
        orchestrator.register_agent(incident_agent)
        orchestrator.register_agent(compliance_agent)
        orchestrator.register_agent(behavior_agent)
        
        print("✅ Created 4 specialized AI agents:")
        print("   🧠 Threat Detection Agent")
        print("   🚨 Incident Response Agent")
        print("   🔐 Compliance Monitoring Agent")
        print("   👤 User Behavior Analysis Agent")
    except Exception as e:
        print(f"❌ Agent creation failed: {e}")
        return False
    
    # Start all agents
    print("\n3️⃣ Starting AI agent fleet...")
    try:
        await orchestrator.start_all_agents()
        print("✅ All agents started and operational")
    except Exception as e:
        print(f"❌ Agent startup failed: {e}")
        return False
    
    # Test Scenario 1: Insider Threat Detection
    print("\n" + "="*60)
    print("🕵️ SCENARIO 1: Insider Threat Detection")
    print("="*60)
    
    try:
        # Simulate suspicious user behavior
        print("📍 Simulating suspicious employee behavior...")
        
        # Step 1: User behavior analysis detects anomaly
        suspicious_login = AgentMessage(
            agent_id="security_monitor",
            message_type="user_login",
            content={
                'user_id': 'jane.smith',
                'timestamp': datetime.now().replace(hour=1).isoformat(),  # 1 AM login
                'source_ip': '203.0.113.15',
                'location': 'Unknown_Location'
            },
            timestamp=datetime.now()
        )
        
        await behavior_agent.receive_message(suspicious_login)
        await asyncio.sleep(0.5)
        
        # Step 2: Simulate file access violation
        file_access = AgentMessage(
            agent_id="file_monitor",
            message_type="file_access",
            content={
                'user_id': 'jane.smith',
                'file_path': '/confidential/customer_data.xlsx',
                'access_type': 'download',
                'file_size': 50000
            },
            timestamp=datetime.now()
        )
        
        await behavior_agent.receive_message(file_access)
        await asyncio.sleep(0.5)
        
        # Step 3: Check behavior anomalies
        behavior_anomalies = await behavior_agent.get_active_anomalies()
        
        print(f"   🔍 Behavior Analysis Results:")
        print(f"     Anomalies Detected: {len(behavior_anomalies)}")
        
        for anomaly in behavior_anomalies:
            print(f"     • {anomaly['description']} (Score: {anomaly['severity_score']:.1f})")
        
        # Step 4: Generate compliance violation
        compliance_event = AgentMessage(
            agent_id="data_monitor",
            message_type="security_event",
            content={
                'event': {
                    'event_type': 'data_access',
                    'timestamp': datetime.now().isoformat(),
                    'system': 'customer_database',
                    'user_id': None,  # Missing user tracking - GDPR violation
                    'data_type': 'personal'
                }
            },
            timestamp=datetime.now()
        )
        
        await compliance_agent.receive_message(compliance_event)
        await asyncio.sleep(0.5)
        
        compliance_violations = await compliance_agent.get_active_violations()
        
        print(f"   📋 Compliance Analysis Results:")
        print(f"     Violations Detected: {len(compliance_violations)}")
        
        for violation in compliance_violations:
            print(f"     • {violation['description']} ({violation['framework'].upper()})")
        
        print("✅ Scenario 1 completed successfully")
        
    except Exception as e:
        print(f"❌ Scenario 1 failed: {e}")
        return False
    
    # Test Scenario 2: Advanced Persistent Threat (APT)
    print("\n" + "="*60)
    print("🎯 SCENARIO 2: Advanced Persistent Threat (APT)")
    print("="*60)
    
    try:
        print("📍 Simulating multi-stage APT attack...")
        
        # Stage 1: Initial compromise
        apt_event_1 = ThreatEvent(
            event_id="apt_stage_1",
            source_ip="203.0.113.200",
            destination_ip="10.0.0.10",
            event_type="phishing_email",
            severity="medium",
            description="Suspicious email attachment with macro code",
            timestamp=datetime.now(),
            raw_data={"attachment": "invoice.docm", "macro_detected": True}
        )
        
        threat_result_1 = await threat_agent.analyze_event(apt_event_1)
        print(f"   Stage 1 - Initial Compromise:")
        print(f"     Threat Score: {threat_result_1.get('threat_score', 0):.2f}")
        
        # Stage 2: Privilege escalation
        apt_event_2 = ThreatEvent(
            event_id="apt_stage_2", 
            source_ip="10.0.0.10",
            destination_ip="10.0.0.5",
            event_type="privilege_escalation",
            severity="high",
            description="Attempted privilege escalation using CVE-2023-1234",
            timestamp=datetime.now(),
            raw_data={"exploit": "CVE-2023-1234", "success": True}
        )
        
        threat_result_2 = await threat_agent.analyze_event(apt_event_2)
        print(f"   Stage 2 - Privilege Escalation:")
        print(f"     Threat Score: {threat_result_2.get('threat_score', 0):.2f}")
        
        # Stage 3: Data exfiltration
        apt_event_3 = ThreatEvent(
            event_id="apt_stage_3",
            source_ip="10.0.0.5",
            destination_ip="203.0.113.300",
            event_type="data_exfiltration",
            severity="critical",
            description="Large encrypted data transfer to external IP",
            timestamp=datetime.now(),
            raw_data={"transfer_size": 500000000, "encrypted": True, "external": True}
        )
        
        threat_result_3 = await threat_agent.analyze_event(apt_event_3)
        print(f"   Stage 3 - Data Exfiltration:")
        print(f"     Threat Score: {threat_result_3.get('threat_score', 0):.2f}")
        
        # Trigger incident response for high-threat events
        if threat_result_3.get('is_threat', False):
            threat_message = AgentMessage(
                agent_id=threat_agent.agent_id,
                message_type="threat_detected",
                content={
                    'event': apt_event_3.__dict__,
                    'analysis': threat_result_3,
                    'priority': 'critical'
                },
                timestamp=datetime.now()
            )
            
            await incident_agent.receive_message(threat_message)
            await asyncio.sleep(1)
            
            incidents = await incident_agent.get_active_incidents()
            
            print(f"   🚨 Incident Response Triggered:")
            if incidents:
                latest_incident = incidents[-1]
                print(f"     Incident: {latest_incident['incident_id']}")
                print(f"     Severity: {latest_incident['severity']}")
                print(f"     Actions: {latest_incident['response_actions']}")
        
        print("✅ Scenario 2 completed successfully")
        
    except Exception as e:
        print(f"❌ Scenario 2 failed: {e}")
        return False
    
    # Test Scenario 3: Compliance Audit Simulation
    print("\n" + "="*60)
    print("📊 SCENARIO 3: Compliance Audit Simulation")
    print("="*60)
    
    try:
        print("📍 Simulating compliance audit scenarios...")
        
        # GDPR data breach scenario
        gdpr_breach = AgentMessage(
            agent_id="data_protection",
            message_type="security_event",
            content={
                'event': {
                    'event_type': 'data_breach',
                    'timestamp': datetime.now().isoformat(),
                    'system': 'customer_portal',
                    'affected_records': 1500,
                    'data_types': ['email', 'name', 'phone'],
                    'notification_time': None  # Not reported yet - violation!
                }
            },
            timestamp=datetime.now()
        )
        
        await compliance_agent.receive_message(gdpr_breach)
        await asyncio.sleep(0.5)
        
        # Generate compliance report
        compliance_report = await compliance_agent.generate_compliance_report()
        
        print(f"   📋 Compliance Audit Results:")
        print(f"     Total Violations: {compliance_report.get('total_violations', 0)}")
        print(f"     Compliance Score: {compliance_report.get('compliance_score', 100)}/100")
        
        if compliance_report.get('severity_breakdown'):
            print(f"     Severity Breakdown:")
            for severity, count in compliance_report['severity_breakdown'].items():
                print(f"       {severity.capitalize()}: {count}")
        
        print("✅ Scenario 3 completed successfully")
        
    except Exception as e:
        print(f"❌ Scenario 3 failed: {e}")
        return False
    
    # System Performance Summary
    print("\n" + "="*60)
    print("📈 SYSTEM PERFORMANCE SUMMARY")
    print("="*60)
    
    try:
        # Get system status
        system_status = orchestrator.get_system_status()
        print(f"🏗️  System Overview:")
        print(f"   Total Agents: {system_status['total_agents']}")
        print(f"   Active Agents: {system_status['active_agents']}")
        
        # Individual agent performance
        agents_info = [
            ("Threat Detection", threat_agent),
            ("Incident Response", incident_agent),
            ("Compliance Monitoring", compliance_agent),
            ("User Behavior Analysis", behavior_agent)
        ]
        
        print(f"\n🤖 Agent Performance:")
        for name, agent in agents_info:
            status = agent.get_status()
            health = await agent.health_check()
            print(f"   {name}:")
            print(f"     Status: {'🟢 Healthy' if health else '🔴 Unhealthy'}")
            print(f"     Queue: {status['queue_size']} messages")
        
        # Get specialized metrics
        print(f"\n📊 Specialized Metrics:")
        
        # Threat detection metrics
        threat_status = threat_agent.get_status()
        print(f"   Threat Detection:")
        print(f"     Events Processed: {threat_status['metrics']['events_processed']}")
        print(f"     Threats Detected: {threat_status['metrics']['threats_detected']}")
        
        # Incident response metrics
        incidents = await incident_agent.get_active_incidents()
        print(f"   Incident Response:")
        print(f"     Active Incidents: {len(incidents)}")
        
        # Compliance metrics
        violations = await compliance_agent.get_active_violations()
        print(f"   Compliance Monitoring:")
        print(f"     Active Violations: {len(violations)}")
        
        # Behavior analysis metrics
        risk_summary = await behavior_agent.get_user_risk_summary()
        anomalies = await behavior_agent.get_active_anomalies()
        print(f"   User Behavior Analysis:")
        print(f"     Users Monitored: {risk_summary['total_users']}")
        print(f"     Active Anomalies: {len(anomalies)}")
        print(f"     High Risk Users: {len(risk_summary['high_risk_users'])}")
        
        print("✅ Performance summary completed")
        
    except Exception as e:
        print(f"❌ Performance summary failed: {e}")
        return False
    
    # Cleanup
    print("\n🧹 Cleaning up expanded system...")
    try:
        await orchestrator.stop_all_agents()
        print("✅ All agents stopped successfully")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")
    
    print("\n" + "="*60)
    print("🎉 EXPANDED AI SOC SYSTEM TEST COMPLETED!")
    print("="*60)
    print("✅ All scenarios passed successfully!")
    print("\n🚀 Your Expanded AI SOC Capabilities:")
    print("• 🧠 Advanced threat detection with ML analysis")
    print("• 🚨 Automated incident response and remediation")
    print("• 🔐 Real-time compliance monitoring (GDPR, ISO27001, NIST)")
    print("• 👤 User behavior analysis and insider threat detection")
    print("• 🔗 Multi-agent coordination and intelligence sharing")
    print("• 📊 Comprehensive reporting and audit trails")
    
    return True

if __name__ == "__main__":
    success = asyncio.run(test_expanded_soc_system())
    print(f"\nTest {'PASSED' if success else 'FAILED'}")
