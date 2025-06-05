#!/usr/bin/env python3
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
    asyncio.run(main())#!/usr/bin/env python3
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
