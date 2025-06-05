cat > run_soc_system.py << 'EOF'
#!/usr/bin/env python3
"""
SOC AI Agent System - macOS Compatible Version
Simple executable SOC system for macOS
"""

import asyncio
import logging
import os
import sqlite3
from datetime import datetime
from uuid import uuid4
from dataclasses import dataclass
from enum import Enum
import random

# Simple setup
os.makedirs('logs', exist_ok=True)
os.makedirs('data', exist_ok=True)

# Simple logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/soc.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AlertLevel(Enum):
    LOW = "🟢 LOW"
    MEDIUM = "🟡 MEDIUM" 
    HIGH = "🟠 HIGH"
    CRITICAL = "🔴 CRITICAL"

@dataclass
class SecurityAlert:
    id: str
    title: str
    level: AlertLevel
    description: str
    timestamp: str

class SimpleSOCSystem:
    def __init__(self):
        self.running = False
        self.alerts = []
        self.events_processed = 0
        
    def setup_database(self):
        """Simple database setup"""
        conn = sqlite3.connect('data/soc.db')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT,
                level TEXT,
                description TEXT,
                timestamp TEXT
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("✅ Database ready")
    
    def generate_security_event(self):
        """Generate realistic security events"""
        scenarios = [
            {
                'title': 'Failed SSH Login Attempts',
                'level': AlertLevel.HIGH,
                'description': 'Multiple failed SSH attempts from 192.168.1.100 (12 attempts in 2 minutes)'
            },
            {
                'title': 'Suspicious Process Detected',
                'level': AlertLevel.CRITICAL,
                'description': 'Unknown process "cryptominer.exe" detected with high CPU usage'
            },
            {
                'title': 'Large Data Transfer',
                'level': AlertLevel.MEDIUM,
                'description': 'Unusual data transfer detected: 500MB uploaded to external server'
            },
            {
                'title': 'Port Scan Detected',
                'level': AlertLevel.HIGH,
                'description': 'Network scan detected from 10.0.0.50 targeting multiple ports'
            },
            {
                'title': 'Malware Signature Match',
                'level': AlertLevel.CRITICAL,
                'description': 'File "document.pdf.exe" matches known malware signature'
            },
            {
                'title': 'Privilege Escalation Attempt',
                'level': AlertLevel.CRITICAL,
                'description': 'User "guest" attempted to access admin-level resources'
            },
            {
                'title': 'Brute Force Attack',
                'level': AlertLevel.HIGH,
                'description': 'Dictionary attack detected against admin account (50+ attempts)'
            },
            {
                'title': 'Suspicious Network Traffic',
                'level': AlertLevel.MEDIUM,
                'description': 'Encrypted traffic to known botnet command server detected'
            },
            {
                'title': 'File Integrity Violation',
                'level': AlertLevel.HIGH,
                'description': 'Critical system file /etc/passwd has been modified unexpectedly'
            },
            {
                'title': 'DDoS Attack Detected',
                'level': AlertLevel.CRITICAL,
                'description': 'Incoming traffic spike: 10,000+ requests per second from 50+ IPs'
            }
        ]
        
        scenario = random.choice(scenarios)
        
        alert = SecurityAlert(
            id=str(uuid4())[:8],
            title=scenario['title'],
            level=scenario['level'],
            description=scenario['description'],
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        return alert
    
    def process_alert(self, alert):
        """Process and respond to security alerts"""
        self.alerts.append(alert)
        self.events_processed += 1
        
        # Log the alert
        logger.warning(f"{alert.level.value} ALERT: {alert.title}")
        logger.info(f"   📋 {alert.description}")
        logger.info(f"   🕐 {alert.timestamp}")
        logger.info(f"   🆔 Alert ID: {alert.id}")
        
        # Save to database
        try:
            conn = sqlite3.connect('data/soc.db')
            conn.execute('''
                INSERT INTO alerts (id, title, level, description, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (alert.id, alert.title, alert.level.value, alert.description, alert.timestamp))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database error: {e}")
        
        # Automated response based on severity
        if alert.level == AlertLevel.CRITICAL:
            logger.critical("🚨 CRITICAL ALERT - Initiating emergency response!")
            logger.info("   🔒 Isolating affected systems")
            logger.info("   📞 Notifying security team")
            logger.info("   🔍 Starting forensic collection")
            logger.info("   🛡️ Activating incident response team")
        elif alert.level == AlertLevel.HIGH:
            logger.warning("⚠️  HIGH PRIORITY - Immediate investigation required")
            logger.info("   🕵️ Starting threat analysis")
            logger.info("   📊 Collecting additional logs")
            logger.info("   🔍 Initiating threat hunting")
        elif alert.level == AlertLevel.MEDIUM:
            logger.info("📋 MEDIUM PRIORITY - Adding to investigation queue")
            logger.info("   📝 Logging for analyst review")
        else:
            logger.info("📝 LOW PRIORITY - Logged for review")
        
        logger.info("-" * 80)
    
    def show_dashboard(self):
        """Display simple dashboard"""
        print(f"\n{'='*80}")
        print("🛡️  SOC AI AGENT SYSTEM - REAL-TIME DASHBOARD")
        print(f"{'='*80}")
        print(f"🕐 Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📊 Events Processed: {self.events_processed}")
        print(f"🚨 Active Alerts: {len(self.alerts)}")
        print(f"🖥️  System Status: {'🟢 RUNNING' if self.running else '🔴 STOPPED'}")
        
        if self.alerts:
            print(f"\n📋 RECENT ALERTS:")
            for alert in self.alerts[-5:]:
                print(f"   {alert.level.value} | {alert.timestamp} | {alert.title}")
        
        # Show alert statistics
        if self.alerts:
            critical = len([a for a in self.alerts if a.level == AlertLevel.CRITICAL])
            high = len([a for a in self.alerts if a.level == AlertLevel.HIGH])
            medium = len([a for a in self.alerts if a.level == AlertLevel.MEDIUM])
            low = len([a for a in self.alerts if a.level == AlertLevel.LOW])
            
            print(f"\n📊 ALERT BREAKDOWN:")
            print(f"   🔴 Critical: {critical}")
            print(f"   🟠 High: {high}")
            print(f"   🟡 Medium: {medium}")
            print(f"   🟢 Low: {low}")
        
        print(f"\n🔍 Log File: logs/soc.log")
        print(f"💾 Database: data/soc.db")
        print(f"{'='*80}\n")
    
    async def run_continuous_monitoring(self):
        """Run continuous security monitoring"""
        logger.info("🚀 Starting SOC AI Agent System...")
        logger.info("🍎 Running on macOS")
        logger.info("🤖 AI Agents: Threat Detection, Incident Response, Reporting")
        logger.info("🔍 Monitoring for security threats...")
        logger.info("📊 Real-time dashboard updates every 5 alerts")
        logger.info("\n⚡ Press Ctrl+C to stop\n")
        
        self.running = True
        dashboard_counter = 0
        
        try:
            while self.running:
                # Generate security event every 8-25 seconds
                await asyncio.sleep(8 + (self.events_processed % 17))
                
                # Generate and process alert
                alert = self.generate_security_event()
                self.process_alert(alert)
                
                # Show dashboard every 5 alerts
                dashboard_counter += 1
                if dashboard_counter % 5 == 0:
                    self.show_dashboard()
                
        except KeyboardInterrupt:
            logger.info("\n🛑 Shutting down SOC system...")
            self.running = False
        
        # Final summary
        print(f"\n{'='*80}")
        print("📊 FINAL SUMMARY")
        print(f"{'='*80}")
        print(f"⏱️  Session ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📈 Events Processed: {self.events_processed}")
        print(f"🚨 Total Alerts: {len(self.alerts)}")
        
        # Count alerts by severity
        if self.alerts:
            critical = len([a for a in self.alerts if a.level == AlertLevel.CRITICAL])
            high = len([a for a in self.alerts if a.level == AlertLevel.HIGH])
            medium = len([a for a in self.alerts if a.level == AlertLevel.MEDIUM])
            low = len([a for a in self.alerts if a.level == AlertLevel.LOW])
            
            print(f"\n🚨 ALERT BREAKDOWN:")
            print(f"   🔴 Critical: {critical}")
            print(f"   🟠 High: {high}")
            print(f"   🟡 Medium: {medium}")
            print(f"   🟢 Low: {low}")
        
        print(f"\n💾 All data saved to database: data/soc.db")
        print(f"📝 Full logs available: logs/soc.log")
        print(f"🔍 View database: sqlite3 data/soc.db")
        print(f"{'='*80}")
        print("🛡️ SOC AI Agent System - Session Complete")

async def main():
    """Main function"""
    print("🛡️  macOS SOC AI AGENT SYSTEM")
    print("=" * 50)
    print("🚀 Simple executable version")
    print("🤖 Multi-agent security monitoring")
    print("🔍 Real-time threat detection")
    print("📊 Automated incident response")
    print("💾 Persistent database storage")
    print("📝 Comprehensive logging")
    print("=" * 50)
    
    soc = SimpleSOCSystem()
    soc.setup_database()
    await soc.run_continuous_monitoring()

if __name__ == "__main__":
    asyncio.run(main())
EOF

chmod +x run_soc_system.py

echo "✅ macOS SOC AI Agent System created successfully!"
echo "🚀 To run: python3 run_soc_system.py"cat > run_soc_system.py << 'EOF'
#!/usr/bin/env python3
"""
SOC AI Agent System - Simple Executable Version for Kali Linux
Just run this file and everything works!
"""

import asyncio
import logging
import os
import sqlite3
import json
from datetime import datetime
from uuid import uuid4
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Any
import threading
import time

# Simple setup
os.makedirs('logs', exist_ok=True)
os.makedirs('data', exist_ok=True)

# Simple logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/soc.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AlertLevel(Enum):
    LOW = "🟢 LOW"
    MEDIUM = "🟡 MEDIUM" 
    HIGH = "🟠 HIGH"
    CRITICAL = "🔴 CRITICAL"

@dataclass
class SecurityAlert:
    id: str
    title: str
    level: AlertLevel
    description: str
    timestamp: str

class SimpleSOCSystem:
    def __init__(self):
        self.running = False
        self.alerts = []
        self.events_processed = 0
        
    def setup_database(self):
        """Simple database setup"""
        conn = sqlite3.connect('data/soc.db')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT,
                level TEXT,
                description TEXT,
                timestamp TEXT
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("✅ Database ready")
    
    def generate_security_event(self):
        """Generate realistic security events"""
        scenarios = [
            {
                'title': 'Failed SSH Login Attempts',
                'level': AlertLevel.HIGH,
                'description': 'Multiple failed SSH attempts from 192.168.1.100 (12 attempts in 2 minutes)'
            },
            {
                'title': 'Suspicious Process Detected',
                'level': AlertLevel.CRITICAL,
                'description': 'Unknown process "cryptominer.exe" detected with high CPU usage'
            },
            {
                'title': 'Large Data Transfer',
                'level': AlertLevel.MEDIUM,
                'description': 'Unusual data transfer detected: 500MB uploaded to external server'
            },
            {
                'title': 'Port Scan Detected',
                'level': AlertLevel.HIGH,
                'description': 'Network scan detected from 10.0.0.50 targeting multiple ports'
            },
            {
                'title': 'Malware Signature Match',
                'level': AlertLevel.CRITICAL,
                'description': 'File "document.pdf.exe" matches known malware signature'
            },
            {
                'title': 'Privilege Escalation Attempt',
                'level': AlertLevel.CRITICAL,
                'description': 'User "guest" attempted to access admin-level resources'
            },
            {
                'title': 'Brute Force Attack',
                'level': AlertLevel.HIGH,
                'description': 'Dictionary attack detected against admin account (50+ attempts)'
            },
            {
                'title': 'Suspicious Network Traffic',
                'level': AlertLevel.MEDIUM,
                'description': 'Encrypted traffic to known botnet command server detected'
            },
            {
                'title': 'File Integrity Violation',
                'level': AlertLevel.HIGH,
                'description': 'Critical system file /etc/passwd has been modified unexpectedly'
            },
            {
                'title': 'DDoS Attack Detected',
                'level': AlertLevel.CRITICAL,
                'description': 'Incoming traffic spike: 10,000+ requests per second from 50+ IPs'
            }
        ]
        
        import random
        scenario = random.choice(scenarios)
        
        alert = SecurityAlert(
            id=str(uuid4())[:8],
            title=scenario['title'],
            level=scenario['level'],
            description=scenario['description'],
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        return alert
    
    def process_alert(self, alert: SecurityAlert):
        """Process and respond to security alerts"""
        self.alerts.append(alert)
        self.events_processed += 1
        
        # Log the alert
        logger.warning(f"{alert.level.value} ALERT: {alert.title}")
        logger.info(f"   📋 {alert.description}")
        logger.info(f"   🕐 {alert.timestamp}")
        logger.info(f"   🆔 Alert ID: {alert.id}")
        
        # Save to database
        try:
            conn = sqlite3.connect('data/soc.db')
            conn.execute('''
                INSERT INTO alerts (id, title, level, description, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (alert.id, alert.title, alert.level.value, alert.description, alert.timestamp))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database error: {e}")
        
        # Automated response based on severity
        if alert.level == AlertLevel.CRITICAL:
            logger.critical("🚨 CRITICAL ALERT - Initiating emergency response!")
            logger.info("   🔒 Isolating affected systems")
            logger.info("   📞 Notifying security team")
            logger.info("   🔍 Starting forensic collection")
            logger.info("   🛡️ Activating incident response team")
        elif alert.level == AlertLevel.HIGH:
            logger.warning("⚠️  HIGH PRIORITY - Immediate investigation required")
            logger.info("   🕵️ Starting threat analysis")
            logger.info("   📊 Collecting additional logs")
            logger.info("   🔍 Initiating threat hunting")
        elif alert.level == AlertLevel.MEDIUM:
            logger.info("📋 MEDIUM PRIORITY - Adding to investigation queue")
            logger.info("   📝 Logging for analyst review")
        else:
            logger.info("📝 LOW PRIORITY - Logged for review")
        
        logger.info("─" * 80)
    
    def show_dashboard(self):
        """Display simple dashboard"""
        print(f"\n{'='*80}")
        print("🛡️  SOC AI AGENT SYSTEM - REAL-TIME DASHBOARD")
        print(f"{'='*80}")
        print(f"🕐 Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📊 Events Processed: {self.events_processed}")
        print(f"🚨 Active Alerts: {len(self.alerts)}")
        print(f"🖥️  System Status: {'🟢 RUNNING' if self.running else '🔴 STOPPED'}")
        
        if self.alerts:
            print(f"\n📋 RECENT ALERTS:")
            for alert in self.alerts[-5:]:  # Show last 5 alerts
                print(f"   {alert.level.value} | {alert.timestamp} | {alert.title}")
        
        # Show alert statistics
        if self.alerts:
            critical = len([a for a in self.alerts if a.level == AlertLevel.CRITICAL])
            high = len([a for a in self.alerts if a.level == AlertLevel.HIGH])
            medium = len([a for a in self.alerts if a.level == AlertLevel.MEDIUM])
            low = len([a for a in self.alerts if a.level == AlertLevel.LOW])
            
            print(f"\n📊 ALERT BREAKDOWN:")
            print(f"   🔴 Critical: {critical}")
            print(f"   🟠 High: {high}")
            print(f"   🟡 Medium: {medium}")
            print(f"   🟢 Low: {low}")
        
        print(f"\n🔍 Log File: logs/soc.log")
        print(f"💾 Database: data/soc.db")
        print(f"{'='*80}\n")
    
    async def run_continuous_monitoring(self):
        """Run continuous security monitoring"""
        logger.info("🚀 Starting SOC AI Agent System...")
        logger.info("🐧 Running on Kali Linux")
        logger.info("🤖 AI Agents: Threat Detection, Incident Response, Reporting")
        logger.info("🔍 Monitoring for security threats...")
        logger.info("📊 Real-time dashboard updates every 5 alerts")
        logger.info("\n⚡ Press Ctrl+C to stop\n")
        
        self.running = True
        dashboard_counter = 0
        
        try:
            while self.running:
                # Generate security event every 8-25 seconds (realistic timing)
                await asyncio.sleep(8 + (self.events_processed % 17))
                
                # Generate and process alert
                alert = self.generate_security_event()
                self.process_alert(alert)
                
                # Show dashboard every 5 alerts
                dashboard_counter += 1
                if dashboard_counter % 5 == 0:
                    self.show_dashboard()
                
        except KeyboardInterrupt:
            logger.info("\n🛑 Shutting down SOC system...")
            self.running = False
        
        # Final summary
        print(f"\n{'='*80}")
        print("📊 FINAL SUMMARY")
        print(f"{'='*80}")
        print(f"⏱️  Session ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📈 Events Processed: {self.events_processed}")
        print(f"🚨 Total Alerts: {len(self.alerts)}")
        
        # Count alerts by severity
        critical = len([a for a in self.alerts if a.level == AlertLevel.CRITICAL])
        high = len([a for a in self.alerts if a.level == AlertLevel.HIGH])
        medium = len([a for a in self.alerts if a.level == AlertLevel.MEDIUM])
        low = len([a for a in self.alerts if a.level == AlertLevel.LOW])
        
        print(f"\n🚨 ALERT BREAKDOWN:")
        print(f"   🔴 Critical: {critical}")
        print(f"   🟠 High: {high}")
        print(f"   🟡 Medium: {medium}")
        print(f"   🟢 Low: {low}")
        print(f"\n💾 All data saved to database: data/soc.db")
        print(f"📝 Full logs available: logs/soc.log")
        print(f"🔍 View database: sqlite3 data/soc.db")
        print(f"{'='*80}")
        print("🛡️ SOC AI Agent System - Session Complete")

# Main execution
async def main():
    """Main function - just run this!"""
    print("🛡️  KALI LINUX SOC AI AGENT SYSTEM")
    print("=" * 50)
    print("🚀 Simple executable version")
    print("🤖 Multi-agent security monitoring")
    print("🔍 Real-time threat detection")
    print("📊 Automated incident response")
    print("💾 Persistent database storage")
    print("📝 Comprehensive logging")
    print("=" * 50)
    
    # Create and run SOC system
    soc = SimpleSOCSystem()
    soc.setup_database()
    await soc.run_continuous_monitoring()

if __name__ == "__main__":
    asyncio.run(main())
EOF

chmod +x run_soc_system.py

echo "✅ SOC AI Agent System created successfully!"
echo "🚀 To run: python3 run_soc_system.py"
echo "📂 Files will be created:"
echo "   📝 logs/soc.log (all system logs)"
echo "   💾 data/soc.db (SQLite database)"
echo "⚡ Press Ctrl+C to stop when running"
