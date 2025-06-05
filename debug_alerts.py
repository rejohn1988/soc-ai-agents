#!/usr/bin/env python3
"""
Debug script to isolate the alert analysis issue
"""

import sqlite3
import sys
import os
from datetime import datetime

def debug_alerts_table():
    """Debug the alerts table specifically"""
    
    db_path = "soc_alerts.db"
    
    print("🔍 Debug: SOC Alerts Analysis")
    print("=" * 50)
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return False
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if alerts table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts';")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("❌ No 'alerts' table found")
            
            # Show all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            print(f"Available tables: {[t[0] for t in tables]}")
            return False
        
        print("✅ Found 'alerts' table")
        
        # Get table schema
        cursor.execute("PRAGMA table_info(alerts);")
        columns = cursor.fetchall()
        
        print(f"\n📋 Table Schema ({len(columns)} columns):")
        for col in columns:
            print(f"   {col[1]} ({col[2]})")
        
        # Count total alerts
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_count = cursor.fetchone()[0]
        print(f"\n📊 Total alerts in database: {total_count}")
        
        if total_count == 0:
            print("⚠️  No alerts found in database")
            return True
        
        # Get sample alerts
        print(f"\n🔍 Sample alerts (showing up to 3):")
        cursor.execute("SELECT * FROM alerts LIMIT 3")
        sample_alerts = cursor.fetchall()
        
        for i, alert in enumerate(sample_alerts, 1):
            print(f"\n--- Alert {i} ---")
            alert_dict = dict(alert)
            for key, value in alert_dict.items():
                # Truncate long values
                str_value = str(value)
                if len(str_value) > 100:
                    str_value = str_value[:100] + "..."
                print(f"   {key}: {str_value}")
        
        # Test basic alert conversion logic
        print(f"\n🧪 Testing Alert Conversion:")
        
        for i, alert in enumerate(sample_alerts[:1], 1):  # Test first alert
            print(f"\nTesting alert {i}:")
            alert_dict = dict(alert)
            
            # Try to extract key fields
            event_id = alert_dict.get('id', alert_dict.get('rowid', 'unknown'))
            source_ip = alert_dict.get('source_ip', alert_dict.get('src_ip', '0.0.0.0'))
            event_type = alert_dict.get('alert_type', alert_dict.get('type', 'unknown'))
            severity = alert_dict.get('severity', 'medium')
            description = alert_dict.get('message', alert_dict.get('description', 'no description'))
            
            print(f"   Extracted event_id: {event_id}")
            print(f"   Extracted source_ip: {source_ip}")
            print(f"   Extracted event_type: {event_type}")
            print(f"   Extracted severity: {severity}")
            print(f"   Extracted description: {str(description)[:50]}...")
            
            # Check if this looks valid for ThreatEvent creation
            if event_id and source_ip:
                print("   ✅ Basic fields look good for ThreatEvent conversion")
            else:
                print("   ⚠️  Missing critical fields")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_test_alert():
    """Create a test alert in the database for testing"""
    
    db_path = "soc_alerts.db"
    
    print(f"\n🔧 Creating test alert in database...")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Insert a test alert
        test_alert = {
            'alert_type': 'login_failure',
            'severity': 'high',
            'source_ip': '192.168.1.100',
            'target_ip': '10.0.0.1',
            'message': 'Multiple failed login attempts detected - potential brute force attack',
            'timestamp': datetime.now().isoformat(),
            'rule_id': 'test_rule_001',
            'confidence': 0.85
        }
        
        # Try to insert
        cursor.execute("""
            INSERT INTO alerts (alert_type, severity, source_ip, target_ip, message, timestamp, rule_id, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            test_alert['alert_type'],
            test_alert['severity'], 
            test_alert['source_ip'],
            test_alert['target_ip'],
            test_alert['message'],
            test_alert['timestamp'],
            test_alert['rule_id'],
            test_alert['confidence']
        ))
        
        conn.commit()
        print("✅ Test alert created successfully")
        
        # Verify it was inserted
        cursor.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        print(f"   Total alerts now: {count}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Failed to create test alert: {e}")
        
        # Try a simpler insert
        try:
            cursor.execute("""
                INSERT INTO alerts (message, timestamp) 
                VALUES (?, ?)
            """, (test_alert['message'], test_alert['timestamp']))
            conn.commit()
            conn.close()
            print("✅ Simple test alert created")
            return True
        except Exception as e2:
            print(f"❌ Simple insert also failed: {e2}")
            conn.close()
            return False

if __name__ == "__main__":
    print("🔬 SOC Alerts Debug Tool")
    print(f"Working directory: {os.getcwd()}")
    print(f"Timestamp: {datetime.now()}")
    print()
    
    # Debug existing alerts
    success = debug_alerts_table()
    
    if success:
        print("\n" + "="*50)
        
        # Ask if user wants to create a test alert
        try:
            response = input("\nCreate a test alert for testing? (y/n): ").lower().strip()
            if response in ['y', 'yes']:
                create_test_alert()
                print("\nRe-running debug after test alert creation:")
                debug_alerts_table()
        except KeyboardInterrupt:
            print("\nSkipping test alert creation")
    
    print(f"\n{'='*50}")
    print("Debug completed!")
