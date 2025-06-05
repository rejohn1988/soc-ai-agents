#!/usr/bin/env python3
"""
SOC Database Inspector
Quick script to inspect the structure and content of your SOC database
"""

import sqlite3
import json
import os
from datetime import datetime

def inspect_soc_database(db_path="soc_alerts.db"):
    """Inspect the SOC database structure and content"""
    
    print("🔍 SOC Database Inspector")
    print("=" * 50)
    print(f"Database: {db_path}")
    print(f"Timestamp: {datetime.now()}")
    print(f"Working directory: {os.getcwd()}")
    print()
    
    # Check if database file exists
    if not os.path.exists(db_path):
        print(f"❌ Database file not found: {db_path}")
        print("Available files in current directory:")
        for file in os.listdir('.'):
            if file.endswith('.db'):
                print(f"   📁 {file}")
        return False
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # 1. List all tables
        print("📋 DATABASE TABLES:")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        if not tables:
            print("   ⚠️  No tables found in database")
            conn.close()
            return False
        
        for table in tables:
            table_name = table[0]
            print(f"   • {table_name}")
            
            # Get table schema
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            
            print(f"     Columns ({len(columns)}):")
            for col in columns:
                col_info = f"{col[1]} ({col[2]})"
                if col[3]:  # NOT NULL
                    col_info += " NOT NULL"
                if col[5]:  # PRIMARY KEY
                    col_info += " PRIMARY KEY"
                print(f"       - {col_info}")
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            print(f"     Rows: {count}")
            print()
        
        # 2. Sample data from alerts table
        if any(table[0] == 'alerts' for table in tables):
            print("📊 SAMPLE ALERTS DATA:")
            cursor.execute("SELECT * FROM alerts LIMIT 3")
            sample_alerts = cursor.fetchall()
            
            if not sample_alerts:
                print("   ℹ️  No alerts found in database")
            else:
                for i, alert in enumerate(sample_alerts, 1):
                    print(f"\n   Alert {i}:")
                    alert_dict = dict(alert)
                    for key, value in alert_dict.items():
                        # Limit long values
                        display_value = str(value)
                        if len(display_value) > 100:
                            display_value = display_value[:100] + "..."
                        print(f"     {key}: {display_value}")
        
        # 3. Statistics
        print("\n📈 DATABASE STATISTICS:")
        if any(table[0] == 'alerts' for table in tables):
            # Alert severity distribution
            try:
                cursor.execute("""
                    SELECT severity, COUNT(*) as count 
                    FROM alerts 
                    WHERE severity IS NOT NULL
                    GROUP BY severity 
                    ORDER BY count DESC
                """)
                severity_stats = cursor.fetchall()
                
                if severity_stats:
                    print("   Severity Distribution:")
                    for stat in severity_stats:
                        print(f"     {stat[0] or 'null'}: {stat[1]} alerts")
                else:
                    print("   No severity data found")
            except Exception as e:
                print(f"   Could not get severity stats: {e}")
            
            # Recent activity
            try:
                cursor.execute("""
                    SELECT DATE(timestamp) as date, COUNT(*) as count 
                    FROM alerts 
                    WHERE timestamp IS NOT NULL
                    GROUP BY DATE(timestamp) 
                    ORDER BY date DESC 
                    LIMIT 5
                """)
                recent_activity = cursor.fetchall()
                
                if recent_activity:
                    print("\n   Recent Activity (by date):")
                    for activity in recent_activity:
                        print(f"     {activity[0]}: {activity[1]} alerts")
                else:
                    print("\n   No timestamp data found for recent activity")
            except Exception as e:
                print(f"\n   Could not get recent activity: {e}")
        
        conn.close()
        print("\n✅ Database inspection completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Database inspection failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    inspect_soc_database()
