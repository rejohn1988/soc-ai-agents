import time
import random
import sqlite3
import json
import threading
from datetime import datetime, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import socketserver

class SOCDatabase:
    def __init__(self, db_path="soc_alerts.db"):
        self.db_path = db_path
        self.create_database()
    
    def create_database(self):
        """Create database and tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_number INTEGER,
                severity TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                created_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS daily_stats (
                date TEXT PRIMARY KEY,
                total_alerts INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                last_updated TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_alert(self, alert_data):
        """Save alert to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_number, severity, threat_type, source, action_taken)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert_data['timestamp'],
            alert_data['alert_number'],
            alert_data['severity'],
            alert_data['threat_type'],
            alert_data['source'],
            alert_data['action_taken']
        ))
        
        conn.commit()
        conn.close()
    
    def get_dashboard_data(self):
        """Get all data needed for dashboard"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get total counts
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        
        # Get counts by severity
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM alerts 
            GROUP BY severity
        ''')
        severity_data = cursor.fetchall()
        severity_counts = {row[0]: row[1] for row in severity_data}
        
        # Get recent alerts (last 20)
        cursor.execute('''
            SELECT id, timestamp, severity, threat_type, source, created_date
            FROM alerts 
            ORDER BY id DESC 
            LIMIT 20
        ''')
        recent_alerts = cursor.fetchall()
        
        # Get hourly activity for last 24 hours
        cursor.execute('''
            SELECT strftime('%H', created_date) as hour, COUNT(*) as count
            FROM alerts 
            WHERE created_date >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        ''')
        hourly_activity = cursor.fetchall()
        
        # Get source breakdown
        cursor.execute('''
            SELECT source, COUNT(*) as count
            FROM alerts 
            GROUP BY source
            ORDER BY count DESC
            LIMIT 10
        ''')
        source_breakdown = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_alerts': total_alerts,
            'severity_counts': severity_counts,
            'recent_alerts': recent_alerts,
            'hourly_activity': hourly_activity,
            'source_breakdown': source_breakdown,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, db_instance=None, **kwargs):
        self.db = db_instance
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/' or parsed_path.path == '/dashboard':
            self.serve_dashboard()
        elif parsed_path.path == '/api/data':
            self.serve_api_data()
        elif parsed_path.path == '/api/alerts':
            self.serve_alerts_api()
        else:
            self.send_error(404, "Page not found")
    
    def serve_dashboard(self):
        """Serve the main dashboard HTML"""
        html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC AI Agent System - Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            background: rgba(0,0,0,0.2);
            padding: 20px;
            border-radius: 10px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #FFD700;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.8;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 2px solid transparent;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: rgba(255,255,255,0.3);
        }
        
        .stat-card.critical {
            border-left: 5px solid #FF4757;
        }
        
        .stat-card.high {
            border-left: 5px solid #FF8C00;
        }
        
        .stat-card.medium {
            border-left: 5px solid #FFD700;
        }
        
        .stat-card.low {
            border-left: 5px solid #7ED321;
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .stat-label {
            font-size: 1.1em;
            opacity: 0.8;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .dashboard-card {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        
        .card-title {
            font-size: 1.3em;
            margin-bottom: 15px;
            color: #FFD700;
        }
        
        .alerts-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .alerts-table th,
        .alerts-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .alerts-table th {
            background: rgba(0,0,0,0.2);
            font-weight: bold;
        }
        
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        
        .severity-critical {
            background: #FF4757;
            color: white;
        }
        
        .severity-high {
            background: #FF8C00;
            color: white;
        }
        
        .severity-medium {
            background: #FFD700;
            color: black;
        }
        
        .severity-low {
            background: #7ED321;
            color: white;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #7ED321;
            margin-right: 5px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .last-updated {
            text-align: center;
            margin-top: 20px;
            opacity: 0.7;
            font-size: 0.9em;
        }
        
        .chart-container {
            height: 200px;
            background: rgba(0,0,0,0.1);
            border-radius: 5px;
            padding: 10px;
            margin-top: 10px;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SOC AI Agent System</h1>
            <p class="subtitle">
                <span class="status-indicator"></span>
                Real-time Security Operations Center Dashboard
            </p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="total-alerts">0</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-number" id="critical-count">0</div>
                <div class="stat-label">🔴 Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number" id="high-count">0</div>
                <div class="stat-label">🟠 High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number" id="medium-count">0</div>
                <div class="stat-label">🟡 Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number" id="low-count">0</div>
                <div class="stat-label">🟢 Low</div>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <div class="dashboard-card">
                <h3 class="card-title">🚨 Recent Security Alerts</h3>
                <table class="alerts-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Severity</th>
                            <th>Threat</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody id="alerts-tbody">
                        <tr>
                            <td colspan="4">Loading alerts...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <div class="dashboard-card">
                <h3 class="card-title">📊 Threat Sources</h3>
                <div id="sources-list">
                    <p>Loading source data...</p>
                </div>
            </div>
        </div>
        
        <div class="last-updated">
            Last updated: <span id="last-updated">Never</span> | 
            Auto-refresh: <span id="refresh-countdown">30</span>s
        </div>
    </div>

    <script>
        let refreshCountdown = 30;
        
        function updateDashboard() {
            fetch('/api/data')
                .then(response => response.json())
                .then(data => {
                    // Update statistics
                    document.getElementById('total-alerts').textContent = data.total_alerts;
                    document.getElementById('critical-count').textContent = data.severity_counts.CRITICAL || 0;
                    document.getElementById('high-count').textContent = data.severity_counts.HIGH || 0;
                    document.getElementById('medium-count').textContent = data.severity_counts.MEDIUM || 0;
                    document.getElementById('low-count').textContent = data.severity_counts.LOW || 0;
                    
                    // Update recent alerts table
                    const tbody = document.getElementById('alerts-tbody');
                    tbody.innerHTML = '';
                    
                    if (data.recent_alerts.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4">No alerts yet</td></tr>';
                    } else {
                        data.recent_alerts.slice(0, 10).forEach(alert => {
                            const row = document.createElement('tr');
                            const severityClass = 'severity-' + alert[2].toLowerCase();
                            row.innerHTML = `
                                <td>${alert[1]}</td>
                                <td><span class="severity-badge ${severityClass}">${alert[2]}</span></td>
                                <td>${alert[3].substring(0, 40)}...</td>
                                <td>${alert[4]}</td>
                            `;
                            tbody.appendChild(row);
                        });
                    }
                    
                    // Update sources
                    const sourcesList = document.getElementById('sources-list');
                    sourcesList.innerHTML = '';
                    
                    if (data.source_breakdown.length === 0) {
                        sourcesList.innerHTML = '<p>No source data available</p>';
                    } else {
                        data.source_breakdown.forEach(source => {
                            const sourceDiv = document.createElement('div');
                            sourceDiv.style.cssText = 'margin: 10px 0; padding: 10px; background: rgba(0,0,0,0.1); border-radius: 5px;';
                            sourceDiv.innerHTML = `<strong>${source[0]}</strong>: ${source[1]} alerts`;
                            sourcesList.appendChild(sourceDiv);
                        });
                    }
                    
                    // Update timestamp
                    document.getElementById('last-updated').textContent = data.last_updated;
                })
                .catch(error => {
                    console.error('Error updating dashboard:', error);
                });
        }
        
        function startCountdown() {
            const countdownElement = document.getElementById('refresh-countdown');
            setInterval(() => {
                refreshCountdown--;
                countdownElement.textContent = refreshCountdown;
                
                if (refreshCountdown <= 0) {
                    refreshCountdown = 30;
                    updateDashboard();
                }
            }, 1000);
        }
        
        // Initial load
        updateDashboard();
        startCountdown();
        
        // Auto refresh every 30 seconds
        setInterval(updateDashboard, 30000);
    </script>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def serve_api_data(self):
        """Serve dashboard data as JSON"""
        if self.db:
            data = self.db.get_dashboard_data()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        else:
            self.send_error(500, "Database not available")

class WebDashboardSOC:
    def __init__(self):
        self.alerts_processed = 0
        self.db = SOCDatabase()
        self.web_server = None
        self.server_thread = None
        
        self.threat_database = {
            'CRITICAL': [
                {'threat': 'Ransomware detected encrypting files', 'source': 'Endpoint-07', 'action': 'ISOLATE SYSTEM IMMEDIATELY'},
                {'threat': 'Data exfiltration to unknown external server', 'source': 'Network-Monitor', 'action': 'BLOCK ALL OUTBOUND TRAFFIC'},
                {'threat': 'Root privilege escalation successful', 'source': 'Server-01', 'action': 'EMERGENCY CONTAINMENT'},
                {'threat': 'Advanced persistent threat (APT) detected', 'source': 'Threat-Intel', 'action': 'ACTIVATE INCIDENT RESPONSE TEAM'},
                {'threat': 'Zero-day exploit detected in memory', 'source': 'Endpoint-03', 'action': 'IMMEDIATE FORENSIC ANALYSIS'}
            ],
            'HIGH': [
                {'threat': 'Multiple failed SSH login attempts (50+ tries)', 'source': 'SSH-Monitor', 'action': 'Block source IP address'},
                {'threat': 'Suspicious PowerShell execution detected', 'source': 'Workstation-15', 'action': 'Quarantine endpoint'},
                {'threat': 'Port scan detected across network range', 'source': 'Firewall', 'action': 'Enable enhanced monitoring'},
                {'threat': 'Malware signature match in email attachment', 'source': 'Email-Gateway', 'action': 'Block sender domain'},
                {'threat': 'Unauthorized admin account creation', 'source': 'Domain-Controller', 'action': 'Disable account and investigate'}
            ],
            'MEDIUM': [
                {'threat': 'Unusual outbound traffic volume detected', 'source': 'Network-01', 'action': 'Investigate traffic patterns'},
                {'threat': 'User accessing files outside normal hours', 'source': 'File-Server', 'action': 'Verify user identity'},
                {'threat': 'DNS query to suspicious domain detected', 'source': 'DNS-Monitor', 'action': 'Add domain to blacklist'},
                {'threat': 'USB device inserted on secure workstation', 'source': 'Endpoint-12', 'action': 'Scan device for malware'},
                {'threat': 'Multiple VPN connections from same user', 'source': 'VPN-Gateway', 'action': 'Verify user location'}
            ],
            'LOW': [
                {'threat': 'Failed login attempt detected', 'source': 'Login-Monitor', 'action': 'Log for pattern analysis'},
                {'threat': 'Software update available for critical system', 'source': 'Patch-Management', 'action': 'Schedule maintenance window'},
                {'threat': 'Disk space running low on backup server', 'source': 'Storage-Monitor', 'action': 'Archive old backups'},
                {'threat': 'Certificate expiring in 30 days', 'source': 'Certificate-Monitor', 'action': 'Schedule renewal'},
                {'threat': 'Unusual file access pattern detected', 'source': 'File-Monitor', 'action': 'Monitor user activity'}
            ]
        }
        
        self.stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    def start_web_server(self, port=8080):
        """Start the web dashboard server"""
        def create_handler(*args, **kwargs):
            return DashboardHandler(*args, db_instance=self.db, **kwargs)
        
        try:
            self.web_server = HTTPServer(('localhost', port), create_handler)
            self.server_thread = threading.Thread(target=self.web_server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            print(f"🌐 Web dashboard started at: http://localhost:{port}")
            return True
        except Exception as e:
            print(f"❌ Failed to start web server: {e}")
            return False
    
    def stop_web_server(self):
        """Stop the web dashboard server"""
        if self.web_server:
            self.web_server.shutdown()
            self.web_server.server_close()
            print("🌐 Web dashboard stopped")
    
    def generate_realistic_alert(self):
        severity_weights = ['CRITICAL'] * 1 + ['HIGH'] * 2 + ['MEDIUM'] * 4 + ['LOW'] * 3
        severity = random.choice(severity_weights)
        
        threat_info = random.choice(self.threat_database[severity])
        self.alerts_processed += 1
        self.stats[severity] += 1
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        alert_data = {
            'timestamp': timestamp,
            'alert_number': self.alerts_processed,
            'severity': severity,
            'threat_type': threat_info['threat'],
            'source': threat_info['source'],
            'action_taken': threat_info['action']
        }
        
        # Save to database (will be picked up by web dashboard)
        self.db.save_alert(alert_data)
        
        # Console output
        severity_colors = {
            'CRITICAL': '[🔴 CRITICAL]',
            'HIGH': '[🟠 HIGH]',
            'MEDIUM': '[🟡 MEDIUM]',
            'LOW': '[🟢 LOW]'
        }
        
        print(f"[{timestamp}] ALERT #{self.alerts_processed}")
        print(f"  {severity_colors[severity]} {threat_info['threat']}")
        print(f"  SOURCE: {threat_info['source']}")
        print(f"  💾 Saved to database → Web dashboard updated")
        print("=" * 60)
        
        return severity
    
    def run_monitoring_with_dashboard(self, duration_minutes=5):
        """Run SOC monitoring with web dashboard"""
        print("🛡️  SOC AI AGENT SYSTEM WITH WEB DASHBOARD")
        print("=" * 60)
        print("🚀 Starting enhanced monitoring with web interface...")
        print("🤖 AI Agents: Detection, Response, Database, Web Dashboard")
        print("💾 Database: soc_alerts.db")
        print(f"⏱️  Running for {duration_minutes} minutes")
        
        # Start web dashboard
        if not self.start_web_server(8080):
            print("❌ Failed to start web dashboard")
            return
        
        print("🌐 Web Dashboard: http://localhost:8080")
        print("📊 Real-time updates every 30 seconds")
        print("=" * 60)
        print("")
        
        end_time = time.time() + (duration_minutes * 60)
        
        try:
            while time.time() < end_time:
                severity = self.generate_realistic_alert()
                
                # Variable sleep based on severity
                if severity == 'CRITICAL':
                    time.sleep(2)  # Critical alerts process quickly
                elif severity == 'HIGH':
                    time.sleep(4)
                else:
                    time.sleep(6)  # Normal monitoring pace
                    
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
        finally:
            self.stop_web_server()
        
        print(f"\n🏁 Monitoring session complete!")
        print(f"📊 Total alerts processed: {self.alerts_processed}")
        print(f"💾 All data stored in database: soc_alerts.db")
        print(f"🌐 Dashboard data available for future sessions")

def main():
    print("🌐 Initializing SOC system with web dashboard...")
    soc = WebDashboardSOC()
    
    print("\n🎯 Starting SOC monitoring with web dashboard...")
    print("📋 Features:")
    print("   ✅ Real-time threat detection")
    print("   ✅ Database storage") 
    print("   ✅ Web dashboard interface")
    print("   ✅ Auto-refreshing statistics")
    print("   ✅ Professional SOC visualization")
    print("")
    
    soc.run_monitoring_with_dashboard(duration_minutes=5)
    
    print(f"\n📖 To restart dashboard only:")
    print(f"   python3 -c \"from soc_web_dashboard import WebDashboardSOC; soc = WebDashboardSOC(); soc.start_web_server(); input('Press Enter to stop...')\"")

if __name__ == "__main__":
    main()
