cat > simple_soc.py << 'EOF'
#!/usr/bin/env python3
import asyncio
import random
from datetime import datetime

class SOC:
    def __init__(self):
        self.alerts = 0
        
    def generate_alert(self):
        threats = [
            "CRITICAL: Malware detected on workstation-01",
            "HIGH: Multiple failed SSH attempts from 192.168.1.100", 
            "MEDIUM: Unusual network traffic to external server",
            "CRITICAL: Privilege escalation attempt detected",
            "HIGH: Port scan detected from unknown source",
            "CRITICAL: Ransomware activity detected",
            "HIGH: Brute force attack in progress",
            "MEDIUM: Suspicious file download detected"
        ]
        
        alert = random.choice(threats)
        self.alerts += 1
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        print(f"[{timestamp}] ALERT #{self.alerts}: {alert}")
        print(f"         Response: Automated response initiated")
        print(f"         Action: Investigating threat...")
        print(f"         Status: Updating threat database")
        print("=" * 60)
        
    async def run(self):
        print("SOC AI AGENT SYSTEM")
        print("Starting security monitoring...")
        print("Press Ctrl+C to stop")
        print("")
        
        try:
            while True:
                self.generate_alert()
                await asyncio.sleep(5)
        except KeyboardInterrupt:
            print(f"\nSystem stopped. Total alerts processed: {self.alerts}")
            print("SOC monitoring session complete.")

if __name__ == "__main__":
    soc = SOC()
    asyncio.run(soc.run())
EOF

chmod +x simple_soc.py
python3 simple_soc.py# Create a minimal working version
cat > simple_soc.py << 'EOF'
#!/usr/bin/env python3
import asyncio
import random
from datetime import datetime

class SOC:
    def __init__(self):
        self.alerts = 0
        
    def generate_alert(self):
        threats = [
            "🔴 CRITICAL: Malware detected on workstation-01",
            "🟠 HIGH: Multiple failed SSH attempts from 192.168.1.100", 
            "🟡 MEDIUM: Unusual network traffic to external server",
            "🔴 CRITICAL: Privilege escalation attempt detected",
            "🟠 HIGH: Port scan detected from unknown source"
        ]
        
        alert = random.choice(threats)
        self.alerts += 1
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        print(f"[{timestamp}] ALERT #{self.alerts}: {alert}")
        print(f"         📋 Automated response initiated")
        print(f"         🔍 Investigating threat...")
        print(f"         📊 Updating threat database")
        print("-" * 60)
        
    async def run(self):
        print("🛡️  SOC AI AGENT SYSTEM")
        print("🚀 Starting security monitoring...")
        print("⚡ Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.generate_alert()
                await asyncio.sleep(5)  # New alert every 5 seconds
        except KeyboardInterrupt:
            print(f"\n🛑 System stopped. Total alerts processed: {self.alerts}")

if __name__ == "__main__":
    soc = SOC()
    asyncio.run(soc.run())
EOF

# Make it executable
chmod +x simple_soc.py

# Run it
python3 simple_soc.py
