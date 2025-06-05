cat > soc.py << 'EOF'
import asyncio
import random
from datetime import datetime

async def main():
    alerts = 0
    
    threats = [
        "CRITICAL: Malware detected on workstation-01",
        "HIGH: Multiple failed SSH attempts",
        "MEDIUM: Unusual network traffic detected",
        "CRITICAL: Privilege escalation attempt",
        "HIGH: Port scan detected"
    ]
    
    print("SOC AI AGENT SYSTEM")
    print("Starting security monitoring...")
    print("Press Ctrl+C to stop")
    print("")
    
    try:
        while True:
            alerts += 1
            threat = random.choice(threats)
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            print(f"[{timestamp}] ALERT #{alerts}: {threat}")
            print("         Response: Investigating...")
            print("         Status: Threat logged")
            print("-" * 50)
            
            await asyncio.sleep(3)
            
    except KeyboardInterrupt:
        print(f"\nSession complete. Alerts processed: {alerts}")

if __name__ == "__main__":
    asyncio.run(main())
EOF

python3 soc.py
