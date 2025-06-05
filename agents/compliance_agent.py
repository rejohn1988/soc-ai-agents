"""
Compliance Monitoring Agent
Specialized AI agent for regulatory compliance monitoring and violation detection
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from .base_agent import BaseAgent, AgentMessage, ThreatEvent


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    ISO27001 = "iso27001"
    NIST = "nist"
    CCPA = "ccpa"


class ViolationSeverity(Enum):
    """Compliance violation severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ComplianceViolation:
    """Compliance violation data structure"""
    violation_id: str
    framework: ComplianceFramework
    rule_id: str
    severity: ViolationSeverity
    description: str
    affected_systems: List[str]
    evidence: Dict[str, Any]
    remediation_steps: List[str]
    created_at: datetime
    status: str = "open"
    risk_score: float = 0.0


class ComplianceMonitoringAgent(BaseAgent):
    """
    AI Agent specialized in compliance monitoring and regulatory adherence
    """
    
    def __init__(self, agent_id: str = "compliance_monitor", config: Dict[str, Any] = None):
        super().__init__(agent_id, "ComplianceMonitoringAgent", config)
        
        # Set capabilities
        self.capabilities.update({
            'monitor_compliance': True,
            'detect_violations': True,
            'generate_reports': True,
            'audit_trails': True
        })
        
        # Compliance monitoring state
        self.active_violations: Dict[str, ComplianceViolation] = {}
        self.compliance_rules = self._load_compliance_rules()
        self.audit_trail: List[Dict[str, Any]] = []
        
        # Monitoring configuration
        self.enabled_frameworks = config.get('frameworks', [
            ComplianceFramework.GDPR,
            ComplianceFramework.ISO27001,
            ComplianceFramework.NIST
        ]) if config else [ComplianceFramework.GDPR, ComplianceFramework.ISO27001, ComplianceFramework.NIST]
        
        # Data privacy monitoring
        self.sensitive_data_patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'passport': r'\b[A-Z]\d{8}\b'
        }
        
        # Access control monitoring
        self.privileged_accounts = set()
        self.failed_access_attempts = {}
        
    async def initialize(self):
        """Initialize compliance monitoring agent"""
        self.logger.info("Initializing Compliance Monitoring Agent...")
        
        # Initialize compliance database
        await self._initialize_compliance_db()
        
        # Load existing violations
        await self._load_violation_history()
        
        # Initialize monitoring rules
        await self._initialize_monitoring_rules()
        
        self.logger.info(f"Compliance Monitoring Agent initialized with {len(self.enabled_frameworks)} frameworks")
    
    def _load_compliance_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance rules for different frameworks"""
        return {
            # GDPR Rules
            'gdpr_data_access_logging': {
                'framework': ComplianceFramework.GDPR,
                'description': 'All personal data access must be logged',
                'severity': ViolationSeverity.HIGH,
                'check_function': self._check_data_access_logging
            },
            'gdpr_data_retention': {
                'framework': ComplianceFramework.GDPR,
                'description': 'Personal data retention limits must be enforced',
                'severity': ViolationSeverity.MEDIUM,
                'check_function': self._check_data_retention
            },
            'gdpr_breach_notification': {
                'framework': ComplianceFramework.GDPR,
                'description': 'Data breaches must be reported within 72 hours',
                'severity': ViolationSeverity.CRITICAL,
                'check_function': self._check_breach_notification
            },
            
            # ISO 27001 Rules
            'iso27001_access_control': {
                'framework': ComplianceFramework.ISO27001,
                'description': 'Access controls must be properly implemented',
                'severity': ViolationSeverity.HIGH,
                'check_function': self._check_access_control
            },
            'iso27001_incident_response': {
                'framework': ComplianceFramework.ISO27001,
                'description': 'Security incidents must be properly handled',
                'severity': ViolationSeverity.HIGH,
                'check_function': self._check_incident_response
            },
            
            # NIST Rules
            'nist_authentication': {
                'framework': ComplianceFramework.NIST,
                'description': 'Multi-factor authentication must be enforced',
                'severity': ViolationSeverity.HIGH,
                'check_function': self._check_authentication
            },
            'nist_encryption': {
                'framework': ComplianceFramework.NIST,
                'description': 'Sensitive data must be encrypted',
                'severity': ViolationSeverity.CRITICAL,
                'check_function': self._check_encryption
            }
        }
    
    async def _initialize_compliance_db(self):
        """Initialize compliance tracking database"""
        try:
            self.compliance_db = sqlite3.connect('compliance_monitoring.db')
            cursor = self.compliance_db.cursor()
            
            # Create violations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS violations (
                    violation_id TEXT PRIMARY KEY,
                    framework TEXT,
                    rule_id TEXT,
                    severity TEXT,
                    description TEXT,
                    affected_systems TEXT,
                    evidence TEXT,
                    remediation_steps TEXT,
                    created_at TEXT,
                    status TEXT,
                    risk_score REAL
                )
            ''')
            
            # Create audit trail table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_trail (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    user_id TEXT,
                    resource TEXT,
                    action TEXT,
                    result TEXT,
                    ip_address TEXT,
                    details TEXT
                )
            ''')
            
            self.compliance_db.commit()
            self.logger.info("Compliance database initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize compliance database: {e}")
    
    async def _load_violation_history(self):
        """Load historical violations from database"""
        try:
            cursor = self.compliance_db.cursor()
            cursor.execute("SELECT COUNT(*) FROM violations WHERE status = 'open'")
            count = cursor.fetchone()[0]
            self.logger.info(f"Loaded {count} open compliance violations")
        except Exception as e:
            self.logger.error(f"Failed to load violation history: {e}")
    
    async def _initialize_monitoring_rules(self):
        """Initialize compliance monitoring rules"""
        active_rules = []
        for rule_id, rule_config in self.compliance_rules.items():
            if rule_config['framework'] in self.enabled_frameworks:
                active_rules.append(rule_id)
        
        self.logger.info(f"Initialized {len(active_rules)} compliance monitoring rules")
    
    async def process_message(self, message: AgentMessage):
        """Process incoming messages"""
        try:
            if message.message_type == "security_event":
                await self._analyze_security_event(message)
            elif message.message_type == "data_access":
                await self._monitor_data_access(message)
            elif message.message_type == "user_activity":
                await self._monitor_user_activity(message)
            elif message.message_type == "system_change":
                await self._monitor_system_changes(message)
            elif message.message_type == "compliance_audit":
                await self._perform_compliance_audit(message)
            else:
                self.logger.warning(f"Unknown message type: {message.message_type}")
        
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    async def _analyze_security_event(self, message: AgentMessage):
        """Analyze security events for compliance violations"""
        try:
            event_data = message.content.get('event', {})
            event_type = event_data.get('event_type', '')
            
            violations = []
            
            # Check each compliance rule
            for rule_id, rule_config in self.compliance_rules.items():
                if rule_config['framework'] in self.enabled_frameworks:
                    try:
                        violation = await rule_config['check_function'](event_data)
                        if violation:
                            violations.append(violation)
                    except Exception as e:
                        self.logger.error(f"Error checking rule {rule_id}: {e}")
            
            # Process violations
            for violation in violations:
                await self._create_violation(violation)
            
            if violations:
                self.logger.warning(f"Detected {len(violations)} compliance violations")
        
        except Exception as e:
            self.logger.error(f"Error analyzing security event: {e}")
    
    async def _check_data_access_logging(self, event_data: Dict[str, Any]) -> Optional[ComplianceViolation]:
        """Check GDPR data access logging compliance"""
        if event_data.get('event_type') == 'data_access':
            # Check if access is properly logged
            if not event_data.get('user_id') or not event_data.get('timestamp'):
                return ComplianceViolation(
                    violation_id=f"GDPR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    framework=ComplianceFramework.GDPR,
                    rule_id="gdpr_data_access_logging",
                    severity=ViolationSeverity.HIGH,
                    description="Personal data access without proper logging",
                    affected_systems=[event_data.get('system', 'unknown')],
                    evidence=event_data,
                    remediation_steps=[
                        "Implement comprehensive access logging",
                        "Ensure user identification in all access events",
                        "Add timestamp tracking for all data access"
                    ],
                    created_at=datetime.now(),
                    risk_score=7.5
                )
        return None
    
    async def _check_data_retention(self, event_data: Dict[str, Any]) -> Optional[ComplianceViolation]:
        """Check GDPR data retention compliance"""
        if event_data.get('event_type') == 'data_storage':
            # Check if data has retention policy
            retention_period = event_data.get('retention_period')
            if not retention_period or retention_period > 365:  # Example: 1 year limit
                return ComplianceViolation(
                    violation_id=f"GDPR-RET-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    framework=ComplianceFramework.GDPR,
                    rule_id="gdpr_data_retention",
                    severity=ViolationSeverity.MEDIUM,
                    description="Data retention period exceeds GDPR limits",
                    affected_systems=[event_data.get('system', 'unknown')],
                    evidence=event_data,
                    remediation_steps=[
                        "Implement data retention policies",
                        "Set up automated data deletion",
                        "Review and classify data categories"
                    ],
                    created_at=datetime.now(),
                    risk_score=5.0
                )
        return None
    
    async def _check_breach_notification(self, event_data: Dict[str, Any]) -> Optional[ComplianceViolation]:
        """Check GDPR breach notification compliance"""
        if event_data.get('event_type') == 'data_breach':
            breach_time = datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat()))
            notification_time = event_data.get('notification_time')
            
            if not notification_time:
                # Breach not reported
                return ComplianceViolation(
                    violation_id=f"GDPR-BREACH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    framework=ComplianceFramework.GDPR,
                    rule_id="gdpr_breach_notification",
                    severity=ViolationSeverity.CRITICAL,
                    description="Data breach not reported within GDPR requirements",
                    affected_systems=[event_data.get('system', 'unknown')],
                    evidence=event_data,
                    remediation_steps=[
                        "Immediately notify data protection authority",
                        "Notify affected individuals",
                        "Document breach response procedures"
                    ],
                    created_at=datetime.now(),
                    risk_score=9.5
                )
            else:
                notification_time = datetime.fromisoformat(notification_time)
                if (notification_time - breach_time).total_seconds() > 72 * 3600:  # 72 hours
                    return ComplianceViolation(
                        violation_id=f"GDPR-LATE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        framework=ComplianceFramework.GDPR,
                        rule_id="gdpr_breach_notification",
                        severity=ViolationSeverity.HIGH,
                        description="Data breach reported after 72-hour GDPR deadline",
                        affected_systems=[event_data.get('system', 'unknown')],
                        evidence=event_data,
                        remediation_steps=[
                            "Review breach detection procedures",
                            "Improve incident response times",
                            "Implement automated breach notifications"
                        ],
                        created_at=datetime.now(),
                        risk_score=8.0
                    )
        return None
    
    async def _check_access_control(self, event_data: Dict[str, Any]) -> Optional[ComplianceViolation]:
        """Check ISO 27001 access control compliance"""
        if event_data.get('event_type') == 'login':
            # Check for proper access controls
            if event_data.get('authentication_method') != 'mfa':
                return ComplianceViolation(
                    violation_id=f"ISO27001-AC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    framework=ComplianceFramework.ISO27001,
                    rule_id="iso27001_access_control",
                    severity=ViolationSeverity.HIGH,
                    description="Login without multi-factor authentication",
                    affected_systems=[event_data.get('system', 'unknown')],
                    evidence=event_data,
                    remediation_steps=[
                        "Implement multi-factor authentication",
                        "Review access control policies",
                        "Train users on security procedures"
                    ],
                    created_at=datetime.now(),
                    risk_score=7.0
                )
        return None
    
    async def _check_incident_response(self, event_data: Dict[str, Any]) -> Optional[ComplianceViolation]:
        """Check ISO 27001 incident response compliance"""
        if event_data.get('severity') in ['high', 'critical']:
            response_time = event_data.get('response_time')
            if not response_time or response_time > 240:  # 4 hours
                return ComplianceViolation(
                    violation_id=f"ISO27001-IR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    framework=ComplianceFramework.ISO27001,
                    rule_id="iso27001_incident_response",
                    severity=ViolationSeverity.HIGH,
                    description="High-severity incident response time exceeds policy",
                    affected_systems=[event_data.get('system', 'unknown')],
                    evidence=event_data,
                    remediation_steps=[
                        "Review incident response procedures",
                        "Improve response team availability",
                        "Implement automated escalation"
                    ],
                    created_at=datetime.now(),
                    risk_score=6.5
                )
        return None
    
    async def _check_authentication(self, event_data: Dict[str, Any]) -> Optional[ComplianceViolation]:
        """Check NIST authentication compliance"""
        if event_data.get('event_type') == 'privileged_access':
            if not event_data.get('mfa_verified'):
                return ComplianceViolation(
                    violation_id=f"NIST-AUTH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    framework=ComplianceFramework.NIST,
                    rule_id="nist_authentication",
                    severity=ViolationSeverity.HIGH,
                    description="Privileged access without multi-factor authentication",
                    affected_systems=[event_data.get('system', 'unknown')],
                    evidence=event_data,
                    remediation_steps=[
                        "Enforce MFA for all privileged accounts",
                        "Review privileged access procedures",
                        "Implement adaptive authentication"
                    ],
                    created_at=datetime.now(),
                    risk_score=8.5
                )
        return None
    
    async def _check_encryption(self, event_data: Dict[str, Any]) -> Optional[ComplianceViolation]:
        """Check NIST encryption compliance"""
        if event_data.get('event_type') == 'data_transfer':
            if not event_data.get('encrypted') or event_data.get('encryption_strength', 0) < 256:
                return ComplianceViolation(
                    violation_id=f"NIST-ENC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    framework=ComplianceFramework.NIST,
                    rule_id="nist_encryption",
                    severity=ViolationSeverity.CRITICAL,
                    description="Sensitive data transmitted without proper encryption",
                    affected_systems=[event_data.get('system', 'unknown')],
                    evidence=event_data,
                    remediation_steps=[
                        "Implement strong encryption (AES-256)",
                        "Review data classification policies",
                        "Encrypt all sensitive data in transit"
                    ],
                    created_at=datetime.now(),
                    risk_score=9.0
                )
        return None
    
    async def _create_violation(self, violation: ComplianceViolation):
        """Create and store a compliance violation"""
        try:
            # Store violation
            self.active_violations[violation.violation_id] = violation
            
            # Save to database
            await self._save_violation_to_db(violation)
            
            # Log violation
            self.logger.warning(
                f"COMPLIANCE VIOLATION: {violation.violation_id} - "
                f"{violation.framework.value.upper()} - {violation.description}"
            )
            
            # Send notification
            await self._notify_compliance_violation(violation)
            
            # Update metrics
            self.update_metrics('violations_detected', 1)
            
        except Exception as e:
            self.logger.error(f"Error creating violation: {e}")
    
    async def _save_violation_to_db(self, violation: ComplianceViolation):
        """Save violation to database"""
        try:
            cursor = self.compliance_db.cursor()
            cursor.execute('''
                INSERT INTO violations 
                (violation_id, framework, rule_id, severity, description, affected_systems, 
                 evidence, remediation_steps, created_at, status, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                violation.violation_id,
                violation.framework.value,
                violation.rule_id,
                violation.severity.value,
                violation.description,
                json.dumps(violation.affected_systems),
                json.dumps(violation.evidence),
                json.dumps(violation.remediation_steps),
                violation.created_at.isoformat(),
                violation.status,
                violation.risk_score
            ))
            self.compliance_db.commit()
        except Exception as e:
            self.logger.error(f"Failed to save violation to database: {e}")
    
    async def _notify_compliance_violation(self, violation: ComplianceViolation):
        """Send compliance violation notification"""
        # Send to incident response if critical
        if violation.severity in [ViolationSeverity.CRITICAL, ViolationSeverity.HIGH]:
            await self.send_message(
                "incident_responder",
                "compliance_violation",
                {
                    'violation': violation.__dict__,
                    'priority': 'high' if violation.severity == ViolationSeverity.CRITICAL else 'medium',
                    'requires_immediate_action': violation.severity == ViolationSeverity.CRITICAL
                }
            )
        
        # Send to orchestrator for logging
        await self.send_message(
            "orchestrator",
            "compliance_alert",
            {
                'violation_id': violation.violation_id,
                'framework': violation.framework.value,
                'severity': violation.severity.value,
                'description': violation.description
            }
        )
    
    async def get_active_violations(self) -> List[Dict[str, Any]]:
        """Get all active compliance violations"""
        return [
            {
                'violation_id': v.violation_id,
                'framework': v.framework.value,
                'severity': v.severity.value,
                'description': v.description,
                'risk_score': v.risk_score,
                'created_at': v.created_at.isoformat(),
                'status': v.status
            }
            for v in self.active_violations.values()
        ]
    
    async def generate_compliance_report(self, framework: ComplianceFramework = None) -> Dict[str, Any]:
        """Generate compliance report"""
        try:
            cursor = self.compliance_db.cursor()
            
            if framework:
                cursor.execute(
                    "SELECT * FROM violations WHERE framework = ? AND created_at >= ?",
                    (framework.value, (datetime.now() - timedelta(days=30)).isoformat())
                )
            else:
                cursor.execute(
                    "SELECT * FROM violations WHERE created_at >= ?",
                    ((datetime.now() - timedelta(days=30)).isoformat(),)
                )
            
            violations = cursor.fetchall()
            
            # Generate report statistics
            total_violations = len(violations)
            severity_breakdown = {}
            framework_breakdown = {}
            
            for violation in violations:
                severity = violation[3]  # severity column
                framework_name = violation[1]  # framework column
                
                severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
                framework_breakdown[framework_name] = framework_breakdown.get(framework_name, 0) + 1
            
            report = {
                'report_id': f"COMP-RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'generated_at': datetime.now().isoformat(),
                'period': '30 days',
                'total_violations': total_violations,
                'severity_breakdown': severity_breakdown,
                'framework_breakdown': framework_breakdown,
                'compliance_score': max(0, 100 - (total_violations * 2)),  # Simple scoring
                'recommendations': self._generate_compliance_recommendations(violations)
            }
            
            self.logger.info(f"Generated compliance report: {total_violations} violations")
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating compliance report: {e}")
            return {'error': str(e)}
    
    def _generate_compliance_recommendations(self, violations: List) -> List[str]:
        """Generate compliance recommendations based on violations"""
        recommendations = []
        
        if len(violations) > 10:
            recommendations.append("High violation count - review security policies")
        
        # Analyze common violation types
        violation_types = {}
        for violation in violations:
            rule_id = violation[2]  # rule_id column
            violation_types[rule_id] = violation_types.get(rule_id, 0) + 1
        
        if violation_types:
            most_common = max(violation_types, key=violation_types.get)
            recommendations.append(f"Focus on {most_common} - most frequent violation type")
        
        recommendations.extend([
            "Implement regular compliance training",
            "Review and update security policies",
            "Conduct quarterly compliance audits"
        ])
        
        return recommendations
    
    async def analyze_event(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze event for compliance implications"""
        compliance_risks = []
        
        # Check for data privacy risks
        if any(pattern in event.description.lower() for pattern in ['personal', 'pii', 'customer']):
            compliance_risks.append('data_privacy')
        
        # Check for access control risks
        if event.event_type in ['login', 'file_access', 'admin_action']:
            compliance_risks.append('access_control')
        
        return {
            'compliance_risks': compliance_risks,
            'frameworks_affected': [f.value for f in self.enabled_frameworks],
            'requires_audit': len(compliance_risks) > 0
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Cleaning up Compliance Monitoring Agent")
        if hasattr(self, 'compliance_db'):
            self.compliance_db.close()


# Test function
async def test_compliance_agent():
    """Test the compliance monitoring agent"""
    agent = ComplianceMonitoringAgent()
    await agent.start()
    
    # Test compliance violation detection
    test_message = AgentMessage(
        agent_id="security_monitor",
        message_type="security_event",
        content={
            'event': {
                'event_type': 'data_access',
                'timestamp': datetime.now().isoformat(),
                'system': 'customer_database',
                'user_id': None,  # Missing user ID - violation
                'data_type': 'personal'
            }
        },
        timestamp=datetime.now()
    )
    
    await agent.receive_message(test_message)
    await asyncio.sleep(1)
    
    # Check violations
    violations = await agent.get_active_violations()
    print(f"✅ Compliance agent detected {len(violations)} violations")
    
    if violations:
        violation = violations[0]
        print(f"   Violation: {violation['violation_id']}")
        print(f"   Framework: {violation['framework']}")
        print(f"   Severity: {violation['severity']}")
    
    await agent.stop()
    return len(violations) > 0


if __name__ == "__main__":
    asyncio.run(test_compliance_agent())
