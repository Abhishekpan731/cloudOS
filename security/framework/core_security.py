#!/usr/bin/env python3
"""
CloudOS Core Security Framework
Comprehensive security, compliance, and threat detection system
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import threading

# Cryptography imports
try:
    from cryptography.fernet import Fernet, MultiFernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# JWT and auth imports
try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

# Security scanning imports
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(Enum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DATA_BREACH = "data_breach"
    DOS_ATTACK = "dos_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    POLICY_VIOLATION = "policy_violation"

class ComplianceStandard(Enum):
    SOC2 = "soc2"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"
    NIST = "nist"

class AuditEventType(Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_CHANGE = "privilege_change"
    CONFIGURATION_CHANGE = "configuration_change"
    DATA_ACCESS = "data_access"
    SYSTEM_CHANGE = "system_change"

@dataclass
class SecurityEvent:
    """Security event for monitoring and analysis"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    event_type: str = ""
    severity: SecurityLevel = SecurityLevel.LOW
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: str = "unknown"
    details: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)

@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    threat_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: ThreatType = ThreatType.SUSPICIOUS_ACTIVITY
    indicators: List[str] = field(default_factory=list)
    severity: SecurityLevel = SecurityLevel.MEDIUM
    confidence: float = 0.5
    description: str = ""
    mitigation: List[str] = field(default_factory=list)
    source: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityPolicy:
    """Security policy definition"""
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    compliance_standards: List[ComplianceStandard] = field(default_factory=list)
    rules: List[Dict[str, Any]] = field(default_factory=list)
    enforcement_level: SecurityLevel = SecurityLevel.MEDIUM
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class AuditRecord:
    """Audit trail record"""
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuditEventType = AuditEventType.SYSTEM_CHANGE
    user_id: str = ""
    session_id: Optional[str] = None
    resource: str = ""
    action: str = ""
    result: str = ""
    before_state: Dict[str, Any] = field(default_factory=dict)
    after_state: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    retention_period: timedelta = field(default_factory=lambda: timedelta(days=2555))  # 7 years default

class SecurityFramework:
    """
    Core security framework for CloudOS
    Provides authentication, authorization, threat detection, and compliance
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Security configuration
        self.encryption_enabled = self.config.get('encryption_enabled', True)
        self.audit_enabled = self.config.get('audit_enabled', True)
        self.threat_detection_enabled = self.config.get('threat_detection_enabled', True)

        # Cryptographic components
        self.master_key = None
        self.encryption_key = None
        self.signing_key = None
        self.jwt_secret = None

        # Storage
        self.security_events: deque = deque(maxlen=100000)  # Last 100k events
        self.audit_records: deque = deque(maxlen=100000)
        self.threat_intelligence: Dict[str, ThreatIntelligence] = {}
        self.security_policies: Dict[str, SecurityPolicy] = {}
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

        # Access control
        self.users: Dict[str, Dict[str, Any]] = {}
        self.roles: Dict[str, Dict[str, Any]] = {}
        self.permissions: Dict[str, Dict[str, Any]] = {}

        # Threat detection
        self.threat_patterns: List[Dict[str, Any]] = []
        self.anomaly_detectors: Dict[str, Any] = {}
        self.blocked_ips: Set[str] = set()
        self.rate_limiters: Dict[str, Dict[str, Any]] = defaultdict(dict)

        # Compliance tracking
        self.compliance_reports: Dict[str, Dict[str, Any]] = {}
        self.policy_violations: List[Dict[str, Any]] = []

        # Background tasks
        self.running = False
        self.monitor_task = None
        self.cleanup_task = None

        # Initialize security components
        self._initialize_crypto()
        self._load_default_policies()
        self._initialize_threat_detection()

        self.logger.info("Security Framework initialized")

    def _initialize_crypto(self):
        """Initialize cryptographic components"""
        if not HAS_CRYPTOGRAPHY:
            self.logger.warning("Cryptography library not available - encryption disabled")
            self.encryption_enabled = False
            return

        try:
            # Generate or load master key
            master_key_path = self.config.get('master_key_path', '/etc/cloudos/master.key')
            if os.path.exists(master_key_path):
                with open(master_key_path, 'rb') as f:
                    self.master_key = f.read()
            else:
                self.master_key = os.urandom(32)  # 256-bit key
                os.makedirs(os.path.dirname(master_key_path), exist_ok=True)
                with open(master_key_path, 'wb') as f:
                    f.write(self.master_key)
                os.chmod(master_key_path, 0o600)

            # Derive encryption key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'cloudos_encryption_salt',
                iterations=100000,
                backend=default_backend()
            )
            derived_key = kdf.derive(self.master_key)
            self.encryption_key = base64.urlsafe_b64encode(derived_key)

            # Generate signing key for JWTs
            if HAS_JWT:
                self.jwt_secret = secrets.token_urlsafe(32)

            self.logger.info("Cryptographic components initialized")

        except Exception as e:
            self.logger.error(f"Crypto initialization failed: {e}")
            self.encryption_enabled = False

    def _load_default_policies(self):
        """Load default security policies"""
        # Password policy
        password_policy = SecurityPolicy(
            name="Password Policy",
            description="Enforce strong password requirements",
            compliance_standards=[ComplianceStandard.SOC2, ComplianceStandard.ISO27001],
            rules=[
                {
                    "type": "password_minimum_length",
                    "value": 12
                },
                {
                    "type": "password_complexity",
                    "requirements": ["uppercase", "lowercase", "digits", "special_chars"]
                },
                {
                    "type": "password_expiry",
                    "days": 90
                }
            ],
            enforcement_level=SecurityLevel.HIGH
        )
        self.security_policies[password_policy.policy_id] = password_policy

        # Access control policy
        access_policy = SecurityPolicy(
            name="Access Control Policy",
            description="Least privilege access control",
            compliance_standards=[ComplianceStandard.SOC2, ComplianceStandard.NIST],
            rules=[
                {
                    "type": "session_timeout",
                    "minutes": 30
                },
                {
                    "type": "max_failed_attempts",
                    "count": 5
                },
                {
                    "type": "multi_factor_required",
                    "roles": ["admin", "operator"]
                }
            ],
            enforcement_level=SecurityLevel.HIGH
        )
        self.security_policies[access_policy.policy_id] = access_policy

        # Data protection policy
        data_policy = SecurityPolicy(
            name="Data Protection Policy",
            description="Protect sensitive data at rest and in transit",
            compliance_standards=[ComplianceStandard.GDPR, ComplianceStandard.HIPAA],
            rules=[
                {
                    "type": "encryption_at_rest",
                    "enabled": True
                },
                {
                    "type": "encryption_in_transit",
                    "minimum_tls_version": "1.2"
                },
                {
                    "type": "data_classification",
                    "levels": ["public", "internal", "confidential", "restricted"]
                }
            ],
            enforcement_level=SecurityLevel.CRITICAL
        )
        self.security_policies[data_policy.policy_id] = data_policy

        self.logger.info(f"Loaded {len(self.security_policies)} default security policies")

    def _initialize_threat_detection(self):
        """Initialize threat detection patterns and rules"""
        # Common attack patterns
        self.threat_patterns = [
            {
                "name": "SQL Injection",
                "pattern": r"(union|select|insert|update|delete|drop|exec|script)",
                "threat_type": ThreatType.INTRUSION,
                "severity": SecurityLevel.HIGH
            },
            {
                "name": "XSS Attack",
                "pattern": r"(<script|javascript:|onload=|onerror=)",
                "threat_type": ThreatType.INTRUSION,
                "severity": SecurityLevel.HIGH
            },
            {
                "name": "Path Traversal",
                "pattern": r"(\.\.\/|\.\.\\|%2e%2e%2f)",
                "threat_type": ThreatType.UNAUTHORIZED_ACCESS,
                "severity": SecurityLevel.MEDIUM
            },
            {
                "name": "Brute Force",
                "pattern": "multiple_failed_logins",
                "threat_type": ThreatType.INTRUSION,
                "severity": SecurityLevel.MEDIUM
            },
            {
                "name": "Privilege Escalation",
                "pattern": "unauthorized_permission_change",
                "threat_type": ThreatType.PRIVILEGE_ESCALATION,
                "severity": SecurityLevel.CRITICAL
            }
        ]

        # Initialize anomaly detection
        self.anomaly_detectors = {
            'login_frequency': {'baseline': 10, 'threshold': 50},
            'failed_logins': {'threshold': 5, 'window_minutes': 15},
            'data_access': {'baseline': 100, 'threshold': 1000},
            'api_calls': {'baseline': 1000, 'threshold': 10000}
        }

        self.logger.info("Threat detection patterns initialized")

    async def start(self):
        """Start security framework background tasks"""
        if self.running:
            return

        self.running = True

        # Start monitoring tasks
        self.monitor_task = asyncio.create_task(self._security_monitor())
        self.cleanup_task = asyncio.create_task(self._cleanup_task())

        self.logger.info("Security Framework started")

    async def stop(self):
        """Stop security framework"""
        if not self.running:
            return

        self.running = False

        # Cancel background tasks
        if self.monitor_task:
            self.monitor_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(
            self.monitor_task, self.cleanup_task,
            return_exceptions=True
        )

        self.logger.info("Security Framework stopped")

    async def _security_monitor(self):
        """Background security monitoring task"""
        while self.running:
            try:
                # Check for threats
                await self._check_threat_indicators()

                # Monitor session timeouts
                await self._check_session_timeouts()

                # Update rate limiters
                await self._update_rate_limiters()

                # Generate compliance reports
                await self._update_compliance_status()

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Security monitor error: {e}")
                await asyncio.sleep(60)

    async def _cleanup_task(self):
        """Background cleanup task"""
        while self.running:
            try:
                # Clean up old events
                cutoff_time = datetime.now(timezone.utc) - timedelta(days=30)

                # Clean security events
                original_count = len(self.security_events)
                self.security_events = deque(
                    [event for event in self.security_events if event.timestamp > cutoff_time],
                    maxlen=100000
                )
                cleaned_events = original_count - len(self.security_events)

                # Clean audit records based on retention policy
                current_audit_count = len(self.audit_records)
                self.audit_records = deque(
                    [record for record in self.audit_records
                     if record.timestamp > (datetime.now(timezone.utc) - record.retention_period)],
                    maxlen=100000
                )
                cleaned_audit = current_audit_count - len(self.audit_records)

                # Clean expired threat intelligence
                expired_threats = []
                for threat_id, threat in self.threat_intelligence.items():
                    if threat.expires_at and threat.expires_at < datetime.now(timezone.utc):
                        expired_threats.append(threat_id)

                for threat_id in expired_threats:
                    del self.threat_intelligence[threat_id]

                self.logger.debug(f"Cleanup: {cleaned_events} events, {cleaned_audit} audit records, "
                                f"{len(expired_threats)} expired threats")

                await asyncio.sleep(3600)  # Run cleanup every hour

            except Exception as e:
                self.logger.error(f"Cleanup task error: {e}")
                await asyncio.sleep(3600)

    # Authentication and Authorization

    async def authenticate_user(self, username: str, password: str,
                              ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """Authenticate user credentials"""
        # Create security event
        event = SecurityEvent(
            source="authentication",
            event_type="login_attempt",
            user_id=username,
            ip_address=ip_address,
            user_agent=user_agent,
            action="authenticate",
            details={'username': username}
        )

        try:
            # Check if IP is blocked
            if ip_address and ip_address in self.blocked_ips:
                event.result = "blocked_ip"
                event.severity = SecurityLevel.HIGH
                await self._record_security_event(event)
                return {'success': False, 'reason': 'IP address blocked'}

            # Check rate limiting
            if not await self._check_rate_limit(f"login_{ip_address}", max_attempts=5, window_minutes=15):
                event.result = "rate_limited"
                event.severity = SecurityLevel.MEDIUM
                await self._record_security_event(event)
                return {'success': False, 'reason': 'Rate limit exceeded'}

            # Validate user
            user = self.users.get(username)
            if not user:
                event.result = "user_not_found"
                event.severity = SecurityLevel.LOW
                await self._record_security_event(event)
                return {'success': False, 'reason': 'Invalid credentials'}

            # Check password
            if not self._verify_password(password, user.get('password_hash', '')):
                # Track failed login
                await self._track_failed_login(username, ip_address)
                event.result = "invalid_password"
                event.severity = SecurityLevel.MEDIUM
                await self._record_security_event(event)
                return {'success': False, 'reason': 'Invalid credentials'}

            # Check if account is locked
            if user.get('locked', False):
                event.result = "account_locked"
                event.severity = SecurityLevel.HIGH
                await self._record_security_event(event)
                return {'success': False, 'reason': 'Account locked'}

            # Generate session
            session_id = secrets.token_urlsafe(32)
            session_data = {
                'user_id': username,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'created_at': datetime.now(timezone.utc),
                'last_activity': datetime.now(timezone.utc),
                'permissions': user.get('permissions', []),
                'roles': user.get('roles', [])
            }

            self.active_sessions[session_id] = session_data

            # Generate JWT token if available
            token = None
            if HAS_JWT and self.jwt_secret:
                payload = {
                    'user_id': username,
                    'session_id': session_id,
                    'iat': int(time.time()),
                    'exp': int(time.time()) + 3600  # 1 hour expiry
                }
                token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')

            # Record successful login
            event.result = "success"
            event.session_id = session_id
            event.severity = SecurityLevel.LOW
            await self._record_security_event(event)

            # Create audit record
            audit_record = AuditRecord(
                event_type=AuditEventType.LOGIN,
                user_id=username,
                session_id=session_id,
                resource="authentication",
                action="login",
                result="success",
                metadata={'ip_address': ip_address, 'user_agent': user_agent}
            )
            await self._record_audit_event(audit_record)

            return {
                'success': True,
                'session_id': session_id,
                'token': token,
                'user': {
                    'id': username,
                    'roles': user.get('roles', []),
                    'permissions': user.get('permissions', [])
                }
            }

        except Exception as e:
            event.result = "error"
            event.severity = SecurityLevel.HIGH
            event.details['error'] = str(e)
            await self._record_security_event(event)
            self.logger.error(f"Authentication error: {e}")
            return {'success': False, 'reason': 'Authentication error'}

    async def authorize_action(self, session_id: str, resource: str, action: str) -> bool:
        """Check if session is authorized for specific action"""
        session = self.active_sessions.get(session_id)
        if not session:
            return False

        # Update last activity
        session['last_activity'] = datetime.now(timezone.utc)

        # Check session timeout
        timeout_minutes = 30  # Default timeout
        if (datetime.now(timezone.utc) - session['last_activity']).total_seconds() > timeout_minutes * 60:
            await self._expire_session(session_id)
            return False

        # Check permissions
        user_permissions = session.get('permissions', [])
        required_permission = f"{resource}:{action}"

        # Check exact permission or wildcard
        if required_permission in user_permissions or f"{resource}:*" in user_permissions or "*:*" in user_permissions:
            return True

        # Check role-based permissions
        user_roles = session.get('roles', [])
        for role in user_roles:
            role_permissions = self.roles.get(role, {}).get('permissions', [])
            if required_permission in role_permissions or f"{resource}:*" in role_permissions:
                return True

        # Record unauthorized access attempt
        event = SecurityEvent(
            source="authorization",
            event_type="access_denied",
            user_id=session.get('user_id'),
            session_id=session_id,
            resource=resource,
            action=action,
            result="unauthorized",
            severity=SecurityLevel.MEDIUM
        )
        await self._record_security_event(event)

        return False

    # Encryption and Data Protection

    def encrypt_data(self, data: Union[str, bytes]) -> str:
        """Encrypt sensitive data"""
        if not self.encryption_enabled or not HAS_CRYPTOGRAPHY:
            return data if isinstance(data, str) else data.decode('utf-8')

        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(data)
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')

        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            return data if isinstance(data, str) else data.decode('utf-8')

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.encryption_enabled or not HAS_CRYPTOGRAPHY:
            return encrypted_data

        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            fernet = Fernet(self.encryption_key)
            decrypted_data = fernet.decrypt(decoded_data)
            return decrypted_data.decode('utf-8')

        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            return encrypted_data

    def hash_password(self, password: str) -> str:
        """Hash password using secure algorithm"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{password_hash.hex()}"

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, password_hash = stored_hash.split(':')
            computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hmac.compare_digest(password_hash, computed_hash.hex())
        except Exception:
            return False

    # Threat Detection and Response

    async def _check_threat_indicators(self):
        """Check for threat indicators in recent events"""
        recent_events = [
            event for event in self.security_events
            if event.timestamp > datetime.now(timezone.utc) - timedelta(minutes=10)
        ]

        # Check for pattern matches
        for pattern in self.threat_patterns:
            await self._check_threat_pattern(pattern, recent_events)

        # Check for anomalies
        await self._check_anomalies(recent_events)

    async def _check_threat_pattern(self, pattern: Dict[str, Any], events: List[SecurityEvent]):
        """Check for specific threat pattern"""
        matches = []

        for event in events:
            # Check pattern match
            if pattern['pattern'] == 'multiple_failed_logins':
                if event.event_type == 'login_attempt' and event.result in ['invalid_password', 'user_not_found']:
                    matches.append(event)
            elif pattern['pattern'] == 'unauthorized_permission_change':
                if event.event_type == 'privilege_change' and event.result == 'unauthorized':
                    matches.append(event)
            else:
                # Pattern matching on event details
                for key, value in event.details.items():
                    if isinstance(value, str) and pattern['pattern'].lower() in value.lower():
                        matches.append(event)

        # Trigger threat response if threshold exceeded
        if len(matches) >= 3:  # Threshold for threat detection
            threat = ThreatIntelligence(
                threat_type=pattern['threat_type'],
                indicators=[match.event_id for match in matches],
                severity=pattern['severity'],
                confidence=0.8,
                description=f"Detected {pattern['name']} pattern",
                source="pattern_detection"
            )
            await self._handle_threat(threat)

    async def _check_anomalies(self, events: List[SecurityEvent]):
        """Check for behavioral anomalies"""
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            if event.user_id:
                user_events[event.user_id].append(event)

        # Check for anomalous behavior
        for user_id, user_event_list in user_events.items():
            # Check login frequency
            login_events = [e for e in user_event_list if e.event_type == 'login_attempt']
            if len(login_events) > self.anomaly_detectors['login_frequency']['threshold']:
                threat = ThreatIntelligence(
                    threat_type=ThreatType.SUSPICIOUS_ACTIVITY,
                    indicators=[user_id],
                    severity=SecurityLevel.MEDIUM,
                    confidence=0.7,
                    description=f"Anomalous login frequency for user {user_id}",
                    source="anomaly_detection"
                )
                await self._handle_threat(threat)

    async def _handle_threat(self, threat: ThreatIntelligence):
        """Handle detected threat"""
        self.threat_intelligence[threat.threat_id] = threat

        # Log threat
        self.logger.warning(f"Threat detected: {threat.description} (Severity: {threat.severity.value})")

        # Take response actions based on severity
        if threat.severity == SecurityLevel.CRITICAL:
            # Block IP addresses if available
            for event_id in threat.indicators:
                event = next((e for e in self.security_events if e.event_id == event_id), None)
                if event and event.ip_address:
                    self.blocked_ips.add(event.ip_address)
                    self.logger.warning(f"Blocked IP address: {event.ip_address}")

        elif threat.severity == SecurityLevel.HIGH:
            # Increase monitoring for affected users/IPs
            pass

        # Create security event for threat detection
        threat_event = SecurityEvent(
            source="threat_detection",
            event_type="threat_detected",
            severity=threat.severity,
            action="threat_response",
            result="handled",
            details={
                'threat_id': threat.threat_id,
                'threat_type': threat.threat_type.value,
                'confidence': threat.confidence,
                'indicators': threat.indicators
            }
        )
        await self._record_security_event(threat_event)

    # Utility Methods

    async def _track_failed_login(self, username: str, ip_address: str):
        """Track failed login attempts"""
        # Update failed attempt counters
        if ip_address:
            self._increment_rate_limit(f"failed_login_{ip_address}")

        self._increment_rate_limit(f"failed_login_{username}")

        # Lock account after too many failures
        user = self.users.get(username)
        if user:
            failed_attempts = user.get('failed_attempts', 0) + 1
            user['failed_attempts'] = failed_attempts

            if failed_attempts >= 5:  # Lock after 5 failed attempts
                user['locked'] = True
                user['locked_at'] = datetime.now(timezone.utc)

    async def _check_rate_limit(self, key: str, max_attempts: int, window_minutes: int) -> bool:
        """Check if action is within rate limit"""
        now = datetime.now(timezone.utc)
        rate_limit_data = self.rate_limiters.get(key, {'attempts': [], 'blocked_until': None})

        # Check if currently blocked
        if rate_limit_data['blocked_until'] and now < rate_limit_data['blocked_until']:
            return False

        # Clean old attempts
        window_start = now - timedelta(minutes=window_minutes)
        rate_limit_data['attempts'] = [
            attempt for attempt in rate_limit_data['attempts']
            if attempt > window_start
        ]

        # Check if within limit
        if len(rate_limit_data['attempts']) >= max_attempts:
            # Block for window duration
            rate_limit_data['blocked_until'] = now + timedelta(minutes=window_minutes)
            self.rate_limiters[key] = rate_limit_data
            return False

        return True

    def _increment_rate_limit(self, key: str):
        """Increment rate limit counter"""
        now = datetime.now(timezone.utc)
        if key not in self.rate_limiters:
            self.rate_limiters[key] = {'attempts': []}

        self.rate_limiters[key]['attempts'].append(now)

    async def _update_rate_limiters(self):
        """Clean up expired rate limit data"""
        now = datetime.now(timezone.utc)
        expired_keys = []

        for key, data in self.rate_limiters.items():
            # Remove old attempts
            data['attempts'] = [
                attempt for attempt in data['attempts']
                if attempt > now - timedelta(hours=1)  # Keep last hour
            ]

            # Remove expired blocks
            if data.get('blocked_until') and now > data['blocked_until']:
                data['blocked_until'] = None

            # Remove empty entries
            if not data['attempts'] and not data.get('blocked_until'):
                expired_keys.append(key)

        for key in expired_keys:
            del self.rate_limiters[key]

    async def _check_session_timeouts(self):
        """Check for expired sessions"""
        now = datetime.now(timezone.utc)
        expired_sessions = []

        for session_id, session in self.active_sessions.items():
            timeout = timedelta(minutes=30)  # Default timeout
            if now - session['last_activity'] > timeout:
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            await self._expire_session(session_id)

    async def _expire_session(self, session_id: str):
        """Expire a session"""
        session = self.active_sessions.pop(session_id, None)
        if session:
            # Create logout audit record
            audit_record = AuditRecord(
                event_type=AuditEventType.LOGOUT,
                user_id=session.get('user_id', ''),
                session_id=session_id,
                resource="authentication",
                action="logout",
                result="session_expired"
            )
            await self._record_audit_event(audit_record)

    async def _record_security_event(self, event: SecurityEvent):
        """Record security event"""
        self.security_events.append(event)

        # Log high severity events
        if event.severity in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            self.logger.warning(f"Security event: {event.event_type} - {event.result} "
                              f"(Severity: {event.severity.value})")

    async def _record_audit_event(self, record: AuditRecord):
        """Record audit event"""
        if self.audit_enabled:
            self.audit_records.append(record)

    async def _update_compliance_status(self):
        """Update compliance status"""
        # This would implement compliance checking logic
        # For now, we'll just track basic metrics

        current_time = datetime.now(timezone.utc)
        for standard in ComplianceStandard:
            if standard.value not in self.compliance_reports:
                self.compliance_reports[standard.value] = {
                    'last_updated': current_time,
                    'status': 'compliant',
                    'issues': [],
                    'policies': []
                }

    # Public API Methods

    def get_security_status(self) -> Dict[str, Any]:
        """Get overall security status"""
        recent_events = [
            event for event in self.security_events
            if event.timestamp > datetime.now(timezone.utc) - timedelta(hours=24)
        ]

        threat_levels = {level: 0 for level in SecurityLevel}
        for event in recent_events:
            threat_levels[event.severity] += 1

        active_threats = len([
            threat for threat in self.threat_intelligence.values()
            if not threat.expires_at or threat.expires_at > datetime.now(timezone.utc)
        ])

        return {
            'status': 'secure' if threat_levels[SecurityLevel.CRITICAL] == 0 else 'at_risk',
            'active_sessions': len(self.active_sessions),
            'blocked_ips': len(self.blocked_ips),
            'active_threats': active_threats,
            'events_24h': len(recent_events),
            'threat_levels': {level.value: count for level, count in threat_levels.items()},
            'policies_enforced': len([p for p in self.security_policies.values() if p.enabled]),
            'encryption_enabled': self.encryption_enabled,
            'audit_enabled': self.audit_enabled,
            'last_updated': datetime.now(timezone.utc).isoformat()
        }

    def get_compliance_report(self, standard: ComplianceStandard) -> Dict[str, Any]:
        """Get compliance report for specific standard"""
        return self.compliance_reports.get(standard.value, {
            'status': 'unknown',
            'last_updated': None,
            'issues': [],
            'policies': []
        })

    def create_user(self, username: str, password: str, roles: List[str] = None,
                   permissions: List[str] = None) -> bool:
        """Create new user account"""
        if username in self.users:
            return False

        self.users[username] = {
            'password_hash': self.hash_password(password),
            'roles': roles or [],
            'permissions': permissions or [],
            'created_at': datetime.now(timezone.utc),
            'locked': False,
            'failed_attempts': 0
        }

        return True

    def add_security_policy(self, policy: SecurityPolicy) -> bool:
        """Add new security policy"""
        self.security_policies[policy.policy_id] = policy
        return True

    def get_audit_trail(self, user_id: str = None, start_time: datetime = None,
                       end_time: datetime = None) -> List[AuditRecord]:
        """Get audit trail records"""
        records = list(self.audit_records)

        if user_id:
            records = [r for r in records if r.user_id == user_id]

        if start_time:
            records = [r for r in records if r.timestamp >= start_time]

        if end_time:
            records = [r for r in records if r.timestamp <= end_time]

        return sorted(records, key=lambda x: x.timestamp, reverse=True)

# Example usage
if __name__ == "__main__":
    async def test_security_framework():
        framework = SecurityFramework()
        await framework.start()

        # Create test user
        framework.create_user("admin", "SecurePassword123!", ["admin"], ["*:*"])

        # Test authentication
        auth_result = await framework.authenticate_user("admin", "SecurePassword123!", "127.0.0.1")
        print(f"Authentication result: {auth_result}")

        if auth_result['success']:
            session_id = auth_result['session_id']

            # Test authorization
            authorized = await framework.authorize_action(session_id, "users", "create")
            print(f"Authorization result: {authorized}")

        # Get security status
        status = framework.get_security_status()
        print(f"Security status: {json.dumps(status, indent=2, default=str)}")

        await framework.stop()

    asyncio.run(test_security_framework())