#!/usr/bin/env python3
"""
CloudOS Self-Healing and Automated Remediation System
AI-powered failure detection, diagnosis, and automated recovery
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import threading

# ML and analysis imports
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(Enum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    DIAGNOSING = "diagnosing"
    REMEDIATING = "remediating"
    RESOLVED = "resolved"
    ESCALATED = "escalated"

class RemediationAction(Enum):
    RESTART_SERVICE = "restart_service"
    SCALE_OUT = "scale_out"
    SCALE_UP = "scale_up"
    FAILOVER = "failover"
    ROLLBACK = "rollback"
    CLEAR_CACHE = "clear_cache"
    RESTART_CONTAINER = "restart_container"
    DRAIN_NODE = "drain_node"
    REPLACE_NODE = "replace_node"
    UPDATE_CONFIG = "update_config"
    MANUAL_INTERVENTION = "manual_intervention"

class HealthMetricType(Enum):
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    DISK_USAGE = "disk_usage"
    NETWORK_LATENCY = "network_latency"
    ERROR_RATE = "error_rate"
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    AVAILABILITY = "availability"
    CUSTOM = "custom"

@dataclass
class HealthMetric:
    """System health metric"""
    timestamp: datetime
    source: str  # service, node, container, etc.
    metric_type: HealthMetricType
    value: float
    unit: str
    tags: Dict[str, str] = field(default_factory=dict)
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None

@dataclass
class Incident:
    """System incident requiring investigation and remediation"""
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.DETECTED
    source: str = ""
    affected_components: List[str] = field(default_factory=list)
    root_cause: Optional[str] = None
    symptoms: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)
    metrics: List[HealthMetric] = field(default_factory=list)

@dataclass
class RemediationPlan:
    """Automated remediation plan"""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    actions: List[RemediationAction] = field(default_factory=list)
    action_details: List[Dict[str, Any]] = field(default_factory=list)
    estimated_recovery_time: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    success_probability: float = 0.8
    risk_level: str = "low"
    rollback_plan: Optional[List[RemediationAction]] = None
    prerequisites: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class RemediationResult:
    """Result of remediation execution"""
    plan_id: str
    action: RemediationAction
    success: bool
    execution_time: timedelta
    output: str = ""
    error: Optional[str] = None
    metrics_before: Dict[str, float] = field(default_factory=dict)
    metrics_after: Dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

class SelfHealingSystem:
    """
    AI-powered self-healing system for CloudOS
    Provides automated failure detection, diagnosis, and remediation
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # System configuration
        self.enabled = self.config.get('enabled', True)
        self.auto_remediation = self.config.get('auto_remediation', True)
        self.escalation_timeout = timedelta(minutes=self.config.get('escalation_timeout_minutes', 15))
        self.max_remediation_attempts = self.config.get('max_remediation_attempts', 3)

        # Data storage
        self.health_metrics: deque = deque(maxlen=10000)  # Last 10k metrics
        self.incidents: Dict[str, Incident] = {}
        self.remediation_history: List[RemediationResult] = []
        self.baseline_metrics: Dict[str, Dict[str, float]] = {}

        # Detection and analysis
        self.anomaly_detectors: Dict[str, Any] = {}
        self.pattern_analyzers: Dict[str, Any] = {}
        self.prediction_models: Dict[str, Any] = {}

        # Remediation
        self.remediation_handlers: Dict[RemediationAction, Callable] = {}
        self.active_remediations: Dict[str, asyncio.Task] = {}

        # Monitoring and alerting
        self.alert_handlers: List[Callable] = []
        self.escalation_handlers: List[Callable] = []

        # Knowledge base
        self.symptom_patterns: Dict[str, List[str]] = {}
        self.remediation_success_rates: Dict[RemediationAction, float] = {}
        self.incident_playbooks: Dict[str, RemediationPlan] = {}

        # Initialize components
        self._initialize_anomaly_detection()
        self._initialize_remediation_handlers()
        self._load_knowledge_base()

        self.logger.info("Self-Healing System initialized")

    def _initialize_anomaly_detection(self):
        """Initialize anomaly detection models"""
        if HAS_SKLEARN:
            # Isolation Forest for outlier detection
            self.anomaly_detectors['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42
            )

            # DBSCAN for clustering anomalies
            self.anomaly_detectors['dbscan'] = DBSCAN(
                eps=0.5,
                min_samples=5
            )

        self.logger.info("Anomaly detection models initialized")

    def _initialize_remediation_handlers(self):
        """Initialize remediation action handlers"""
        self.remediation_handlers = {
            RemediationAction.RESTART_SERVICE: self._restart_service,
            RemediationAction.SCALE_OUT: self._scale_out,
            RemediationAction.SCALE_UP: self._scale_up,
            RemediationAction.FAILOVER: self._failover,
            RemediationAction.ROLLBACK: self._rollback,
            RemediationAction.CLEAR_CACHE: self._clear_cache,
            RemediationAction.RESTART_CONTAINER: self._restart_container,
            RemediationAction.DRAIN_NODE: self._drain_node,
            RemediationAction.REPLACE_NODE: self._replace_node,
            RemediationAction.UPDATE_CONFIG: self._update_config,
            RemediationAction.MANUAL_INTERVENTION: self._manual_intervention
        }

        self.logger.info("Remediation handlers initialized")

    def _load_knowledge_base(self):
        """Load knowledge base with patterns and playbooks"""
        # Symptom patterns for common issues
        self.symptom_patterns = {
            "high_cpu_usage": [
                "CPU usage > 90% for 5+ minutes",
                "Response time degradation",
                "Increased request queuing"
            ],
            "memory_leak": [
                "Memory usage steadily increasing",
                "GC frequency increasing",
                "Application responsiveness decreasing"
            ],
            "network_issues": [
                "High network latency",
                "Packet loss detected",
                "Connection timeouts"
            ],
            "storage_full": [
                "Disk usage > 95%",
                "Write operations failing",
                "Log rotation issues"
            ],
            "service_unavailable": [
                "Health check failures",
                "Connection refused errors",
                "Zero successful requests"
            ]
        }

        # Default success rates for remediation actions
        self.remediation_success_rates = {
            RemediationAction.RESTART_SERVICE: 0.85,
            RemediationAction.SCALE_OUT: 0.90,
            RemediationAction.SCALE_UP: 0.80,
            RemediationAction.FAILOVER: 0.95,
            RemediationAction.ROLLBACK: 0.90,
            RemediationAction.CLEAR_CACHE: 0.70,
            RemediationAction.RESTART_CONTAINER: 0.85,
            RemediationAction.DRAIN_NODE: 0.95,
            RemediationAction.REPLACE_NODE: 0.98,
            RemediationAction.UPDATE_CONFIG: 0.75
        }

        self.logger.info("Knowledge base loaded")

    async def add_health_metric(self, metric: HealthMetric):
        """Add a health metric for monitoring"""
        self.health_metrics.append(metric)

        # Update baseline metrics
        await self._update_baseline_metrics(metric)

        # Check for anomalies
        anomalies = await self._detect_anomalies([metric])

        # Trigger incident detection if anomalies found
        if anomalies:
            await self._trigger_incident_detection(metric, anomalies)

        self.logger.debug(f"Added health metric: {metric.source} {metric.metric_type.value} = {metric.value}")

    async def _update_baseline_metrics(self, metric: HealthMetric):
        """Update baseline metrics for normal behavior"""
        key = f"{metric.source}_{metric.metric_type.value}"

        if key not in self.baseline_metrics:
            self.baseline_metrics[key] = {
                'values': [],
                'mean': 0.0,
                'std': 0.0,
                'min': float('inf'),
                'max': float('-inf'),
                'last_updated': datetime.now()
            }

        baseline = self.baseline_metrics[key]
        baseline['values'].append(metric.value)

        # Keep only last 1000 values for baseline
        if len(baseline['values']) > 1000:
            baseline['values'] = baseline['values'][-1000:]

        # Update statistics
        values = baseline['values']
        if HAS_NUMPY:
            baseline['mean'] = float(np.mean(values))
            baseline['std'] = float(np.std(values))
            baseline['min'] = float(np.min(values))
            baseline['max'] = float(np.max(values))
        else:
            import statistics
            baseline['mean'] = statistics.mean(values)
            baseline['std'] = statistics.stdev(values) if len(values) > 1 else 0.0
            baseline['min'] = min(values)
            baseline['max'] = max(values)

        baseline['last_updated'] = datetime.now()

    async def _detect_anomalies(self, metrics: List[HealthMetric]) -> List[Dict[str, Any]]:
        """Detect anomalies in health metrics"""
        anomalies = []

        for metric in metrics:
            # Threshold-based detection
            threshold_anomaly = await self._detect_threshold_anomaly(metric)
            if threshold_anomaly:
                anomalies.append(threshold_anomaly)

            # Statistical anomaly detection
            statistical_anomaly = await self._detect_statistical_anomaly(metric)
            if statistical_anomaly:
                anomalies.append(statistical_anomaly)

            # Pattern-based anomaly detection
            pattern_anomaly = await self._detect_pattern_anomaly(metric)
            if pattern_anomaly:
                anomalies.append(pattern_anomaly)

        return anomalies

    async def _detect_threshold_anomaly(self, metric: HealthMetric) -> Optional[Dict[str, Any]]:
        """Detect threshold-based anomalies"""
        if metric.threshold_critical and metric.value >= metric.threshold_critical:
            return {
                'type': 'threshold_critical',
                'metric': metric,
                'severity': IncidentSeverity.CRITICAL,
                'message': f"{metric.metric_type.value} value {metric.value} exceeds critical threshold {metric.threshold_critical}"
            }
        elif metric.threshold_warning and metric.value >= metric.threshold_warning:
            return {
                'type': 'threshold_warning',
                'metric': metric,
                'severity': IncidentSeverity.MEDIUM,
                'message': f"{metric.metric_type.value} value {metric.value} exceeds warning threshold {metric.threshold_warning}"
            }
        return None

    async def _detect_statistical_anomaly(self, metric: HealthMetric) -> Optional[Dict[str, Any]]:
        """Detect statistical anomalies using baseline metrics"""
        key = f"{metric.source}_{metric.metric_type.value}"
        baseline = self.baseline_metrics.get(key)

        if not baseline or len(baseline['values']) < 30:
            return None  # Not enough data for statistical analysis

        mean = baseline['mean']
        std = baseline['std']

        if std == 0:
            return None  # No variance in baseline

        # Z-score anomaly detection
        z_score = abs(metric.value - mean) / std

        if z_score > 3:  # 3 standard deviations
            return {
                'type': 'statistical_anomaly',
                'metric': metric,
                'severity': IncidentSeverity.HIGH if z_score > 4 else IncidentSeverity.MEDIUM,
                'message': f"{metric.metric_type.value} value {metric.value} is {z_score:.2f} standard deviations from baseline",
                'z_score': z_score,
                'baseline_mean': mean,
                'baseline_std': std
            }

        return None

    async def _detect_pattern_anomaly(self, metric: HealthMetric) -> Optional[Dict[str, Any]]:
        """Detect pattern-based anomalies"""
        # Get recent metrics for the same source and type
        recent_metrics = [
            m for m in list(self.health_metrics)[-100:]
            if m.source == metric.source and m.metric_type == metric.metric_type
        ]

        if len(recent_metrics) < 10:
            return None

        # Check for rapid increase/decrease patterns
        values = [m.value for m in recent_metrics[-10:]]

        if len(values) >= 5:
            # Check for consistent increase
            increasing_count = sum(1 for i in range(1, len(values)) if values[i] > values[i-1])
            decreasing_count = sum(1 for i in range(1, len(values)) if values[i] < values[i-1])

            if increasing_count >= 8:  # 80% increasing
                rate_of_change = (values[-1] - values[0]) / len(values)
                if rate_of_change > 0.1:  # Significant increase
                    return {
                        'type': 'pattern_rapid_increase',
                        'metric': metric,
                        'severity': IncidentSeverity.MEDIUM,
                        'message': f"{metric.metric_type.value} showing rapid increase pattern",
                        'rate_of_change': rate_of_change
                    }

            elif decreasing_count >= 8 and metric.metric_type in [HealthMetricType.THROUGHPUT, HealthMetricType.AVAILABILITY]:
                rate_of_change = (values[0] - values[-1]) / len(values)
                if rate_of_change > 0.1:  # Significant decrease in performance metrics
                    return {
                        'type': 'pattern_rapid_decrease',
                        'metric': metric,
                        'severity': IncidentSeverity.MEDIUM,
                        'message': f"{metric.metric_type.value} showing rapid decrease pattern",
                        'rate_of_change': rate_of_change
                    }

        return None

    async def _trigger_incident_detection(self, metric: HealthMetric, anomalies: List[Dict[str, Any]]):
        """Trigger incident detection and creation"""
        # Group anomalies by severity and source
        critical_anomalies = [a for a in anomalies if a.get('severity') == IncidentSeverity.CRITICAL]
        high_anomalies = [a for a in anomalies if a.get('severity') == IncidentSeverity.HIGH]

        # Create incident for critical anomalies
        if critical_anomalies:
            incident = await self._create_incident(metric, critical_anomalies, IncidentSeverity.CRITICAL)
            await self._process_incident(incident)

        # Create incident for multiple high anomalies
        elif len(high_anomalies) >= 2:
            incident = await self._create_incident(metric, high_anomalies, IncidentSeverity.HIGH)
            await self._process_incident(incident)

    async def _create_incident(self,
                             trigger_metric: HealthMetric,
                             anomalies: List[Dict[str, Any]],
                             severity: IncidentSeverity) -> Incident:
        """Create a new incident"""

        # Generate incident title and description
        anomaly_types = [a['type'] for a in anomalies]
        title = f"{trigger_metric.source} - {', '.join(anomaly_types)}"

        description_parts = []
        symptoms = []

        for anomaly in anomalies:
            description_parts.append(anomaly['message'])
            symptoms.append(anomaly['message'])

        description = "; ".join(description_parts)

        # Identify affected components
        affected_components = [trigger_metric.source]

        # Check for related components
        related_metrics = [
            m for m in list(self.health_metrics)[-50:]
            if m.source != trigger_metric.source and
               m.timestamp > datetime.now() - timedelta(minutes=5)
        ]

        for related_metric in related_metrics:
            related_anomalies = await self._detect_anomalies([related_metric])
            if related_anomalies:
                affected_components.append(related_metric.source)

        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            source=trigger_metric.source,
            affected_components=list(set(affected_components)),
            symptoms=symptoms,
            metrics=[trigger_metric] + [a['metric'] for a in anomalies if 'metric' in a],
            tags={
                'metric_type': trigger_metric.metric_type.value,
                'auto_detected': 'true'
            }
        )

        self.incidents[incident.incident_id] = incident
        self.logger.warning(f"Created incident {incident.incident_id}: {incident.title}")

        return incident

    async def _process_incident(self, incident: Incident):
        """Process an incident through the healing pipeline"""
        try:
            # Update incident status
            incident.status = IncidentStatus.INVESTIGATING
            incident.updated_at = datetime.now()

            # Perform root cause analysis
            await self._perform_root_cause_analysis(incident)

            # Generate remediation plan
            remediation_plan = await self._generate_remediation_plan(incident)

            if remediation_plan and self.auto_remediation:
                # Execute automated remediation
                await self._execute_remediation_plan(incident, remediation_plan)
            else:
                # Escalate for manual intervention
                await self._escalate_incident(incident, "No automated remediation available")

        except Exception as e:
            self.logger.error(f"Error processing incident {incident.incident_id}: {e}")
            await self._escalate_incident(incident, f"Processing error: {e}")

    async def _perform_root_cause_analysis(self, incident: Incident):
        """Perform AI-powered root cause analysis"""
        incident.status = IncidentStatus.DIAGNOSING
        incident.updated_at = datetime.now()

        # Analyze symptoms against known patterns
        potential_causes = []

        for pattern_name, pattern_symptoms in self.symptom_patterns.items():
            matching_symptoms = 0
            for symptom in pattern_symptoms:
                if any(symptom.lower() in s.lower() for s in incident.symptoms):
                    matching_symptoms += 1

            if matching_symptoms > 0:
                confidence = matching_symptoms / len(pattern_symptoms)
                potential_causes.append({
                    'cause': pattern_name,
                    'confidence': confidence,
                    'matching_symptoms': matching_symptoms
                })

        # Sort by confidence
        potential_causes.sort(key=lambda x: x['confidence'], reverse=True)

        if potential_causes:
            best_cause = potential_causes[0]
            if best_cause['confidence'] >= 0.6:  # High confidence threshold
                incident.root_cause = best_cause['cause']
                self.logger.info(f"Root cause identified for {incident.incident_id}: {incident.root_cause}")
            else:
                incident.root_cause = f"Suspected: {best_cause['cause']} (confidence: {best_cause['confidence']:.2f})"

    async def _generate_remediation_plan(self, incident: Incident) -> Optional[RemediationPlan]:
        """Generate automated remediation plan"""
        if not incident.root_cause:
            return None

        # Map root causes to remediation actions
        remediation_mapping = {
            'high_cpu_usage': [RemediationAction.SCALE_OUT, RemediationAction.RESTART_SERVICE],
            'memory_leak': [RemediationAction.RESTART_SERVICE, RemediationAction.SCALE_UP],
            'network_issues': [RemediationAction.FAILOVER, RemediationAction.RESTART_SERVICE],
            'storage_full': [RemediationAction.CLEAR_CACHE, RemediationAction.SCALE_UP],
            'service_unavailable': [RemediationAction.RESTART_SERVICE, RemediationAction.FAILOVER]
        }

        root_cause_key = incident.root_cause.split(' ')[0].lower()  # Handle "Suspected: cause" format
        actions = []
        action_details = []

        for cause, cause_actions in remediation_mapping.items():
            if cause in root_cause_key:
                actions = cause_actions[:2]  # Take first 2 actions
                break

        if not actions:
            # Default actions based on severity
            if incident.severity == IncidentSeverity.CRITICAL:
                actions = [RemediationAction.FAILOVER, RemediationAction.RESTART_SERVICE]
            else:
                actions = [RemediationAction.RESTART_SERVICE]

        # Generate action details
        for action in actions:
            detail = {
                'action': action.value,
                'target': incident.source,
                'parameters': self._get_action_parameters(action, incident)
            }
            action_details.append(detail)

        # Calculate success probability
        success_prob = 1.0
        for action in actions:
            action_success_rate = self.remediation_success_rates.get(action, 0.5)
            success_prob *= action_success_rate

        plan = RemediationPlan(
            incident_id=incident.incident_id,
            actions=actions,
            action_details=action_details,
            estimated_recovery_time=timedelta(minutes=5 * len(actions)),
            success_probability=success_prob,
            risk_level="low" if success_prob > 0.8 else "medium",
            rollback_plan=[RemediationAction.ROLLBACK] if len(actions) > 1 else None,
            prerequisites=[f"Verify {incident.source} is accessible"]
        )

        self.logger.info(f"Generated remediation plan for {incident.incident_id}: {[a.value for a in actions]}")
        return plan

    def _get_action_parameters(self, action: RemediationAction, incident: Incident) -> Dict[str, Any]:
        """Get parameters for remediation action"""
        base_params = {
            'target': incident.source,
            'incident_id': incident.incident_id,
            'severity': incident.severity.value
        }

        if action == RemediationAction.SCALE_OUT:
            base_params.update({
                'scale_factor': 2 if incident.severity == IncidentSeverity.CRITICAL else 1,
                'max_instances': 10
            })
        elif action == RemediationAction.SCALE_UP:
            base_params.update({
                'cpu_increase': '50%',
                'memory_increase': '50%'
            })
        elif action == RemediationAction.RESTART_SERVICE:
            base_params.update({
                'graceful_shutdown': True,
                'timeout_seconds': 30
            })

        return base_params

    async def _execute_remediation_plan(self, incident: Incident, plan: RemediationPlan):
        """Execute automated remediation plan"""
        incident.status = IncidentStatus.REMEDIATING
        incident.updated_at = datetime.now()

        self.logger.info(f"Executing remediation plan for incident {incident.incident_id}")

        results = []
        success = True

        for i, action in enumerate(plan.actions):
            try:
                # Get action parameters
                action_detail = plan.action_details[i] if i < len(plan.action_details) else {}

                # Execute action
                start_time = datetime.now()
                handler = self.remediation_handlers.get(action)

                if handler:
                    result = await handler(incident, action_detail)
                    execution_time = datetime.now() - start_time

                    remediation_result = RemediationResult(
                        plan_id=plan.plan_id,
                        action=action,
                        success=result.get('success', False),
                        execution_time=execution_time,
                        output=result.get('output', ''),
                        error=result.get('error')
                    )

                    results.append(remediation_result)
                    self.remediation_history.append(remediation_result)

                    if not remediation_result.success:
                        success = False
                        self.logger.error(f"Remediation action {action.value} failed: {remediation_result.error}")
                        break
                    else:
                        self.logger.info(f"Remediation action {action.value} completed successfully")

                else:
                    self.logger.error(f"No handler found for remediation action {action.value}")
                    success = False
                    break

                # Wait between actions
                if i < len(plan.actions) - 1:
                    await asyncio.sleep(2)

            except Exception as e:
                self.logger.error(f"Error executing remediation action {action.value}: {e}")
                success = False
                break

        # Update incident status
        if success:
            incident.status = IncidentStatus.RESOLVED
            incident.resolved_at = datetime.now()
            self.logger.info(f"Incident {incident.incident_id} resolved automatically")
        else:
            await self._escalate_incident(incident, "Automated remediation failed")

        incident.updated_at = datetime.now()

    async def _escalate_incident(self, incident: Incident, reason: str):
        """Escalate incident for manual intervention"""
        incident.status = IncidentStatus.ESCALATED
        incident.updated_at = datetime.now()

        self.logger.warning(f"Escalating incident {incident.incident_id}: {reason}")

        # Notify escalation handlers
        for handler in self.escalation_handlers:
            try:
                await handler(incident, reason)
            except Exception as e:
                self.logger.error(f"Error in escalation handler: {e}")

    # Remediation action handlers
    async def _restart_service(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Restart service remediation action"""
        target = params.get('target')
        graceful = params.get('graceful_shutdown', True)
        timeout = params.get('timeout_seconds', 30)

        try:
            # Simulate service restart
            self.logger.info(f"Restarting service {target} (graceful={graceful})")
            await asyncio.sleep(2)  # Simulate restart time

            return {
                'success': True,
                'output': f"Service {target} restarted successfully"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _scale_out(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Scale out remediation action"""
        target = params.get('target')
        scale_factor = params.get('scale_factor', 1)

        try:
            self.logger.info(f"Scaling out {target} by factor {scale_factor}")
            await asyncio.sleep(3)  # Simulate scaling time

            return {
                'success': True,
                'output': f"Scaled out {target} by {scale_factor} instances"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _scale_up(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Scale up remediation action"""
        target = params.get('target')
        cpu_increase = params.get('cpu_increase', '50%')
        memory_increase = params.get('memory_increase', '50%')

        try:
            self.logger.info(f"Scaling up {target} (CPU: +{cpu_increase}, Memory: +{memory_increase})")
            await asyncio.sleep(2)  # Simulate scaling time

            return {
                'success': True,
                'output': f"Scaled up {target} resources"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _failover(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Failover remediation action"""
        target = params.get('target')

        try:
            self.logger.info(f"Performing failover for {target}")
            await asyncio.sleep(5)  # Simulate failover time

            return {
                'success': True,
                'output': f"Failover completed for {target}"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _rollback(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback remediation action"""
        target = params.get('target')

        try:
            self.logger.info(f"Performing rollback for {target}")
            await asyncio.sleep(3)  # Simulate rollback time

            return {
                'success': True,
                'output': f"Rollback completed for {target}"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _clear_cache(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Clear cache remediation action"""
        target = params.get('target')

        try:
            self.logger.info(f"Clearing cache for {target}")
            await asyncio.sleep(1)  # Simulate cache clear time

            return {
                'success': True,
                'output': f"Cache cleared for {target}"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _restart_container(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Restart container remediation action"""
        target = params.get('target')

        try:
            self.logger.info(f"Restarting container {target}")
            await asyncio.sleep(2)  # Simulate container restart time

            return {
                'success': True,
                'output': f"Container {target} restarted successfully"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _drain_node(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Drain node remediation action"""
        target = params.get('target')

        try:
            self.logger.info(f"Draining node {target}")
            await asyncio.sleep(10)  # Simulate node drain time

            return {
                'success': True,
                'output': f"Node {target} drained successfully"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _replace_node(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Replace node remediation action"""
        target = params.get('target')

        try:
            self.logger.info(f"Replacing node {target}")
            await asyncio.sleep(15)  # Simulate node replacement time

            return {
                'success': True,
                'output': f"Node {target} replaced successfully"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _update_config(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Update configuration remediation action"""
        target = params.get('target')

        try:
            self.logger.info(f"Updating configuration for {target}")
            await asyncio.sleep(2)  # Simulate config update time

            return {
                'success': True,
                'output': f"Configuration updated for {target}"
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _manual_intervention(self, incident: Incident, params: Dict[str, Any]) -> Dict[str, Any]:
        """Manual intervention remediation action"""
        return {
            'success': False,
            'error': 'Manual intervention required'
        }

    def get_incidents(self, status: Optional[IncidentStatus] = None) -> List[Incident]:
        """Get incidents, optionally filtered by status"""
        if status:
            return [i for i in self.incidents.values() if i.status == status]
        return list(self.incidents.values())

    def get_system_health_summary(self) -> Dict[str, Any]:
        """Get overall system health summary"""
        if not self.health_metrics:
            return {"status": "unknown", "message": "No metrics available"}

        recent_metrics = list(self.health_metrics)[-100:]  # Last 100 metrics

        # Count active incidents by severity
        incident_counts = defaultdict(int)
        for incident in self.incidents.values():
            if incident.status not in [IncidentStatus.RESOLVED]:
                incident_counts[incident.severity.value] += 1

        # Calculate health score
        health_score = 100
        health_score -= incident_counts['critical'] * 30
        health_score -= incident_counts['high'] * 20
        health_score -= incident_counts['medium'] * 10
        health_score -= incident_counts['low'] * 5
        health_score = max(0, health_score)

        # Determine overall status
        if incident_counts['critical'] > 0:
            status = "critical"
        elif incident_counts['high'] > 0:
            status = "degraded"
        elif incident_counts['medium'] > 0:
            status = "warning"
        else:
            status = "healthy"

        return {
            'status': status,
            'health_score': health_score,
            'active_incidents': dict(incident_counts),
            'total_incidents': len(self.incidents),
            'resolved_incidents': len([i for i in self.incidents.values() if i.status == IncidentStatus.RESOLVED]),
            'metrics_collected': len(self.health_metrics),
            'last_metric_time': recent_metrics[-1].timestamp.isoformat() if recent_metrics else None,
            'self_healing_enabled': self.enabled and self.auto_remediation,
            'last_updated': datetime.now().isoformat()
        }

# Example usage
if __name__ == "__main__":
    async def test_self_healing():
        system = SelfHealingSystem()

        # Simulate health metrics
        for i in range(10):
            # Normal metrics
            metric = HealthMetric(
                timestamp=datetime.now(),
                source="web-service-1",
                metric_type=HealthMetricType.CPU_USAGE,
                value=60 + i * 2,  # Gradually increasing
                unit="percent",
                threshold_warning=80,
                threshold_critical=90
            )
            await system.add_health_metric(metric)
            await asyncio.sleep(0.1)

        # Critical metric to trigger incident
        critical_metric = HealthMetric(
            timestamp=datetime.now(),
            source="web-service-1",
            metric_type=HealthMetricType.CPU_USAGE,
            value=95,  # Critical level
            unit="percent",
            threshold_warning=80,
            threshold_critical=90
        )
        await system.add_health_metric(critical_metric)

        # Wait for processing
        await asyncio.sleep(2)

        # Check system health
        health_summary = system.get_system_health_summary()
        print(f"System Health: {json.dumps(health_summary, indent=2)}")

        # List incidents
        incidents = system.get_incidents()
        print(f"\nIncidents ({len(incidents)}):")
        for incident in incidents:
            print(f"- {incident.incident_id}: {incident.title} ({incident.status.value})")

    asyncio.run(test_self_healing())