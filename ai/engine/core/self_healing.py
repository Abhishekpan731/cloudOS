#!/usr/bin/env python3
"""
CloudOS Self-Healing System
Automated problem detection, diagnosis, and remediation
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

from .ai_engine import CloudOSAIEngine, AIRequest, AITaskType

class IssueType(Enum):
    HIGH_CPU = "high_cpu"
    HIGH_MEMORY = "high_memory"
    DISK_FULL = "disk_full"
    NETWORK_ISSUES = "network_issues"
    APPLICATION_ERRORS = "application_errors"
    NODE_FAILURE = "node_failure"
    SERVICE_UNAVAILABLE = "service_unavailable"
    PERFORMANCE_DEGRADATION = "performance_degradation"

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ActionType(Enum):
    RESTART_SERVICE = "restart_service"
    SCALE_OUT = "scale_out"
    MIGRATE_WORKLOAD = "migrate_workload"
    CLEAR_DISK_SPACE = "clear_disk_space"
    RESET_NETWORK = "reset_network"
    ROLLBACK_DEPLOYMENT = "rollback_deployment"
    ALERT_OPERATOR = "alert_operator"
    QUARANTINE_NODE = "quarantine_node"

@dataclass
class Issue:
    id: str
    type: IssueType
    severity: Severity
    description: str
    affected_nodes: List[str]
    affected_services: List[str]
    detected_at: datetime
    symptoms: Dict[str, Any]
    root_cause: Optional[str] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None

@dataclass
class RemediationAction:
    id: str
    issue_id: str
    action_type: ActionType
    description: str
    target: str  # node, service, etc.
    parameters: Dict[str, Any]
    estimated_impact: str
    success_probability: float
    rollback_plan: Optional[str] = None

@dataclass
class RemediationResult:
    action_id: str
    success: bool
    executed_at: datetime
    execution_time: float
    output: str
    side_effects: List[str] = field(default_factory=list)

class SelfHealingSystem:
    """
    AI-powered self-healing system for CloudOS
    """

    def __init__(self, ai_engine: CloudOSAIEngine, resource_manager=None, config: Dict[str, Any] = None):
        self.ai_engine = ai_engine
        self.resource_manager = resource_manager
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Issue tracking
        self.active_issues: Dict[str, Issue] = {}
        self.resolved_issues: List[Issue] = []
        self.remediation_history: List[RemediationResult] = []

        # Detection thresholds
        self.thresholds = {
            IssueType.HIGH_CPU: 85.0,
            IssueType.HIGH_MEMORY: 90.0,
            IssueType.DISK_FULL: 95.0,
        }

        # Auto-remediation settings
        self.auto_remediation_enabled = self.config.get('auto_remediation', True)
        self.max_concurrent_actions = self.config.get('max_concurrent_actions', 3)
        self.safety_mode = self.config.get('safety_mode', True)  # Requires approval for critical actions

        # Pattern learning
        self.issue_patterns = {}
        self.remediation_effectiveness = {}

        # Background tasks
        self.monitoring_task = None
        self.running = False

        self.logger.info("Self-Healing System initialized")

    async def start(self):
        """Start the self-healing system"""
        self.running = True
        self.logger.info("Starting Self-Healing System...")

        # Start monitoring loop
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())

        self.logger.info("Self-Healing System started")

    async def stop(self):
        """Stop the self-healing system"""
        self.running = False
        self.logger.info("Stopping Self-Healing System...")

        if self.monitoring_task:
            self.monitoring_task.cancel()

        self.logger.info("Self-Healing System stopped")

    async def detect_issues(self, system_metrics: Dict[str, Any]) -> List[Issue]:
        """Detect system issues from metrics"""
        issues = []
        current_time = datetime.now()

        for node_id, metrics in system_metrics.items():
            node_issues = []

            # CPU threshold check
            cpu_usage = metrics.get('cpu_usage', 0)
            if cpu_usage > self.thresholds[IssueType.HIGH_CPU]:
                node_issues.append(Issue(
                    id=f"cpu_{node_id}_{int(current_time.timestamp())}",
                    type=IssueType.HIGH_CPU,
                    severity=Severity.HIGH if cpu_usage > 95 else Severity.MEDIUM,
                    description=f"High CPU usage on {node_id}: {cpu_usage:.1f}%",
                    affected_nodes=[node_id],
                    affected_services=metrics.get('services', []),
                    detected_at=current_time,
                    symptoms={'cpu_usage': cpu_usage}
                ))

            # Memory threshold check
            memory_usage = metrics.get('memory_usage', 0)
            if memory_usage > self.thresholds[IssueType.HIGH_MEMORY]:
                node_issues.append(Issue(
                    id=f"memory_{node_id}_{int(current_time.timestamp())}",
                    type=IssueType.HIGH_MEMORY,
                    severity=Severity.CRITICAL if memory_usage > 95 else Severity.HIGH,
                    description=f"High memory usage on {node_id}: {memory_usage:.1f}%",
                    affected_nodes=[node_id],
                    affected_services=metrics.get('services', []),
                    detected_at=current_time,
                    symptoms={'memory_usage': memory_usage}
                ))

            # Disk space check
            disk_usage = metrics.get('disk_usage', 0)
            if disk_usage > self.thresholds[IssueType.DISK_FULL]:
                node_issues.append(Issue(
                    id=f"disk_{node_id}_{int(current_time.timestamp())}",
                    type=IssueType.DISK_FULL,
                    severity=Severity.CRITICAL,
                    description=f"Low disk space on {node_id}: {disk_usage:.1f}% used",
                    affected_nodes=[node_id],
                    affected_services=metrics.get('services', []),
                    detected_at=current_time,
                    symptoms={'disk_usage': disk_usage}
                ))

            # Network issues
            network_errors = metrics.get('network_errors', 0)
            if network_errors > 100:  # errors per minute
                node_issues.append(Issue(
                    id=f"network_{node_id}_{int(current_time.timestamp())}",
                    type=IssueType.NETWORK_ISSUES,
                    severity=Severity.HIGH,
                    description=f"High network error rate on {node_id}: {network_errors} errors/min",
                    affected_nodes=[node_id],
                    affected_services=metrics.get('services', []),
                    detected_at=current_time,
                    symptoms={'network_errors': network_errors}
                ))

            issues.extend(node_issues)

        # Store new issues
        for issue in issues:
            if issue.id not in self.active_issues:
                self.active_issues[issue.id] = issue
                self.logger.warning(f"New issue detected: {issue.description}")

        return issues

    async def diagnose_issue(self, issue: Issue) -> Issue:
        """Diagnose the root cause of an issue using AI"""
        self.logger.info(f"Diagnosing issue: {issue.id}")

        try:
            # Prepare diagnostic data
            diagnostic_data = {
                'issue_type': issue.type.value,
                'symptoms': issue.symptoms,
                'affected_nodes': issue.affected_nodes,
                'affected_services': issue.affected_services,
                'detection_time': issue.detected_at.isoformat()
            }

            # Request AI diagnosis
            request = AIRequest(
                task_id=f"diagnose_{issue.id}",
                task_type=AITaskType.ANOMALY_DETECTION,
                data=diagnostic_data
            )

            # For immediate response, use rule-based diagnosis
            # In production, would wait for AI response
            root_cause = await self._rule_based_diagnosis(issue)
            issue.root_cause = root_cause

            self.logger.info(f"Issue {issue.id} diagnosed: {root_cause}")

        except Exception as e:
            self.logger.error(f"Error diagnosing issue {issue.id}: {e}")
            issue.root_cause = "Unable to determine root cause"

        return issue

    async def plan_remediation(self, issue: Issue) -> List[RemediationAction]:
        """Plan remediation actions for an issue"""
        actions = []

        if issue.type == IssueType.HIGH_CPU:
            actions.extend(await self._plan_cpu_remediation(issue))
        elif issue.type == IssueType.HIGH_MEMORY:
            actions.extend(await self._plan_memory_remediation(issue))
        elif issue.type == IssueType.DISK_FULL:
            actions.extend(await self._plan_disk_remediation(issue))
        elif issue.type == IssueType.NETWORK_ISSUES:
            actions.extend(await self._plan_network_remediation(issue))

        # Sort by success probability
        actions.sort(key=lambda x: x.success_probability, reverse=True)

        self.logger.info(f"Planned {len(actions)} remediation actions for issue {issue.id}")
        return actions

    async def execute_remediation(self, action: RemediationAction) -> RemediationResult:
        """Execute a remediation action"""
        start_time = datetime.now()
        self.logger.info(f"Executing remediation action: {action.description}")

        try:
            success = False
            output = ""
            side_effects = []

            # Execute based on action type
            if action.action_type == ActionType.RESTART_SERVICE:
                success, output = await self._restart_service(action.target, action.parameters)
            elif action.action_type == ActionType.SCALE_OUT:
                success, output = await self._scale_out(action.target, action.parameters)
            elif action.action_type == ActionType.MIGRATE_WORKLOAD:
                success, output = await self._migrate_workload(action.target, action.parameters)
            elif action.action_type == ActionType.CLEAR_DISK_SPACE:
                success, output = await self._clear_disk_space(action.target, action.parameters)
            elif action.action_type == ActionType.RESET_NETWORK:
                success, output = await self._reset_network(action.target, action.parameters)
            elif action.action_type == ActionType.QUARANTINE_NODE:
                success, output = await self._quarantine_node(action.target, action.parameters)
            else:
                output = f"Action type {action.action_type.value} not implemented"

            execution_time = (datetime.now() - start_time).total_seconds()

            result = RemediationResult(
                action_id=action.id,
                success=success,
                executed_at=start_time,
                execution_time=execution_time,
                output=output,
                side_effects=side_effects
            )

            # Store result
            self.remediation_history.append(result)

            if success:
                self.logger.info(f"Remediation action {action.id} completed successfully")
            else:
                self.logger.error(f"Remediation action {action.id} failed: {output}")

            return result

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Error executing remediation {action.id}: {e}")

            return RemediationResult(
                action_id=action.id,
                success=False,
                executed_at=start_time,
                execution_time=execution_time,
                output=str(e)
            )

    async def heal_system(self, system_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Main healing workflow"""
        healing_summary = {
            'issues_detected': 0,
            'issues_diagnosed': 0,
            'actions_planned': 0,
            'actions_executed': 0,
            'successful_remediations': 0,
            'timestamp': datetime.now().isoformat()
        }

        try:
            # 1. Detect issues
            new_issues = await self.detect_issues(system_metrics)
            healing_summary['issues_detected'] = len(new_issues)

            # 2. Diagnose issues
            for issue in new_issues:
                await self.diagnose_issue(issue)
                healing_summary['issues_diagnosed'] += 1

            # 3. Plan and execute remediation for high-priority issues
            for issue in new_issues:
                if issue.severity in [Severity.HIGH, Severity.CRITICAL]:
                    actions = await self.plan_remediation(issue)
                    healing_summary['actions_planned'] += len(actions)

                    if self.auto_remediation_enabled:
                        # Execute the best action(s)
                        for action in actions[:2]:  # Execute top 2 actions
                            # Safety check for critical actions
                            if (action.action_type in [ActionType.QUARANTINE_NODE, ActionType.ROLLBACK_DEPLOYMENT] and
                                self.safety_mode):
                                self.logger.warning(f"Skipping critical action {action.id} - safety mode enabled")
                                continue

                            result = await self.execute_remediation(action)
                            healing_summary['actions_executed'] += 1

                            if result.success:
                                healing_summary['successful_remediations'] += 1
                                # Mark issue as resolved if remediation was successful
                                issue.resolved = True
                                issue.resolved_at = datetime.now()

            # 4. Clean up resolved issues
            self._cleanup_resolved_issues()

        except Exception as e:
            self.logger.error(f"Error in healing workflow: {e}")
            healing_summary['error'] = str(e)

        return healing_summary

    async def _rule_based_diagnosis(self, issue: Issue) -> str:
        """Simple rule-based diagnosis as fallback"""
        if issue.type == IssueType.HIGH_CPU:
            cpu_usage = issue.symptoms.get('cpu_usage', 0)
            if cpu_usage > 95:
                return "Critical CPU saturation - likely resource starvation or runaway process"
            elif cpu_usage > 85:
                return "High CPU load - insufficient capacity or inefficient workload"

        elif issue.type == IssueType.HIGH_MEMORY:
            memory_usage = issue.symptoms.get('memory_usage', 0)
            if memory_usage > 95:
                return "Memory exhaustion - risk of OOM killer activation"
            else:
                return "High memory pressure - consider memory optimization or scaling"

        elif issue.type == IssueType.DISK_FULL:
            return "Disk space critically low - immediate cleanup or expansion needed"

        elif issue.type == IssueType.NETWORK_ISSUES:
            return "High network error rate - connectivity or configuration issue"

        return "Root cause analysis in progress"

    async def _plan_cpu_remediation(self, issue: Issue) -> List[RemediationAction]:
        """Plan remediation for high CPU issues"""
        actions = []
        node_id = issue.affected_nodes[0] if issue.affected_nodes else "unknown"

        # Scale out action
        actions.append(RemediationAction(
            id=f"scale_out_{issue.id}",
            issue_id=issue.id,
            action_type=ActionType.SCALE_OUT,
            description=f"Scale out to reduce CPU load on {node_id}",
            target=node_id,
            parameters={'additional_instances': 2},
            estimated_impact="Reduce CPU load by distributing workload",
            success_probability=0.8,
            rollback_plan="Scale back if CPU doesn't improve within 10 minutes"
        ))

        # Migrate workload action
        if len(issue.affected_services) > 0:
            actions.append(RemediationAction(
                id=f"migrate_{issue.id}",
                issue_id=issue.id,
                action_type=ActionType.MIGRATE_WORKLOAD,
                description=f"Migrate high-CPU services from {node_id}",
                target=issue.affected_services[0],
                parameters={'source_node': node_id},
                estimated_impact="Move resource-intensive workload to less loaded node",
                success_probability=0.7
            ))

        return actions

    async def _plan_memory_remediation(self, issue: Issue) -> List[RemediationAction]:
        """Plan remediation for high memory issues"""
        actions = []
        node_id = issue.affected_nodes[0] if issue.affected_nodes else "unknown"

        # Restart services to clear memory leaks
        if issue.affected_services:
            actions.append(RemediationAction(
                id=f"restart_{issue.id}",
                issue_id=issue.id,
                action_type=ActionType.RESTART_SERVICE,
                description=f"Restart services on {node_id} to clear memory",
                target=issue.affected_services[0],
                parameters={'graceful': True},
                estimated_impact="Clear potential memory leaks",
                success_probability=0.6
            ))

        # Scale out for more memory capacity
        actions.append(RemediationAction(
            id=f"scale_memory_{issue.id}",
            issue_id=issue.id,
            action_type=ActionType.SCALE_OUT,
            description=f"Add memory capacity by scaling out",
            target=node_id,
            parameters={'memory_optimized': True},
            estimated_impact="Increase available memory capacity",
            success_probability=0.8
        ))

        return actions

    async def _plan_disk_remediation(self, issue: Issue) -> List[RemediationAction]:
        """Plan remediation for disk space issues"""
        actions = []
        node_id = issue.affected_nodes[0] if issue.affected_nodes else "unknown"

        # Clear disk space
        actions.append(RemediationAction(
            id=f"cleanup_{issue.id}",
            issue_id=issue.id,
            action_type=ActionType.CLEAR_DISK_SPACE,
            description=f"Clean up temporary files and logs on {node_id}",
            target=node_id,
            parameters={'cleanup_logs': True, 'cleanup_temp': True},
            estimated_impact="Free up disk space immediately",
            success_probability=0.9
        ))

        return actions

    async def _plan_network_remediation(self, issue: Issue) -> List[RemediationAction]:
        """Plan remediation for network issues"""
        actions = []
        node_id = issue.affected_nodes[0] if issue.affected_nodes else "unknown"

        # Reset network interfaces
        actions.append(RemediationAction(
            id=f"reset_net_{issue.id}",
            issue_id=issue.id,
            action_type=ActionType.RESET_NETWORK,
            description=f"Reset network interfaces on {node_id}",
            target=node_id,
            parameters={'reset_interfaces': True},
            estimated_impact="Resolve network connectivity issues",
            success_probability=0.7
        ))

        return actions

    # Remediation execution methods (simplified implementations)

    async def _restart_service(self, service: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """Restart a service"""
        # In real implementation, this would call service management APIs
        await asyncio.sleep(2)  # Simulate restart time
        return True, f"Service {service} restarted successfully"

    async def _scale_out(self, target: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """Scale out resources"""
        additional = params.get('additional_instances', 1)
        await asyncio.sleep(5)  # Simulate scaling time
        return True, f"Scaled out {additional} additional instances for {target}"

    async def _migrate_workload(self, workload: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """Migrate workload to another node"""
        source = params.get('source_node', 'unknown')
        await asyncio.sleep(10)  # Simulate migration time
        return True, f"Migrated {workload} from {source} to available node"

    async def _clear_disk_space(self, node: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """Clear disk space on a node"""
        await asyncio.sleep(3)  # Simulate cleanup time
        freed_gb = 5  # Simulate freed space
        return True, f"Cleaned up {freed_gb}GB of disk space on {node}"

    async def _reset_network(self, node: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """Reset network interfaces"""
        await asyncio.sleep(5)  # Simulate network reset
        return True, f"Reset network interfaces on {node}"

    async def _quarantine_node(self, node: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """Quarantine a problematic node"""
        await asyncio.sleep(2)  # Simulate quarantine process
        return True, f"Node {node} quarantined - no new workloads will be scheduled"

    def _cleanup_resolved_issues(self):
        """Clean up old resolved issues"""
        resolved_count = 0
        for issue_id, issue in list(self.active_issues.items()):
            if issue.resolved:
                self.resolved_issues.append(issue)
                del self.active_issues[issue_id]
                resolved_count += 1

        # Keep only recent resolved issues
        if len(self.resolved_issues) > 1000:
            self.resolved_issues = self.resolved_issues[-1000:]

        if resolved_count > 0:
            self.logger.info(f"Cleaned up {resolved_count} resolved issues")

    async def _monitoring_loop(self):
        """Background monitoring and healing loop"""
        while self.running:
            try:
                # In a real implementation, this would get metrics from the resource manager
                if self.resource_manager:
                    # For now, simulate some metrics
                    sample_metrics = {
                        'node1': {
                            'cpu_usage': 45.0,
                            'memory_usage': 60.0,
                            'disk_usage': 75.0,
                            'network_errors': 10
                        }
                    }

                    healing_result = await self.heal_system(sample_metrics)
                    if healing_result['issues_detected'] > 0:
                        self.logger.info(f"Healing cycle completed: {healing_result}")

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(30)

    def get_system_health_report(self) -> Dict[str, Any]:
        """Generate comprehensive system health report"""
        return {
            'active_issues': len(self.active_issues),
            'resolved_issues_today': len([i for i in self.resolved_issues
                                        if i.resolved_at and
                                        i.resolved_at.date() == datetime.now().date()]),
            'remediation_success_rate': (
                sum(1 for r in self.remediation_history if r.success) /
                max(len(self.remediation_history), 1) * 100
            ),
            'current_issues': [
                {
                    'id': issue.id,
                    'type': issue.type.value,
                    'severity': issue.severity.value,
                    'description': issue.description,
                    'age_minutes': (datetime.now() - issue.detected_at).total_seconds() / 60
                }
                for issue in self.active_issues.values()
            ],
            'auto_remediation_enabled': self.auto_remediation_enabled,
            'safety_mode': self.safety_mode,
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Example usage
    import asyncio
    from .ai_engine import CloudOSAIEngine

    async def test_self_healing():
        ai_engine = CloudOSAIEngine()
        await ai_engine.start()

        healing_system = SelfHealingSystem(ai_engine)
        await healing_system.start()

        # Simulate problematic metrics
        test_metrics = {
            'node1': {
                'cpu_usage': 90.0,  # High CPU
                'memory_usage': 95.0,  # High Memory
                'disk_usage': 85.0,
                'network_errors': 150,  # High error rate
                'services': ['web-service', 'database']
            },
            'node2': {
                'cpu_usage': 30.0,
                'memory_usage': 40.0,
                'disk_usage': 98.0,  # Disk full
                'network_errors': 5,
                'services': ['api-service']
            }
        }

        # Run healing process
        result = await healing_system.heal_system(test_metrics)
        print(f"Healing result: {json.dumps(result, indent=2)}")

        # Get health report
        report = healing_system.get_system_health_report()
        print(f"Health report: {json.dumps(report, indent=2)}")

        await healing_system.stop()
        await ai_engine.stop()

    # Run test
    asyncio.run(test_self_healing())