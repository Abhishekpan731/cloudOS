#!/usr/bin/env python3
"""
CloudOS Intelligent Resource Management System
AI-powered resource allocation, optimization, and scaling
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import threading

from .ai_engine import CloudOSAIEngine, AIRequest, AITaskType

class ResourceType(Enum):
    CPU = "cpu"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    GPU = "gpu"

class AllocationStrategy(Enum):
    BALANCED = "balanced"
    CPU_OPTIMIZED = "cpu_optimized"
    MEMORY_OPTIMIZED = "memory_optimized"
    COST_OPTIMIZED = "cost_optimized"
    PERFORMANCE_OPTIMIZED = "performance_optimized"

class NodeHealth(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNAVAILABLE = "unavailable"

@dataclass
class ResourceMetrics:
    node_id: str
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    storage_usage: float
    network_io: float
    gpu_usage: float = 0.0
    temperature: float = 0.0
    power_consumption: float = 0.0

@dataclass
class NodeSpec:
    node_id: str
    cpu_cores: int
    memory_gb: int
    storage_gb: int
    network_bandwidth_mbps: int
    gpu_count: int = 0
    instance_type: str = ""
    cloud_provider: str = ""
    region: str = ""
    availability_zone: str = ""

@dataclass
class WorkloadRequirement:
    workload_id: str
    cpu_request: float
    memory_request: float
    storage_request: float
    network_request: float = 0.0
    gpu_request: int = 0
    priority: int = 1
    affinity_rules: List[str] = field(default_factory=list)
    anti_affinity_rules: List[str] = field(default_factory=list)
    required_labels: Dict[str, str] = field(default_factory=dict)

@dataclass
class AllocationDecision:
    workload_id: str
    target_node_id: str
    allocated_resources: Dict[str, float]
    confidence: float
    reason: str
    alternatives: List[str] = field(default_factory=list)

class IntelligentResourceManager:
    """
    AI-powered resource management system for CloudOS
    """

    def __init__(self, ai_engine: CloudOSAIEngine, config: Dict[str, Any] = None):
        self.ai_engine = ai_engine
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Resource tracking
        self.nodes: Dict[str, NodeSpec] = {}
        self.node_metrics: Dict[str, List[ResourceMetrics]] = {}
        self.node_health: Dict[str, NodeHealth] = {}

        # Workload tracking
        self.pending_workloads: List[WorkloadRequirement] = []
        self.active_allocations: Dict[str, AllocationDecision] = {}

        # Resource pools and strategies
        self.allocation_strategy = AllocationStrategy.BALANCED
        self.resource_pools: Dict[str, Set[str]] = {}  # pool_name -> node_ids

        # Optimization settings
        self.enable_predictive_scaling = self.config.get('predictive_scaling', True)
        self.enable_load_balancing = self.config.get('load_balancing', True)
        self.enable_cost_optimization = self.config.get('cost_optimization', True)

        # Monitoring and alerts
        self.resource_thresholds = {
            ResourceType.CPU: {'warning': 70.0, 'critical': 85.0},
            ResourceType.MEMORY: {'warning': 75.0, 'critical': 90.0},
            ResourceType.STORAGE: {'warning': 80.0, 'critical': 95.0}
        }

        # Background tasks
        self.monitoring_task = None
        self.optimization_task = None
        self.running = False

        self.logger.info("Intelligent Resource Manager initialized")

    async def start(self):
        """Start the resource management system"""
        self.running = True
        self.logger.info("Starting Intelligent Resource Manager...")

        # Start background monitoring
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())

        # Start optimization loop
        self.optimization_task = asyncio.create_task(self._optimization_loop())

        self.logger.info("Resource Manager started")

    async def stop(self):
        """Stop the resource management system"""
        self.running = False
        self.logger.info("Stopping Intelligent Resource Manager...")

        # Cancel background tasks
        if self.monitoring_task:
            self.monitoring_task.cancel()
        if self.optimization_task:
            self.optimization_task.cancel()

        self.logger.info("Resource Manager stopped")

    async def register_node(self, node_spec: NodeSpec):
        """Register a new node in the cluster"""
        self.nodes[node_spec.node_id] = node_spec
        self.node_metrics[node_spec.node_id] = []
        self.node_health[node_spec.node_id] = NodeHealth.HEALTHY

        self.logger.info(f"Registered node {node_spec.node_id} ({node_spec.instance_type})")

    async def unregister_node(self, node_id: str):
        """Unregister a node from the cluster"""
        if node_id in self.nodes:
            # Migrate workloads if any
            await self._migrate_workloads_from_node(node_id)

            # Remove node data
            del self.nodes[node_id]
            del self.node_metrics[node_id]
            del self.node_health[node_id]

            self.logger.info(f"Unregistered node {node_id}")

    async def update_node_metrics(self, metrics: ResourceMetrics):
        """Update resource metrics for a node"""
        node_id = metrics.node_id

        if node_id not in self.nodes:
            self.logger.warning(f"Received metrics for unknown node {node_id}")
            return

        # Store metrics (keep last 100 data points)
        if node_id not in self.node_metrics:
            self.node_metrics[node_id] = []

        self.node_metrics[node_id].append(metrics)
        if len(self.node_metrics[node_id]) > 100:
            self.node_metrics[node_id] = self.node_metrics[node_id][-100:]

        # Update node health
        await self._update_node_health(node_id, metrics)

    async def request_allocation(self, workload: WorkloadRequirement) -> Optional[AllocationDecision]:
        """Request resource allocation for a workload"""
        self.logger.info(f"Processing allocation request for workload {workload.workload_id}")

        # Find suitable nodes
        candidate_nodes = await self._find_candidate_nodes(workload)

        if not candidate_nodes:
            self.logger.warning(f"No suitable nodes found for workload {workload.workload_id}")
            self.pending_workloads.append(workload)
            return None

        # Use AI to make optimal allocation decision
        allocation_decision = await self._ai_allocation_decision(workload, candidate_nodes)

        if allocation_decision:
            # Record the allocation
            self.active_allocations[workload.workload_id] = allocation_decision
            self.logger.info(f"Allocated workload {workload.workload_id} to node {allocation_decision.target_node_id}")

        return allocation_decision

    async def release_allocation(self, workload_id: str):
        """Release resources allocated to a workload"""
        if workload_id in self.active_allocations:
            allocation = self.active_allocations[workload_id]
            del self.active_allocations[workload_id]

            self.logger.info(f"Released allocation for workload {workload_id} from node {allocation.target_node_id}")

    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get comprehensive cluster status"""
        total_nodes = len(self.nodes)
        healthy_nodes = sum(1 for health in self.node_health.values() if health == NodeHealth.HEALTHY)

        # Calculate resource utilization
        total_cpu_capacity = sum(node.cpu_cores for node in self.nodes.values())
        total_memory_capacity = sum(node.memory_gb for node in self.nodes.values())

        # Get current utilization
        current_cpu_usage = 0
        current_memory_usage = 0

        for node_id, metrics_list in self.node_metrics.items():
            if metrics_list:
                latest_metrics = metrics_list[-1]
                node_spec = self.nodes[node_id]
                current_cpu_usage += (latest_metrics.cpu_usage / 100) * node_spec.cpu_cores
                current_memory_usage += (latest_metrics.memory_usage / 100) * node_spec.memory_gb

        return {
            'cluster_health': {
                'total_nodes': total_nodes,
                'healthy_nodes': healthy_nodes,
                'warning_nodes': sum(1 for h in self.node_health.values() if h == NodeHealth.WARNING),
                'critical_nodes': sum(1 for h in self.node_health.values() if h == NodeHealth.CRITICAL)
            },
            'resource_utilization': {
                'cpu': {
                    'used': current_cpu_usage,
                    'total': total_cpu_capacity,
                    'utilization_percent': (current_cpu_usage / max(total_cpu_capacity, 1)) * 100
                },
                'memory': {
                    'used': current_memory_usage,
                    'total': total_memory_capacity,
                    'utilization_percent': (current_memory_usage / max(total_memory_capacity, 1)) * 100
                }
            },
            'workloads': {
                'active_allocations': len(self.active_allocations),
                'pending_workloads': len(self.pending_workloads)
            },
            'optimization': {
                'strategy': self.allocation_strategy.value,
                'predictive_scaling': self.enable_predictive_scaling,
                'cost_optimization': self.enable_cost_optimization
            },
            'timestamp': datetime.now().isoformat()
        }

    async def optimize_cluster(self) -> Dict[str, Any]:
        """Run cluster optimization using AI"""
        self.logger.info("Running cluster optimization...")

        # Collect current state data
        cluster_state = {
            'nodes': {node_id: {
                'spec': {
                    'cpu_cores': spec.cpu_cores,
                    'memory_gb': spec.memory_gb,
                    'instance_type': spec.instance_type,
                    'cloud_provider': spec.cloud_provider
                },
                'metrics': self.node_metrics[node_id][-10:] if self.node_metrics[node_id] else [],
                'health': self.node_health[node_id].value
            } for node_id, spec in self.nodes.items()},
            'workloads': self.active_allocations,
            'strategy': self.allocation_strategy.value
        }

        # Request AI optimization
        request = AIRequest(
            task_id=f"cluster_opt_{int(time.time())}",
            task_type=AITaskType.RESOURCE_OPTIMIZATION,
            data={'cluster_state': cluster_state}
        )

        task_id = await self.ai_engine.submit_task(request)

        # For now, return immediate recommendations
        # In a full implementation, you'd wait for the AI response
        return {
            'optimization_started': True,
            'task_id': task_id,
            'estimated_completion': '2-5 minutes',
            'timestamp': datetime.now().isoformat()
        }

    async def _find_candidate_nodes(self, workload: WorkloadRequirement) -> List[str]:
        """Find nodes that can potentially host the workload"""
        candidates = []

        for node_id, node_spec in self.nodes.items():
            # Check if node is healthy
            if self.node_health[node_id] not in [NodeHealth.HEALTHY, NodeHealth.WARNING]:
                continue

            # Check basic resource requirements
            if (node_spec.cpu_cores >= workload.cpu_request and
                node_spec.memory_gb >= workload.memory_request and
                node_spec.storage_gb >= workload.storage_request):

                # Check current utilization
                if self._has_available_resources(node_id, workload):
                    candidates.append(node_id)

        return candidates

    def _has_available_resources(self, node_id: str, workload: WorkloadRequirement) -> bool:
        """Check if node has enough available resources"""
        if node_id not in self.node_metrics or not self.node_metrics[node_id]:
            return True  # Assume available if no metrics

        latest_metrics = self.node_metrics[node_id][-1]
        node_spec = self.nodes[node_id]

        # Calculate available resources
        available_cpu = (100 - latest_metrics.cpu_usage) * node_spec.cpu_cores / 100
        available_memory = (100 - latest_metrics.memory_usage) * node_spec.memory_gb / 100

        return (available_cpu >= workload.cpu_request and
                available_memory >= workload.memory_request)

    async def _ai_allocation_decision(self, workload: WorkloadRequirement,
                                   candidates: List[str]) -> Optional[AllocationDecision]:
        """Use AI to make the best allocation decision"""
        # Prepare data for AI
        node_data = {}
        for node_id in candidates:
            node_spec = self.nodes[node_id]
            recent_metrics = self.node_metrics[node_id][-5:] if self.node_metrics[node_id] else []

            node_data[node_id] = {
                'spec': {
                    'cpu_cores': node_spec.cpu_cores,
                    'memory_gb': node_spec.memory_gb,
                    'instance_type': node_spec.instance_type,
                    'cloud_provider': node_spec.cloud_provider
                },
                'recent_metrics': [
                    {
                        'cpu_usage': m.cpu_usage,
                        'memory_usage': m.memory_usage,
                        'timestamp': m.timestamp.isoformat()
                    } for m in recent_metrics
                ],
                'health': self.node_health[node_id].value
            }

        # For now, use simple best-fit algorithm
        # In production, this would query the AI engine
        best_node = self._simple_allocation_algorithm(workload, candidates)

        if best_node:
            return AllocationDecision(
                workload_id=workload.workload_id,
                target_node_id=best_node,
                allocated_resources={
                    'cpu': workload.cpu_request,
                    'memory': workload.memory_request,
                    'storage': workload.storage_request
                },
                confidence=0.8,
                reason="Best-fit allocation based on current utilization",
                alternatives=candidates[1:3] if len(candidates) > 1 else []
            )

        return None

    def _simple_allocation_algorithm(self, workload: WorkloadRequirement,
                                   candidates: List[str]) -> Optional[str]:
        """Simple allocation algorithm as fallback"""
        if not candidates:
            return None

        # Score each candidate node
        node_scores = []

        for node_id in candidates:
            node_spec = self.nodes[node_id]

            # Get current utilization
            cpu_util = 0
            memory_util = 0

            if node_id in self.node_metrics and self.node_metrics[node_id]:
                latest_metrics = self.node_metrics[node_id][-1]
                cpu_util = latest_metrics.cpu_usage
                memory_util = latest_metrics.memory_usage

            # Calculate score (lower is better)
            score = 0

            if self.allocation_strategy == AllocationStrategy.BALANCED:
                # Prefer nodes with balanced resource usage
                score = abs(cpu_util - memory_util)
            elif self.allocation_strategy == AllocationStrategy.CPU_OPTIMIZED:
                # Prefer nodes with low CPU usage
                score = cpu_util
            elif self.allocation_strategy == AllocationStrategy.MEMORY_OPTIMIZED:
                # Prefer nodes with low memory usage
                score = memory_util
            elif self.allocation_strategy == AllocationStrategy.PERFORMANCE_OPTIMIZED:
                # Prefer higher-spec nodes
                score = -(node_spec.cpu_cores + node_spec.memory_gb)

            node_scores.append((node_id, score))

        # Return node with best score
        node_scores.sort(key=lambda x: x[1])
        return node_scores[0][0]

    async def _update_node_health(self, node_id: str, metrics: ResourceMetrics):
        """Update node health based on metrics"""
        health = NodeHealth.HEALTHY

        # Check thresholds
        if (metrics.cpu_usage > self.resource_thresholds[ResourceType.CPU]['critical'] or
            metrics.memory_usage > self.resource_thresholds[ResourceType.MEMORY]['critical'] or
            metrics.storage_usage > self.resource_thresholds[ResourceType.STORAGE]['critical']):
            health = NodeHealth.CRITICAL
        elif (metrics.cpu_usage > self.resource_thresholds[ResourceType.CPU]['warning'] or
              metrics.memory_usage > self.resource_thresholds[ResourceType.MEMORY]['warning'] or
              metrics.storage_usage > self.resource_thresholds[ResourceType.STORAGE]['warning']):
            health = NodeHealth.WARNING

        # Update health if changed
        if self.node_health[node_id] != health:
            old_health = self.node_health[node_id]
            self.node_health[node_id] = health

            self.logger.info(f"Node {node_id} health changed from {old_health.value} to {health.value}")

            # Trigger alerts or actions if needed
            if health == NodeHealth.CRITICAL:
                await self._handle_critical_node(node_id)

    async def _handle_critical_node(self, node_id: str):
        """Handle a node in critical state"""
        self.logger.warning(f"Node {node_id} in critical state - taking protective actions")

        # In a full implementation, this would:
        # 1. Stop scheduling new workloads to this node
        # 2. Consider migrating existing workloads
        # 3. Send alerts to operators
        # 4. Trigger auto-scaling if available

    async def _migrate_workloads_from_node(self, node_id: str):
        """Migrate workloads away from a node"""
        workloads_to_migrate = [
            allocation for allocation in self.active_allocations.values()
            if allocation.target_node_id == node_id
        ]

        for allocation in workloads_to_migrate:
            self.logger.info(f"Migrating workload {allocation.workload_id} from node {node_id}")
            # In a full implementation, this would trigger workload migration

    async def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.running:
            try:
                # Check for pending workloads
                if self.pending_workloads:
                    pending = self.pending_workloads.copy()
                    self.pending_workloads.clear()

                    for workload in pending:
                        allocation = await self.request_allocation(workload)
                        if not allocation:
                            # Still can't allocate, keep in pending
                            self.pending_workloads.append(workload)

                await asyncio.sleep(30)  # Check every 30 seconds

            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(5)

    async def _optimization_loop(self):
        """Background optimization loop"""
        while self.running:
            try:
                # Run optimization every 5 minutes
                await asyncio.sleep(300)

                if self.enable_predictive_scaling or self.enable_cost_optimization:
                    await self.optimize_cluster()

            except Exception as e:
                self.logger.error(f"Optimization loop error: {e}")
                await asyncio.sleep(60)

if __name__ == "__main__":
    # Example usage
    import asyncio
    from .ai_engine import CloudOSAIEngine

    async def test_resource_manager():
        # Initialize AI engine and resource manager
        ai_engine = CloudOSAIEngine()
        await ai_engine.start()

        resource_manager = IntelligentResourceManager(ai_engine)
        await resource_manager.start()

        # Register some test nodes
        await resource_manager.register_node(NodeSpec(
            node_id="node1",
            cpu_cores=4,
            memory_gb=16,
            storage_gb=100,
            network_bandwidth_mbps=1000,
            instance_type="t3.large",
            cloud_provider="aws"
        ))

        await resource_manager.register_node(NodeSpec(
            node_id="node2",
            cpu_cores=8,
            memory_gb=32,
            storage_gb=200,
            network_bandwidth_mbps=1000,
            instance_type="t3.xlarge",
            cloud_provider="aws"
        ))

        # Update with some metrics
        await resource_manager.update_node_metrics(ResourceMetrics(
            node_id="node1",
            timestamp=datetime.now(),
            cpu_usage=45.0,
            memory_usage=60.0,
            storage_usage=30.0,
            network_io=100.0
        ))

        # Request allocation
        workload = WorkloadRequirement(
            workload_id="test-workload",
            cpu_request=2.0,
            memory_request=8.0,
            storage_request=20.0
        )

        allocation = await resource_manager.request_allocation(workload)
        if allocation:
            print(f"Allocated workload to {allocation.target_node_id}")

        # Get cluster status
        status = await resource_manager.get_cluster_status()
        print(f"Cluster status: {json.dumps(status, indent=2)}")

        # Cleanup
        await resource_manager.stop()
        await ai_engine.stop()

    # Run test
    asyncio.run(test_resource_manager())