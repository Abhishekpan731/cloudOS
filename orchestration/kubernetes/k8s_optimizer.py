"""
Kubernetes Integration and Optimization for CloudOS
Advanced container orchestration with AI-powered optimization
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import json
import yaml
from datetime import datetime, timedelta

try:
    from kubernetes import client, config, watch
    from kubernetes.client.rest import ApiException
    HAS_K8S_CLIENT = True
except ImportError:
    HAS_K8S_CLIENT = False
    client = None
    config = None
    watch = None
    ApiException = Exception

logger = logging.getLogger(__name__)

class OptimizationType(Enum):
    RESOURCE_OPTIMIZATION = "resource_optimization"
    SCHEDULING_OPTIMIZATION = "scheduling_optimization"
    NETWORKING_OPTIMIZATION = "networking_optimization"
    STORAGE_OPTIMIZATION = "storage_optimization"
    COST_OPTIMIZATION = "cost_optimization"

class WorkloadType(Enum):
    WEB_SERVICE = "web_service"
    BATCH_JOB = "batch_job"
    DATABASE = "database"
    ML_TRAINING = "ml_training"
    STREAMING = "streaming"
    CACHE = "cache"

@dataclass
class PodMetrics:
    name: str
    namespace: str
    cpu_usage: float
    memory_usage: float
    network_rx: float
    network_tx: float
    storage_io: float
    age: int
    restart_count: int
    node_name: str
    labels: Dict[str, str]

@dataclass
class NodeMetrics:
    name: str
    cpu_capacity: float
    memory_capacity: float
    cpu_usage: float
    memory_usage: float
    pod_count: int
    gpu_available: bool
    zone: str
    instance_type: str
    cost_per_hour: float

@dataclass
class OptimizationRecommendation:
    id: str
    type: OptimizationType
    workload: str
    namespace: str
    description: str
    current_resources: Dict[str, Any]
    recommended_resources: Dict[str, Any]
    expected_savings: float
    confidence_score: float
    impact_level: str
    implementation_steps: List[str]
    yaml_manifest: str

class CloudOSKubernetesOptimizer:
    def __init__(self, config_path: str = None):
        self.config_path = config_path
        self.k8s_client = None
        self.apps_v1 = None
        self.core_v1 = None
        self.metrics_v1beta1 = None
        self.is_initialized = False

        # Optimization parameters
        self.optimization_params = {
            'cpu_target_utilization': 70.0,
            'memory_target_utilization': 80.0,
            'underutilization_threshold': 20.0,
            'overutilization_threshold': 90.0,
            'recommendation_confidence_threshold': 0.7,
            'cost_savings_threshold': 10.0
        }

        # Resource recommendations by workload type
        self.workload_profiles = {
            WorkloadType.WEB_SERVICE: {
                'cpu_request': '100m',
                'cpu_limit': '500m',
                'memory_request': '128Mi',
                'memory_limit': '512Mi',
                'replicas': 3,
                'hpa_enabled': True
            },
            WorkloadType.DATABASE: {
                'cpu_request': '500m',
                'cpu_limit': '2000m',
                'memory_request': '1Gi',
                'memory_limit': '4Gi',
                'replicas': 1,
                'persistent_storage': True
            },
            WorkloadType.BATCH_JOB: {
                'cpu_request': '1000m',
                'cpu_limit': '4000m',
                'memory_request': '2Gi',
                'memory_limit': '8Gi',
                'completion_mode': 'NonIndexed'
            },
            WorkloadType.ML_TRAINING: {
                'cpu_request': '2000m',
                'cpu_limit': '8000m',
                'memory_request': '4Gi',
                'memory_limit': '16Gi',
                'gpu_required': True,
                'node_selector': {'accelerator': 'gpu'}
            }
        }

    async def initialize(self):
        """Initialize Kubernetes client and connections"""
        try:
            if not HAS_K8S_CLIENT:
                logger.warning("Kubernetes client library not available")
                return

            # Load Kubernetes configuration
            try:
                config.load_incluster_config()
                logger.info("Loaded in-cluster Kubernetes configuration")
            except config.ConfigException:
                if self.config_path:
                    config.load_kube_config(config_file=self.config_path)
                else:
                    config.load_kube_config()
                logger.info("Loaded Kubernetes configuration from kubeconfig")

            # Initialize API clients
            self.core_v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()

            # Try to initialize metrics API (may not be available)
            try:
                self.metrics_v1beta1 = client.CustomObjectsApi()
                await self._test_metrics_api()
            except Exception as e:
                logger.warning(f"Metrics API not available: {e}")
                self.metrics_v1beta1 = None

            self.is_initialized = True
            logger.info("Kubernetes Optimizer initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes Optimizer: {e}")
            raise

    async def _test_metrics_api(self):
        """Test if metrics API is available"""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.metrics_v1beta1.list_cluster_custom_object(
                    group="metrics.k8s.io",
                    version="v1beta1",
                    plural="nodes"
                )
            )
            logger.info("Metrics API is available")
        except Exception as e:
            logger.warning(f"Metrics API test failed: {e}")
            raise

    async def collect_cluster_metrics(self) -> Tuple[List[PodMetrics], List[NodeMetrics]]:
        """Collect comprehensive cluster metrics"""
        try:
            if not self.is_initialized:
                await self.initialize()

            pod_metrics = []
            node_metrics = []

            # Collect pod metrics
            pods = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.core_v1.list_pod_for_all_namespaces()
            )

            for pod in pods.items:
                if pod.status.phase == 'Running':
                    metrics = await self._get_pod_metrics(pod)
                    if metrics:
                        pod_metrics.append(metrics)

            # Collect node metrics
            nodes = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.core_v1.list_node()
            )

            for node in nodes.items:
                metrics = await self._get_node_metrics(node)
                if metrics:
                    node_metrics.append(metrics)

            logger.info(f"Collected metrics for {len(pod_metrics)} pods and {len(node_metrics)} nodes")
            return pod_metrics, node_metrics

        except Exception as e:
            logger.error(f"Failed to collect cluster metrics: {e}")
            return [], []

    async def _get_pod_metrics(self, pod) -> Optional[PodMetrics]:
        """Get detailed metrics for a single pod"""
        try:
            # Get resource usage from metrics API if available
            cpu_usage = 0.0
            memory_usage = 0.0
            network_rx = 0.0
            network_tx = 0.0
            storage_io = 0.0

            if self.metrics_v1beta1:
                try:
                    pod_metrics = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self.metrics_v1beta1.get_namespaced_custom_object(
                            group="metrics.k8s.io",
                            version="v1beta1",
                            namespace=pod.metadata.namespace,
                            plural="pods",
                            name=pod.metadata.name
                        )
                    )

                    # Parse CPU and memory usage
                    containers = pod_metrics.get('containers', [])
                    for container in containers:
                        usage = container.get('usage', {})
                        if 'cpu' in usage:
                            cpu_usage += self._parse_cpu_value(usage['cpu'])
                        if 'memory' in usage:
                            memory_usage += self._parse_memory_value(usage['memory'])

                except Exception as e:
                    logger.debug(f"Could not get metrics for pod {pod.metadata.name}: {e}")

            # Calculate pod age
            creation_time = pod.metadata.creation_timestamp
            age = (datetime.now(creation_time.tzinfo) - creation_time).total_seconds() / 3600  # hours

            # Count restarts
            restart_count = 0
            if pod.status.container_statuses:
                restart_count = sum(cs.restart_count for cs in pod.status.container_statuses)

            return PodMetrics(
                name=pod.metadata.name,
                namespace=pod.metadata.namespace,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                network_rx=network_rx,
                network_tx=network_tx,
                storage_io=storage_io,
                age=int(age),
                restart_count=restart_count,
                node_name=pod.spec.node_name or 'unknown',
                labels=pod.metadata.labels or {}
            )

        except Exception as e:
            logger.error(f"Failed to get pod metrics for {pod.metadata.name}: {e}")
            return None

    async def _get_node_metrics(self, node) -> Optional[NodeMetrics]:
        """Get detailed metrics for a single node"""
        try:
            # Parse node capacity
            capacity = node.status.capacity
            cpu_capacity = self._parse_cpu_value(capacity.get('cpu', '0'))
            memory_capacity = self._parse_memory_value(capacity.get('memory', '0'))

            # Get current usage from metrics API if available
            cpu_usage = 0.0
            memory_usage = 0.0

            if self.metrics_v1beta1:
                try:
                    node_metrics = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self.metrics_v1beta1.get_cluster_custom_object(
                            group="metrics.k8s.io",
                            version="v1beta1",
                            plural="nodes",
                            name=node.metadata.name
                        )
                    )

                    usage = node_metrics.get('usage', {})
                    if 'cpu' in usage:
                        cpu_usage = self._parse_cpu_value(usage['cpu'])
                    if 'memory' in usage:
                        memory_usage = self._parse_memory_value(usage['memory'])

                except Exception as e:
                    logger.debug(f"Could not get metrics for node {node.metadata.name}: {e}")

            # Count pods on this node
            pods = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.core_v1.list_pod_for_all_namespaces(
                    field_selector=f'spec.nodeName={node.metadata.name}'
                )
            )
            pod_count = len([p for p in pods.items if p.status.phase == 'Running'])

            # Check for GPU availability
            gpu_available = 'nvidia.com/gpu' in capacity

            # Extract zone and instance type from labels
            labels = node.metadata.labels or {}
            zone = labels.get('topology.kubernetes.io/zone', 'unknown')
            instance_type = labels.get('node.kubernetes.io/instance-type', 'unknown')

            # Estimate cost (simplified - would integrate with cloud pricing APIs)
            cost_per_hour = self._estimate_node_cost(instance_type, gpu_available)

            return NodeMetrics(
                name=node.metadata.name,
                cpu_capacity=cpu_capacity,
                memory_capacity=memory_capacity,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                pod_count=pod_count,
                gpu_available=gpu_available,
                zone=zone,
                instance_type=instance_type,
                cost_per_hour=cost_per_hour
            )

        except Exception as e:
            logger.error(f"Failed to get node metrics for {node.metadata.name}: {e}")
            return None

    async def analyze_workloads(self, pod_metrics: List[PodMetrics]) -> List[OptimizationRecommendation]:
        """Analyze workloads and generate optimization recommendations"""
        try:
            recommendations = []

            # Group pods by deployment/workload
            workload_groups = await self._group_pods_by_workload(pod_metrics)

            for workload_name, pods in workload_groups.items():
                # Analyze resource utilization
                resource_rec = await self._analyze_resource_utilization(workload_name, pods)
                if resource_rec:
                    recommendations.append(resource_rec)

                # Analyze scheduling optimization
                scheduling_rec = await self._analyze_scheduling_optimization(workload_name, pods)
                if scheduling_rec:
                    recommendations.append(scheduling_rec)

                # Analyze cost optimization
                cost_rec = await self._analyze_cost_optimization(workload_name, pods)
                if cost_rec:
                    recommendations.append(cost_rec)

            # Sort by expected savings
            recommendations.sort(key=lambda x: x.expected_savings, reverse=True)

            return recommendations

        except Exception as e:
            logger.error(f"Failed to analyze workloads: {e}")
            return []

    async def _group_pods_by_workload(self, pod_metrics: List[PodMetrics]) -> Dict[str, List[PodMetrics]]:
        """Group pods by their parent workload (deployment, statefulset, etc.)"""
        try:
            workload_groups = {}

            for pod in pod_metrics:
                # Try to identify parent workload from labels
                workload_name = "unknown"

                if 'app' in pod.labels:
                    workload_name = pod.labels['app']
                elif 'app.kubernetes.io/name' in pod.labels:
                    workload_name = pod.labels['app.kubernetes.io/name']
                elif pod.name.count('-') >= 2:
                    # Extract deployment name from pod name pattern
                    parts = pod.name.rsplit('-', 2)
                    workload_name = parts[0]

                workload_key = f"{pod.namespace}/{workload_name}"

                if workload_key not in workload_groups:
                    workload_groups[workload_key] = []

                workload_groups[workload_key].append(pod)

            return workload_groups

        except Exception as e:
            logger.error(f"Failed to group pods by workload: {e}")
            return {}

    async def _analyze_resource_utilization(self, workload_name: str, pods: List[PodMetrics]) -> Optional[OptimizationRecommendation]:
        """Analyze resource utilization and recommend optimizations"""
        try:
            if not pods:
                return None

            # Calculate average utilization
            avg_cpu = sum(p.cpu_usage for p in pods) / len(pods)
            avg_memory = sum(p.memory_usage for p in pods) / len(pods)

            # Get current resource requests/limits from deployment
            namespace, workload = workload_name.split('/', 1)
            current_resources = await self._get_current_resource_specs(namespace, workload)

            # Determine if optimization is needed
            cpu_utilization = (avg_cpu / self._parse_cpu_value(current_resources.get('cpu_request', '100m'))) * 100 if current_resources.get('cpu_request') else 0
            memory_utilization = (avg_memory / self._parse_memory_value(current_resources.get('memory_request', '128Mi'))) * 100 if current_resources.get('memory_request') else 0

            optimization_needed = False
            recommendations = {}

            # Check for underutilization
            if cpu_utilization < self.optimization_params['underutilization_threshold']:
                new_cpu_request = max(avg_cpu * 1.2, self._parse_cpu_value('50m'))  # 20% buffer, minimum 50m
                recommendations['cpu_request'] = self._format_cpu_value(new_cpu_request)
                optimization_needed = True

            if memory_utilization < self.optimization_params['underutilization_threshold']:
                new_memory_request = max(avg_memory * 1.2, self._parse_memory_value('64Mi'))  # 20% buffer, minimum 64Mi
                recommendations['memory_request'] = self._format_memory_value(new_memory_request)
                optimization_needed = True

            # Check for overutilization
            if cpu_utilization > self.optimization_params['overutilization_threshold']:
                new_cpu_limit = avg_cpu * 1.5  # 50% buffer for spikes
                recommendations['cpu_limit'] = self._format_cpu_value(new_cpu_limit)
                optimization_needed = True

            if memory_utilization > self.optimization_params['overutilization_threshold']:
                new_memory_limit = avg_memory * 1.3  # 30% buffer for spikes
                recommendations['memory_limit'] = self._format_memory_value(new_memory_limit)
                optimization_needed = True

            if not optimization_needed:
                return None

            # Calculate potential savings
            current_cost = self._calculate_workload_cost(current_resources, len(pods))
            optimized_cost = self._calculate_workload_cost(recommendations, len(pods))
            expected_savings = max(0, current_cost - optimized_cost)

            if expected_savings < self.optimization_params['cost_savings_threshold']:
                return None

            # Generate YAML manifest for the optimization
            yaml_manifest = await self._generate_optimization_yaml(namespace, workload, recommendations)

            return OptimizationRecommendation(
                id=f"resource_{workload_name}_{int(datetime.now().timestamp())}",
                type=OptimizationType.RESOURCE_OPTIMIZATION,
                workload=workload,
                namespace=namespace,
                description=f"Optimize resource allocation for {workload}. CPU utilization: {cpu_utilization:.1f}%, Memory utilization: {memory_utilization:.1f}%",
                current_resources=current_resources,
                recommended_resources=recommendations,
                expected_savings=expected_savings,
                confidence_score=0.8,
                impact_level="Medium" if expected_savings < 100 else "High",
                implementation_steps=[
                    f"Review current resource usage patterns for {workload}",
                    "Apply the recommended resource changes",
                    "Monitor workload performance for 24-48 hours",
                    "Fine-tune resources based on observed behavior"
                ],
                yaml_manifest=yaml_manifest
            )

        except Exception as e:
            logger.error(f"Resource utilization analysis failed for {workload_name}: {e}")
            return None

    async def _analyze_scheduling_optimization(self, workload_name: str, pods: List[PodMetrics]) -> Optional[OptimizationRecommendation]:
        """Analyze pod scheduling and recommend optimizations"""
        try:
            if len(pods) < 2:
                return None

            # Check for uneven distribution across nodes
            node_distribution = {}
            for pod in pods:
                node_distribution[pod.node_name] = node_distribution.get(pod.node_name, 0) + 1

            # If all pods are on the same node, recommend spreading
            if len(node_distribution) == 1 and len(pods) > 1:
                namespace, workload = workload_name.split('/', 1)

                # Generate pod anti-affinity rules
                affinity_rules = {
                    'podAntiAffinity': {
                        'preferredDuringSchedulingIgnoredDuringExecution': [{
                            'weight': 100,
                            'podAffinityTerm': {
                                'labelSelector': {
                                    'matchLabels': {
                                        'app': workload
                                    }
                                },
                                'topologyKey': 'kubernetes.io/hostname'
                            }
                        }]
                    }
                }

                yaml_manifest = await self._generate_affinity_yaml(namespace, workload, affinity_rules)

                return OptimizationRecommendation(
                    id=f"scheduling_{workload_name}_{int(datetime.now().timestamp())}",
                    type=OptimizationType.SCHEDULING_OPTIMIZATION,
                    workload=workload,
                    namespace=namespace,
                    description=f"Improve pod distribution for {workload}. All {len(pods)} pods are on the same node.",
                    current_resources={'node_distribution': node_distribution},
                    recommended_resources={'affinity_rules': affinity_rules},
                    expected_savings=50.0,  # Improved availability value
                    confidence_score=0.9,
                    impact_level="High",
                    implementation_steps=[
                        "Apply pod anti-affinity rules to deployment",
                        "Restart deployment to trigger rescheduling",
                        "Verify pods are distributed across multiple nodes",
                        "Monitor application performance and availability"
                    ],
                    yaml_manifest=yaml_manifest
                )

        except Exception as e:
            logger.error(f"Scheduling optimization analysis failed for {workload_name}: {e}")
            return None

    async def _analyze_cost_optimization(self, workload_name: str, pods: List[PodMetrics]) -> Optional[OptimizationRecommendation]:
        """Analyze cost optimization opportunities"""
        try:
            if not pods:
                return None

            namespace, workload = workload_name.split('/', 1)

            # Check for spot instance opportunities
            has_high_restart_count = any(p.restart_count > 3 for p in pods)
            avg_age = sum(p.age for p in pods) / len(pods)

            # If workload is stable (low restarts, long-running), recommend spot instances
            if not has_high_restart_count and avg_age > 24:  # Running for more than 24 hours
                spot_tolerations = [{
                    'key': 'node.kubernetes.io/spot-instance',
                    'operator': 'Exists',
                    'effect': 'NoSchedule'
                }]

                node_selector = {
                    'node-lifecycle': 'spot'
                }

                current_cost = len(pods) * 0.10 * 24 * 30  # Estimate $0.10/hour per pod
                spot_cost = current_cost * 0.3  # 70% savings with spot instances
                expected_savings = current_cost - spot_cost

                yaml_manifest = await self._generate_spot_yaml(namespace, workload, node_selector, spot_tolerations)

                return OptimizationRecommendation(
                    id=f"cost_{workload_name}_{int(datetime.now().timestamp())}",
                    type=OptimizationType.COST_OPTIMIZATION,
                    workload=workload,
                    namespace=namespace,
                    description=f"Migrate {workload} to spot instances. Workload appears stable with low restart rate.",
                    current_resources={'instance_type': 'on-demand'},
                    recommended_resources={'instance_type': 'spot', 'tolerations': spot_tolerations},
                    expected_savings=expected_savings,
                    confidence_score=0.7,  # Lower confidence due to spot instance risks
                    impact_level="High",
                    implementation_steps=[
                        "Ensure workload can handle interruptions gracefully",
                        "Apply spot instance node selectors and tolerations",
                        "Monitor workload for spot instance interruptions",
                        "Set up alerts for spot instance events"
                    ],
                    yaml_manifest=yaml_manifest
                )

        except Exception as e:
            logger.error(f"Cost optimization analysis failed for {workload_name}: {e}")
            return None

    async def apply_optimization(self, recommendation: OptimizationRecommendation) -> Dict[str, Any]:
        """Apply an optimization recommendation"""
        try:
            logger.info(f"Applying optimization: {recommendation.id}")

            # Parse and apply the YAML manifest
            manifest = yaml.safe_load(recommendation.yaml_manifest)

            if manifest['kind'] == 'Deployment':
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.apps_v1.patch_namespaced_deployment(
                        name=recommendation.workload,
                        namespace=recommendation.namespace,
                        body=manifest
                    )
                )
            elif manifest['kind'] == 'StatefulSet':
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.apps_v1.patch_namespaced_stateful_set(
                        name=recommendation.workload,
                        namespace=recommendation.namespace,
                        body=manifest
                    )
                )
            else:
                raise ValueError(f"Unsupported workload kind: {manifest['kind']}")

            return {
                "status": "success",
                "applied_at": datetime.now().isoformat(),
                "recommendation_id": recommendation.id,
                "message": f"Successfully applied {recommendation.type.value} optimization"
            }

        except Exception as e:
            logger.error(f"Failed to apply optimization {recommendation.id}: {e}")
            return {
                "status": "error",
                "error": str(e),
                "recommendation_id": recommendation.id
            }

    # Utility methods for parsing and formatting resources
    def _parse_cpu_value(self, cpu_str: str) -> float:
        """Parse CPU value to millicores"""
        if not cpu_str:
            return 0.0

        cpu_str = cpu_str.strip().lower()
        if cpu_str.endswith('m'):
            return float(cpu_str[:-1])
        elif cpu_str.endswith('n'):
            return float(cpu_str[:-1]) / 1000000
        else:
            return float(cpu_str) * 1000

    def _parse_memory_value(self, memory_str: str) -> float:
        """Parse memory value to bytes"""
        if not memory_str:
            return 0.0

        memory_str = memory_str.strip()
        multipliers = {
            'Ki': 1024, 'Mi': 1024**2, 'Gi': 1024**3,
            'K': 1000, 'M': 1000**2, 'G': 1000**3
        }

        for suffix, multiplier in multipliers.items():
            if memory_str.endswith(suffix):
                return float(memory_str[:-len(suffix)]) * multiplier

        return float(memory_str)

    def _format_cpu_value(self, millicores: float) -> str:
        """Format CPU value from millicores to Kubernetes format"""
        if millicores >= 1000:
            return f"{int(millicores // 1000)}"
        else:
            return f"{int(millicores)}m"

    def _format_memory_value(self, bytes_val: float) -> str:
        """Format memory value from bytes to Kubernetes format"""
        if bytes_val >= 1024**3:
            return f"{int(bytes_val // (1024**3))}Gi"
        elif bytes_val >= 1024**2:
            return f"{int(bytes_val // (1024**2))}Mi"
        elif bytes_val >= 1024:
            return f"{int(bytes_val // 1024)}Ki"
        else:
            return f"{int(bytes_val)}"

    def _calculate_workload_cost(self, resources: Dict[str, Any], replica_count: int) -> float:
        """Calculate estimated monthly cost for workload resources"""
        cpu_cost_per_mcore = 0.0001  # $0.0001 per millcore per month
        memory_cost_per_mb = 0.00005  # $0.00005 per MB per month

        cpu_request = self._parse_cpu_value(resources.get('cpu_request', '100m'))
        memory_request = self._parse_memory_value(resources.get('memory_request', '128Mi')) / (1024**2)  # Convert to MB

        return (cpu_request * cpu_cost_per_mcore + memory_request * memory_cost_per_mb) * replica_count

    def _estimate_node_cost(self, instance_type: str, has_gpu: bool) -> float:
        """Estimate hourly cost for a node based on instance type"""
        # Simplified cost estimation - in production, integrate with cloud pricing APIs
        base_costs = {
            't3.medium': 0.0416,
            't3.large': 0.0832,
            'm5.large': 0.096,
            'm5.xlarge': 0.192,
            'c5.large': 0.085,
            'c5.xlarge': 0.17
        }

        base_cost = base_costs.get(instance_type, 0.10)  # Default $0.10/hour
        if has_gpu:
            base_cost += 0.90  # Add GPU cost

        return base_cost

    async def _get_current_resource_specs(self, namespace: str, workload: str) -> Dict[str, Any]:
        """Get current resource specifications for a workload"""
        try:
            # Try to get deployment first
            try:
                deployment = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.apps_v1.read_namespaced_deployment(
                        name=workload,
                        namespace=namespace
                    )
                )
                containers = deployment.spec.template.spec.containers
            except ApiException:
                # Try StatefulSet
                try:
                    statefulset = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self.apps_v1.read_namespaced_stateful_set(
                            name=workload,
                            namespace=namespace
                        )
                    )
                    containers = statefulset.spec.template.spec.containers
                except ApiException:
                    return {}

            if containers:
                container = containers[0]  # Use first container
                resources = container.resources

                result = {}
                if resources.requests:
                    result.update({
                        'cpu_request': resources.requests.get('cpu'),
                        'memory_request': resources.requests.get('memory')
                    })
                if resources.limits:
                    result.update({
                        'cpu_limit': resources.limits.get('cpu'),
                        'memory_limit': resources.limits.get('memory')
                    })

                return {k: v for k, v in result.items() if v is not None}

        except Exception as e:
            logger.error(f"Failed to get current resource specs for {namespace}/{workload}: {e}")

        return {}

    async def _generate_optimization_yaml(self, namespace: str, workload: str, resources: Dict[str, Any]) -> str:
        """Generate YAML manifest for resource optimization"""
        try:
            # Get current deployment/statefulset
            current_spec = await self._get_current_resource_specs(namespace, workload)

            manifest = {
                'apiVersion': 'apps/v1',
                'kind': 'Deployment',
                'metadata': {
                    'name': workload,
                    'namespace': namespace
                },
                'spec': {
                    'template': {
                        'spec': {
                            'containers': [{
                                'name': 'main',  # Simplified - would need actual container names
                                'resources': {
                                    'requests': {},
                                    'limits': {}
                                }
                            }]
                        }
                    }
                }
            }

            # Update resources
            container_resources = manifest['spec']['template']['spec']['containers'][0]['resources']

            if 'cpu_request' in resources:
                container_resources['requests']['cpu'] = resources['cpu_request']
            if 'memory_request' in resources:
                container_resources['requests']['memory'] = resources['memory_request']
            if 'cpu_limit' in resources:
                container_resources['limits']['cpu'] = resources['cpu_limit']
            if 'memory_limit' in resources:
                container_resources['limits']['memory'] = resources['memory_limit']

            return yaml.dump(manifest, default_flow_style=False)

        except Exception as e:
            logger.error(f"Failed to generate optimization YAML: {e}")
            return ""

    async def _generate_affinity_yaml(self, namespace: str, workload: str, affinity_rules: Dict[str, Any]) -> str:
        """Generate YAML manifest for scheduling optimization"""
        manifest = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': workload,
                'namespace': namespace
            },
            'spec': {
                'template': {
                    'spec': {
                        'affinity': affinity_rules
                    }
                }
            }
        }

        return yaml.dump(manifest, default_flow_style=False)

    async def _generate_spot_yaml(self, namespace: str, workload: str, node_selector: Dict[str, str], tolerations: List[Dict[str, Any]]) -> str:
        """Generate YAML manifest for spot instance optimization"""
        manifest = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': workload,
                'namespace': namespace
            },
            'spec': {
                'template': {
                    'spec': {
                        'nodeSelector': node_selector,
                        'tolerations': tolerations
                    }
                }
            }
        }

        return yaml.dump(manifest, default_flow_style=False)

    async def get_cluster_report(self) -> Dict[str, Any]:
        """Generate comprehensive cluster optimization report"""
        try:
            pod_metrics, node_metrics = await self.collect_cluster_metrics()
            recommendations = await self.analyze_workloads(pod_metrics)

            # Calculate cluster statistics
            total_pods = len(pod_metrics)
            total_nodes = len(node_metrics)
            total_cost = sum(node.cost_per_hour * 24 * 30 for node in node_metrics)  # Monthly cost
            potential_savings = sum(rec.expected_savings for rec in recommendations)

            # Resource utilization
            total_cpu_capacity = sum(node.cpu_capacity for node in node_metrics)
            total_cpu_usage = sum(node.cpu_usage for node in node_metrics)
            total_memory_capacity = sum(node.memory_capacity for node in node_metrics)
            total_memory_usage = sum(node.memory_usage for node in node_metrics)

            cluster_cpu_utilization = (total_cpu_usage / total_cpu_capacity * 100) if total_cpu_capacity > 0 else 0
            cluster_memory_utilization = (total_memory_usage / total_memory_capacity * 100) if total_memory_capacity > 0 else 0

            report = {
                "timestamp": datetime.now().isoformat(),
                "cluster_overview": {
                    "total_nodes": total_nodes,
                    "total_pods": total_pods,
                    "monthly_cost": total_cost,
                    "cluster_cpu_utilization": cluster_cpu_utilization,
                    "cluster_memory_utilization": cluster_memory_utilization
                },
                "optimization_opportunities": {
                    "total_recommendations": len(recommendations),
                    "potential_monthly_savings": potential_savings,
                    "savings_percentage": (potential_savings / total_cost * 100) if total_cost > 0 else 0
                },
                "recommendations_by_type": {
                    "resource_optimization": len([r for r in recommendations if r.type == OptimizationType.RESOURCE_OPTIMIZATION]),
                    "scheduling_optimization": len([r for r in recommendations if r.type == OptimizationType.SCHEDULING_OPTIMIZATION]),
                    "cost_optimization": len([r for r in recommendations if r.type == OptimizationType.COST_OPTIMIZATION])
                },
                "top_recommendations": [
                    {
                        "id": rec.id,
                        "type": rec.type.value,
                        "workload": rec.workload,
                        "namespace": rec.namespace,
                        "expected_savings": rec.expected_savings,
                        "confidence_score": rec.confidence_score,
                        "impact_level": rec.impact_level
                    }
                    for rec in recommendations[:10]  # Top 10
                ],
                "node_utilization": [
                    {
                        "name": node.name,
                        "cpu_utilization": (node.cpu_usage / node.cpu_capacity * 100) if node.cpu_capacity > 0 else 0,
                        "memory_utilization": (node.memory_usage / node.memory_capacity * 100) if node.memory_capacity > 0 else 0,
                        "pod_count": node.pod_count,
                        "cost_per_hour": node.cost_per_hour
                    }
                    for node in node_metrics
                ]
            }

            return report

        except Exception as e:
            logger.error(f"Failed to generate cluster report: {e}")
            return {"error": str(e)}

    async def stop(self):
        """Stop the Kubernetes optimizer"""
        try:
            logger.info("Stopping Kubernetes Optimizer")
            self.is_initialized = False

        except Exception as e:
            logger.error(f"Error stopping Kubernetes Optimizer: {e}")