#!/usr/bin/env python3
"""
CloudOS Prometheus Integration and Observability Stack
Comprehensive metrics collection, monitoring, and alerting infrastructure
"""

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading

# Prometheus client library
try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, Info, Enum as PrometheusEnum,
        CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST,
        start_http_server, push_to_gateway, delete_from_gateway
    )
    HAS_PROMETHEUS_CLIENT = True
except ImportError:
    HAS_PROMETHEUS_CLIENT = False

# HTTP server for metrics endpoint
try:
    from aiohttp import web, ClientSession
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# YAML for configuration
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    INFO = "info"

class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

@dataclass
class MetricDefinition:
    """Definition of a metric to be collected"""
    name: str
    metric_type: MetricType
    description: str
    labels: List[str] = field(default_factory=list)
    buckets: Optional[List[float]] = None  # For histograms
    quantiles: Optional[List[float]] = None  # For summaries
    unit: str = ""

@dataclass
class AlertRule:
    """Prometheus alert rule definition"""
    name: str
    expression: str
    duration: str = "5m"
    severity: AlertSeverity = AlertSeverity.WARNING
    summary: str = ""
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)

@dataclass
class DashboardPanel:
    """Grafana dashboard panel definition"""
    title: str
    panel_type: str = "graph"  # graph, stat, table, heatmap, etc.
    query: str = ""
    unit: str = ""
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    thresholds: List[Dict[str, Any]] = field(default_factory=list)
    width: int = 12
    height: int = 8

@dataclass
class Dashboard:
    """Grafana dashboard definition"""
    title: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    panels: List[DashboardPanel] = field(default_factory=list)
    refresh_interval: str = "30s"
    time_range: str = "1h"

class CloudOSMetricsCollector:
    """
    Custom metrics collector for CloudOS components
    Integrates with Prometheus for monitoring and alerting
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Configuration
        self.metrics_port = self.config.get('metrics_port', 9090)
        self.pushgateway_url = self.config.get('pushgateway_url')
        self.job_name = self.config.get('job_name', 'cloudos')
        self.instance_name = self.config.get('instance_name', 'cloudos-instance')

        # Prometheus registry
        self.registry = CollectorRegistry()
        self.metrics: Dict[str, Any] = {}

        # Metric definitions
        self.metric_definitions: Dict[str, MetricDefinition] = {}

        # HTTP server for metrics endpoint
        self.metrics_server = None
        self.running = False

        # Background tasks
        self.collection_task = None
        self.push_task = None

        # Initialize built-in metrics
        self._initialize_builtin_metrics()

        self.logger.info("CloudOS Metrics Collector initialized")

    def _initialize_builtin_metrics(self):
        """Initialize built-in CloudOS metrics"""
        if not HAS_PROMETHEUS_CLIENT:
            self.logger.warning("Prometheus client not available - metrics disabled")
            return

        # System metrics
        self.register_metric(MetricDefinition(
            name="cloudos_system_cpu_usage_percent",
            metric_type=MetricType.GAUGE,
            description="System CPU usage percentage",
            labels=["cpu_core"],
            unit="percent"
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_system_memory_usage_bytes",
            metric_type=MetricType.GAUGE,
            description="System memory usage in bytes",
            labels=["type"],  # total, used, free, cached
            unit="bytes"
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_system_disk_usage_bytes",
            metric_type=MetricType.GAUGE,
            description="System disk usage in bytes",
            labels=["device", "mountpoint", "type"],  # type: total, used, free
            unit="bytes"
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_system_network_bytes_total",
            metric_type=MetricType.COUNTER,
            description="Total network bytes transferred",
            labels=["interface", "direction"],  # direction: rx, tx
            unit="bytes"
        ))

        # Container metrics
        self.register_metric(MetricDefinition(
            name="cloudos_container_count",
            metric_type=MetricType.GAUGE,
            description="Number of containers by state",
            labels=["state"]  # running, stopped, paused, etc.
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_container_cpu_usage_percent",
            metric_type=MetricType.GAUGE,
            description="Container CPU usage percentage",
            labels=["container_id", "container_name"],
            unit="percent"
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_container_memory_usage_bytes",
            metric_type=MetricType.GAUGE,
            description="Container memory usage in bytes",
            labels=["container_id", "container_name"],
            unit="bytes"
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_container_restart_count",
            metric_type=MetricType.COUNTER,
            description="Container restart count",
            labels=["container_id", "container_name"]
        ))

        # AI Engine metrics
        self.register_metric(MetricDefinition(
            name="cloudos_ai_inference_requests_total",
            metric_type=MetricType.COUNTER,
            description="Total AI inference requests",
            labels=["model_id", "status"]  # status: success, failure
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_ai_inference_duration_seconds",
            metric_type=MetricType.HISTOGRAM,
            description="AI inference request duration",
            labels=["model_id"],
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
            unit="seconds"
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_ai_model_loaded_count",
            metric_type=MetricType.GAUGE,
            description="Number of loaded AI models",
            labels=["backend"]  # tensorflow, pytorch, onnx
        ))

        # Security metrics
        self.register_metric(MetricDefinition(
            name="cloudos_security_events_total",
            metric_type=MetricType.COUNTER,
            description="Total security events",
            labels=["event_type", "severity"]
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_auth_attempts_total",
            metric_type=MetricType.COUNTER,
            description="Authentication attempts",
            labels=["result"]  # success, failure
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_active_sessions",
            metric_type=MetricType.GAUGE,
            description="Number of active user sessions"
        ))

        # Cluster metrics
        self.register_metric(MetricDefinition(
            name="cloudos_cluster_nodes_total",
            metric_type=MetricType.GAUGE,
            description="Total cluster nodes",
            labels=["state"]  # healthy, unhealthy, unknown
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_leader_election_total",
            metric_type=MetricType.COUNTER,
            description="Leader election events",
            labels=["event_type"]  # elected, lost, failed
        ))

        # Cost optimization metrics
        self.register_metric(MetricDefinition(
            name="cloudos_cost_optimization_savings_total",
            metric_type=MetricType.COUNTER,
            description="Total cost savings from optimization",
            labels=["provider", "action"],  # action: rightsizing, spot, reserved
            unit="dollars"
        ))

        # Self-healing metrics
        self.register_metric(MetricDefinition(
            name="cloudos_incidents_total",
            metric_type=MetricType.COUNTER,
            description="Total incidents detected",
            labels=["severity", "status"]  # status: detected, resolved, escalated
        ))

        self.register_metric(MetricDefinition(
            name="cloudos_remediation_actions_total",
            metric_type=MetricType.COUNTER,
            description="Automated remediation actions",
            labels=["action", "result"]  # result: success, failure
        ))

    def register_metric(self, definition: MetricDefinition):
        """Register a new metric definition"""
        if not HAS_PROMETHEUS_CLIENT:
            return

        self.metric_definitions[definition.name] = definition

        # Create Prometheus metric object
        if definition.metric_type == MetricType.COUNTER:
            metric = Counter(
                definition.name,
                definition.description,
                labelnames=definition.labels,
                registry=self.registry
            )
        elif definition.metric_type == MetricType.GAUGE:
            metric = Gauge(
                definition.name,
                definition.description,
                labelnames=definition.labels,
                registry=self.registry
            )
        elif definition.metric_type == MetricType.HISTOGRAM:
            buckets = definition.buckets or [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0]
            metric = Histogram(
                definition.name,
                definition.description,
                labelnames=definition.labels,
                buckets=buckets,
                registry=self.registry
            )
        elif definition.metric_type == MetricType.SUMMARY:
            quantiles = definition.quantiles or [0.5, 0.9, 0.95, 0.99]
            metric = Summary(
                definition.name,
                definition.description,
                labelnames=definition.labels,
                registry=self.registry
            )
        elif definition.metric_type == MetricType.INFO:
            metric = Info(
                definition.name,
                definition.description,
                labelnames=definition.labels,
                registry=self.registry
            )
        else:
            self.logger.error(f"Unknown metric type: {definition.metric_type}")
            return

        self.metrics[definition.name] = metric
        self.logger.debug(f"Registered metric: {definition.name}")

    def increment_counter(self, metric_name: str, labels: Dict[str, str] = None, value: float = 1.0):
        """Increment a counter metric"""
        metric = self.metrics.get(metric_name)
        if not metric:
            self.logger.warning(f"Metric {metric_name} not found")
            return

        if labels:
            metric.labels(**labels).inc(value)
        else:
            metric.inc(value)

    def set_gauge(self, metric_name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric value"""
        metric = self.metrics.get(metric_name)
        if not metric:
            self.logger.warning(f"Metric {metric_name} not found")
            return

        if labels:
            metric.labels(**labels).set(value)
        else:
            metric.set(value)

    def observe_histogram(self, metric_name: str, value: float, labels: Dict[str, str] = None):
        """Observe a value in a histogram metric"""
        metric = self.metrics.get(metric_name)
        if not metric:
            self.logger.warning(f"Metric {metric_name} not found")
            return

        if labels:
            metric.labels(**labels).observe(value)
        else:
            metric.observe(value)

    def observe_summary(self, metric_name: str, value: float, labels: Dict[str, str] = None):
        """Observe a value in a summary metric"""
        metric = self.metrics.get(metric_name)
        if not metric:
            self.logger.warning(f"Metric {metric_name} not found")
            return

        if labels:
            metric.labels(**labels).observe(value)
        else:
            metric.observe(value)

    def set_info(self, metric_name: str, labels: Dict[str, str]):
        """Set info metric labels"""
        metric = self.metrics.get(metric_name)
        if not metric:
            self.logger.warning(f"Metric {metric_name} not found")
            return

        metric.info(labels)

    async def start(self):
        """Start the metrics collection system"""
        if self.running:
            return

        self.running = True

        # Start HTTP server for /metrics endpoint
        if HAS_AIOHTTP:
            await self._start_metrics_server()

        # Start background collection task
        self.collection_task = asyncio.create_task(self._collection_loop())

        # Start push gateway task if configured
        if self.pushgateway_url:
            self.push_task = asyncio.create_task(self._push_loop())

        self.logger.info("Metrics collection started")

    async def stop(self):
        """Stop the metrics collection system"""
        if not self.running:
            return

        self.running = False

        # Cancel background tasks
        if self.collection_task:
            self.collection_task.cancel()
        if self.push_task:
            self.push_task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(
            self.collection_task, self.push_task,
            return_exceptions=True
        )

        # Stop metrics server
        if self.metrics_server:
            await self.metrics_server.cleanup()

        self.logger.info("Metrics collection stopped")

    async def _start_metrics_server(self):
        """Start HTTP server for metrics endpoint"""
        app = web.Application()
        app.router.add_get('/metrics', self._metrics_handler)
        app.router.add_get('/health', self._health_handler)

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, '0.0.0.0', self.metrics_port)
        await site.start()

        self.metrics_server = runner
        self.logger.info(f"Metrics server started on port {self.metrics_port}")

    async def _metrics_handler(self, request):
        """Handle /metrics endpoint"""
        if not HAS_PROMETHEUS_CLIENT:
            return web.Response(text="Prometheus client not available", status=500)

        try:
            metrics_output = generate_latest(self.registry)
            return web.Response(
                body=metrics_output,
                content_type=CONTENT_TYPE_LATEST
            )
        except Exception as e:
            self.logger.error(f"Error generating metrics: {e}")
            return web.Response(text=f"Error: {e}", status=500)

    async def _health_handler(self, request):
        """Handle /health endpoint"""
        health_data = {
            'status': 'healthy' if self.running else 'unhealthy',
            'metrics_count': len(self.metrics),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        return web.json_response(health_data)

    async def _collection_loop(self):
        """Background task for collecting system metrics"""
        while self.running:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(30)  # Collect every 30 seconds
            except Exception as e:
                self.logger.error(f"Error in collection loop: {e}")
                await asyncio.sleep(30)

    async def _collect_system_metrics(self):
        """Collect system-level metrics"""
        try:
            # CPU metrics
            try:
                import psutil
                cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
                for i, percent in enumerate(cpu_percent):
                    self.set_gauge("cloudos_system_cpu_usage_percent", percent, {"cpu_core": str(i)})

                # Memory metrics
                memory = psutil.virtual_memory()
                self.set_gauge("cloudos_system_memory_usage_bytes", memory.total, {"type": "total"})
                self.set_gauge("cloudos_system_memory_usage_bytes", memory.used, {"type": "used"})
                self.set_gauge("cloudos_system_memory_usage_bytes", memory.free, {"type": "free"})
                self.set_gauge("cloudos_system_memory_usage_bytes", memory.cached, {"type": "cached"})

                # Disk metrics
                for partition in psutil.disk_partitions():
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        labels = {"device": partition.device, "mountpoint": partition.mountpoint}
                        self.set_gauge("cloudos_system_disk_usage_bytes", usage.total, {**labels, "type": "total"})
                        self.set_gauge("cloudos_system_disk_usage_bytes", usage.used, {**labels, "type": "used"})
                        self.set_gauge("cloudos_system_disk_usage_bytes", usage.free, {**labels, "type": "free"})
                    except PermissionError:
                        pass  # Skip inaccessible partitions

                # Network metrics
                network = psutil.net_io_counters(pernic=True)
                for interface, stats in network.items():
                    self.set_gauge("cloudos_system_network_bytes_total", stats.bytes_recv,
                                 {"interface": interface, "direction": "rx"})
                    self.set_gauge("cloudos_system_network_bytes_total", stats.bytes_sent,
                                 {"interface": interface, "direction": "tx"})

            except ImportError:
                self.logger.warning("psutil not available - system metrics disabled")

        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")

    async def _push_loop(self):
        """Background task for pushing metrics to Pushgateway"""
        if not self.pushgateway_url or not HAS_PROMETHEUS_CLIENT:
            return

        while self.running:
            try:
                # Push metrics to gateway
                push_to_gateway(
                    self.pushgateway_url,
                    job=self.job_name,
                    registry=self.registry
                )
                await asyncio.sleep(60)  # Push every minute
            except Exception as e:
                self.logger.error(f"Error pushing to gateway: {e}")
                await asyncio.sleep(60)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of collected metrics"""
        return {
            'metrics_count': len(self.metrics),
            'metric_definitions': list(self.metric_definitions.keys()),
            'running': self.running,
            'metrics_port': self.metrics_port,
            'pushgateway_configured': bool(self.pushgateway_url),
            'last_updated': datetime.now(timezone.utc).isoformat()
        }


class AlertManager:
    """
    Prometheus AlertManager integration
    Manages alert rules and notification routing
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.alert_rules: Dict[str, AlertRule] = {}
        self.prometheus_config_path = self.config.get('prometheus_config_path', '/etc/prometheus')

        # Initialize default alert rules
        self._initialize_default_alerts()

    def _initialize_default_alerts(self):
        """Initialize default CloudOS alert rules"""
        # System alerts
        self.add_alert_rule(AlertRule(
            name="HighCPUUsage",
            expression="cloudos_system_cpu_usage_percent > 90",
            duration="5m",
            severity=AlertSeverity.WARNING,
            summary="High CPU usage detected",
            description="CPU usage is above 90% for more than 5 minutes",
            labels={"team": "infrastructure"},
            annotations={"runbook": "https://docs.cloudos.dev/runbooks/high-cpu"}
        ))

        self.add_alert_rule(AlertRule(
            name="HighMemoryUsage",
            expression="(cloudos_system_memory_usage_bytes{type='used'} / cloudos_system_memory_usage_bytes{type='total'}) > 0.9",
            duration="5m",
            severity=AlertSeverity.WARNING,
            summary="High memory usage detected",
            description="Memory usage is above 90% for more than 5 minutes"
        ))

        self.add_alert_rule(AlertRule(
            name="DiskSpaceLow",
            expression="(cloudos_system_disk_usage_bytes{type='free'} / cloudos_system_disk_usage_bytes{type='total'}) < 0.1",
            duration="1m",
            severity=AlertSeverity.CRITICAL,
            summary="Disk space critically low",
            description="Less than 10% disk space remaining"
        ))

        # Container alerts
        self.add_alert_rule(AlertRule(
            name="ContainerHighRestarts",
            expression="increase(cloudos_container_restart_count[1h]) > 5",
            duration="1m",
            severity=AlertSeverity.WARNING,
            summary="Container restarting frequently",
            description="Container has restarted more than 5 times in the last hour"
        ))

        # AI Engine alerts
        self.add_alert_rule(AlertRule(
            name="AIInferenceFailureRate",
            expression="rate(cloudos_ai_inference_requests_total{status='failure'}[5m]) / rate(cloudos_ai_inference_requests_total[5m]) > 0.1",
            duration="2m",
            severity=AlertSeverity.WARNING,
            summary="High AI inference failure rate",
            description="AI inference failure rate is above 10%"
        ))

        # Security alerts
        self.add_alert_rule(AlertRule(
            name="HighAuthenticationFailures",
            expression="increase(cloudos_auth_attempts_total{result='failure'}[5m]) > 10",
            duration="1m",
            severity=AlertSeverity.CRITICAL,
            summary="High authentication failure rate",
            description="More than 10 authentication failures in 5 minutes - possible brute force attack"
        ))

        # Cluster alerts
        self.add_alert_rule(AlertRule(
            name="ClusterNodeDown",
            expression="cloudos_cluster_nodes_total{state='unhealthy'} > 0",
            duration="30s",
            severity=AlertSeverity.CRITICAL,
            summary="Cluster node is down",
            description="One or more cluster nodes are in unhealthy state"
        ))

    def add_alert_rule(self, alert_rule: AlertRule):
        """Add a new alert rule"""
        self.alert_rules[alert_rule.name] = alert_rule
        self.logger.debug(f"Added alert rule: {alert_rule.name}")

    def remove_alert_rule(self, rule_name: str):
        """Remove an alert rule"""
        if rule_name in self.alert_rules:
            del self.alert_rules[rule_name]
            self.logger.debug(f"Removed alert rule: {rule_name}")

    def generate_prometheus_rules(self) -> Dict[str, Any]:
        """Generate Prometheus alert rules configuration"""
        groups = [{
            "name": "cloudos_alerts",
            "rules": []
        }]

        for rule in self.alert_rules.values():
            prometheus_rule = {
                "alert": rule.name,
                "expr": rule.expression,
                "for": rule.duration,
                "labels": {
                    "severity": rule.severity.value,
                    **rule.labels
                },
                "annotations": {
                    "summary": rule.summary,
                    "description": rule.description,
                    **rule.annotations
                }
            }
            groups[0]["rules"].append(prometheus_rule)

        return {"groups": groups}

    def save_prometheus_rules(self, file_path: str = None):
        """Save alert rules to Prometheus rules file"""
        if not HAS_YAML:
            self.logger.error("YAML library not available - cannot save rules")
            return

        file_path = file_path or os.path.join(self.prometheus_config_path, "cloudos_alerts.yml")

        try:
            rules_config = self.generate_prometheus_rules()

            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                yaml.dump(rules_config, f, default_flow_style=False)

            self.logger.info(f"Saved {len(self.alert_rules)} alert rules to {file_path}")

        except Exception as e:
            self.logger.error(f"Failed to save alert rules: {e}")


class GrafanaDashboardManager:
    """
    Grafana dashboard management
    Creates and manages dashboards for CloudOS monitoring
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.dashboards: Dict[str, Dashboard] = {}
        self.grafana_url = self.config.get('grafana_url', 'http://localhost:3000')
        self.grafana_api_key = self.config.get('grafana_api_key')

        # Initialize default dashboards
        self._initialize_default_dashboards()

    def _initialize_default_dashboards(self):
        """Initialize default CloudOS dashboards"""
        # System Overview Dashboard
        system_dashboard = Dashboard(
            title="CloudOS System Overview",
            description="High-level system metrics and health overview",
            tags=["cloudos", "system", "overview"],
            panels=[
                DashboardPanel(
                    title="CPU Usage",
                    panel_type="graph",
                    query="cloudos_system_cpu_usage_percent",
                    unit="percent",
                    max_value=100,
                    thresholds=[{"value": 80, "color": "yellow"}, {"value": 90, "color": "red"}]
                ),
                DashboardPanel(
                    title="Memory Usage",
                    panel_type="graph",
                    query="cloudos_system_memory_usage_bytes{type='used'} / cloudos_system_memory_usage_bytes{type='total'} * 100",
                    unit="percent",
                    max_value=100,
                    thresholds=[{"value": 80, "color": "yellow"}, {"value": 90, "color": "red"}]
                ),
                DashboardPanel(
                    title="Disk Usage",
                    panel_type="table",
                    query="cloudos_system_disk_usage_bytes",
                    unit="bytes"
                ),
                DashboardPanel(
                    title="Network I/O",
                    panel_type="graph",
                    query="rate(cloudos_system_network_bytes_total[5m])",
                    unit="Bps"
                )
            ]
        )
        self.add_dashboard("system_overview", system_dashboard)

        # Container Dashboard
        container_dashboard = Dashboard(
            title="CloudOS Container Metrics",
            description="Container runtime metrics and statistics",
            tags=["cloudos", "containers"],
            panels=[
                DashboardPanel(
                    title="Container Count by State",
                    panel_type="stat",
                    query="cloudos_container_count",
                    unit="short"
                ),
                DashboardPanel(
                    title="Container CPU Usage",
                    panel_type="graph",
                    query="cloudos_container_cpu_usage_percent",
                    unit="percent",
                    max_value=100
                ),
                DashboardPanel(
                    title="Container Memory Usage",
                    panel_type="graph",
                    query="cloudos_container_memory_usage_bytes",
                    unit="bytes"
                ),
                DashboardPanel(
                    title="Container Restarts",
                    panel_type="graph",
                    query="rate(cloudos_container_restart_count[1h])",
                    unit="ops"
                )
            ]
        )
        self.add_dashboard("containers", container_dashboard)

        # AI Engine Dashboard
        ai_dashboard = Dashboard(
            title="CloudOS AI Engine Metrics",
            description="AI/ML workload performance and statistics",
            tags=["cloudos", "ai", "ml"],
            panels=[
                DashboardPanel(
                    title="Inference Requests Rate",
                    panel_type="graph",
                    query="rate(cloudos_ai_inference_requests_total[5m])",
                    unit="ops"
                ),
                DashboardPanel(
                    title="Inference Duration",
                    panel_type="graph",
                    query="histogram_quantile(0.95, rate(cloudos_ai_inference_duration_seconds_bucket[5m]))",
                    unit="s"
                ),
                DashboardPanel(
                    title="Loaded Models",
                    panel_type="stat",
                    query="cloudos_ai_model_loaded_count",
                    unit="short"
                ),
                DashboardPanel(
                    title="Error Rate",
                    panel_type="graph",
                    query="rate(cloudos_ai_inference_requests_total{status='failure'}[5m]) / rate(cloudos_ai_inference_requests_total[5m]) * 100",
                    unit="percent",
                    thresholds=[{"value": 5, "color": "yellow"}, {"value": 10, "color": "red"}]
                )
            ]
        )
        self.add_dashboard("ai_engine", ai_dashboard)

        # Security Dashboard
        security_dashboard = Dashboard(
            title="CloudOS Security Metrics",
            description="Security events, authentication, and threat detection",
            tags=["cloudos", "security"],
            panels=[
                DashboardPanel(
                    title="Security Events Rate",
                    panel_type="graph",
                    query="rate(cloudos_security_events_total[5m])",
                    unit="ops"
                ),
                DashboardPanel(
                    title="Authentication Success Rate",
                    panel_type="stat",
                    query="rate(cloudos_auth_attempts_total{result='success'}[5m]) / rate(cloudos_auth_attempts_total[5m]) * 100",
                    unit="percent",
                    min_value=0,
                    max_value=100
                ),
                DashboardPanel(
                    title="Active Sessions",
                    panel_type="stat",
                    query="cloudos_active_sessions",
                    unit="short"
                ),
                DashboardPanel(
                    title="Incidents by Severity",
                    panel_type="graph",
                    query="rate(cloudos_incidents_total[1h])",
                    unit="ops"
                )
            ]
        )
        self.add_dashboard("security", security_dashboard)

    def add_dashboard(self, dashboard_id: str, dashboard: Dashboard):
        """Add a new dashboard"""
        self.dashboards[dashboard_id] = dashboard
        self.logger.debug(f"Added dashboard: {dashboard.title}")

    def remove_dashboard(self, dashboard_id: str):
        """Remove a dashboard"""
        if dashboard_id in self.dashboards:
            del self.dashboards[dashboard_id]
            self.logger.debug(f"Removed dashboard: {dashboard_id}")

    def generate_grafana_dashboard(self, dashboard_id: str) -> Dict[str, Any]:
        """Generate Grafana dashboard JSON"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            return {}

        panels = []
        panel_id = 1

        for panel in dashboard.panels:
            grafana_panel = {
                "id": panel_id,
                "title": panel.title,
                "type": panel.panel_type,
                "targets": [{
                    "expr": panel.query,
                    "interval": "",
                    "legendFormat": "",
                    "refId": "A"
                }],
                "gridPos": {
                    "h": panel.height,
                    "w": panel.width,
                    "x": 0,
                    "y": (panel_id - 1) * panel.height
                },
                "fieldConfig": {
                    "defaults": {
                        "unit": panel.unit,
                        "min": panel.min_value,
                        "max": panel.max_value,
                        "thresholds": {
                            "steps": panel.thresholds
                        }
                    }
                }
            }
            panels.append(grafana_panel)
            panel_id += 1

        dashboard_json = {
            "dashboard": {
                "id": None,
                "title": dashboard.title,
                "description": dashboard.description,
                "tags": dashboard.tags,
                "panels": panels,
                "time": {
                    "from": f"now-{dashboard.time_range}",
                    "to": "now"
                },
                "refresh": dashboard.refresh_interval,
                "schemaVersion": 16,
                "version": 1
            },
            "overwrite": True
        }

        return dashboard_json

    async def upload_dashboard_to_grafana(self, dashboard_id: str) -> bool:
        """Upload dashboard to Grafana via API"""
        if not self.grafana_api_key or not HAS_AIOHTTP:
            self.logger.warning("Grafana API key or aiohttp not available")
            return False

        try:
            dashboard_json = self.generate_grafana_dashboard(dashboard_id)
            if not dashboard_json:
                return False

            headers = {
                'Authorization': f'Bearer {self.grafana_api_key}',
                'Content-Type': 'application/json'
            }

            async with ClientSession() as session:
                url = f"{self.grafana_url}/api/dashboards/db"
                async with session.post(url, json=dashboard_json, headers=headers) as response:
                    if response.status == 200:
                        self.logger.info(f"Successfully uploaded dashboard: {dashboard_id}")
                        return True
                    else:
                        error_text = await response.text()
                        self.logger.error(f"Failed to upload dashboard: {response.status} - {error_text}")
                        return False

        except Exception as e:
            self.logger.error(f"Error uploading dashboard to Grafana: {e}")
            return False

    def save_dashboard_json(self, dashboard_id: str, file_path: str = None):
        """Save dashboard JSON to file"""
        dashboard_json = self.generate_grafana_dashboard(dashboard_id)
        if not dashboard_json:
            return

        file_path = file_path or f"/tmp/cloudos_dashboard_{dashboard_id}.json"

        try:
            with open(file_path, 'w') as f:
                json.dump(dashboard_json, f, indent=2)

            self.logger.info(f"Saved dashboard JSON to {file_path}")

        except Exception as e:
            self.logger.error(f"Failed to save dashboard JSON: {e}")


class ObservabilityStack:
    """
    Complete observability stack for CloudOS
    Integrates metrics collection, alerting, and dashboards
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.metrics_collector = CloudOSMetricsCollector(self.config.get('metrics', {}))
        self.alert_manager = AlertManager(self.config.get('alerts', {}))
        self.dashboard_manager = GrafanaDashboardManager(self.config.get('dashboards', {}))

        # Integration callbacks
        self.metric_callbacks: List[Callable] = []

    async def start(self):
        """Start the complete observability stack"""
        # Start metrics collection
        await self.metrics_collector.start()

        # Generate and save alert rules
        self.alert_manager.save_prometheus_rules()

        # Upload dashboards to Grafana
        for dashboard_id in self.dashboard_manager.dashboards.keys():
            await self.dashboard_manager.upload_dashboard_to_grafana(dashboard_id)

        self.logger.info("Observability stack started")

    async def stop(self):
        """Stop the observability stack"""
        await self.metrics_collector.stop()
        self.logger.info("Observability stack stopped")

    def add_metric_callback(self, callback: Callable):
        """Add callback for custom metric collection"""
        self.metric_callbacks.append(callback)

    def record_container_metric(self, container_id: str, container_name: str, stats: Dict[str, Any]):
        """Record container metrics"""
        labels = {"container_id": container_id, "container_name": container_name}

        if 'cpu_usage_percent' in stats:
            self.metrics_collector.set_gauge("cloudos_container_cpu_usage_percent",
                                            stats['cpu_usage_percent'], labels)

        if 'memory_usage_bytes' in stats:
            self.metrics_collector.set_gauge("cloudos_container_memory_usage_bytes",
                                            stats['memory_usage_bytes'], labels)

    def record_ai_inference_metric(self, model_id: str, duration: float, success: bool):
        """Record AI inference metrics"""
        # Record request count
        status = "success" if success else "failure"
        self.metrics_collector.increment_counter("cloudos_ai_inference_requests_total",
                                                {"model_id": model_id, "status": status})

        # Record duration
        if success:
            self.metrics_collector.observe_histogram("cloudos_ai_inference_duration_seconds",
                                                    duration, {"model_id": model_id})

    def record_security_event(self, event_type: str, severity: str):
        """Record security event metric"""
        self.metrics_collector.increment_counter("cloudos_security_events_total",
                                                {"event_type": event_type, "severity": severity})

    def record_auth_attempt(self, success: bool):
        """Record authentication attempt"""
        result = "success" if success else "failure"
        self.metrics_collector.increment_counter("cloudos_auth_attempts_total", {"result": result})

    def get_observability_status(self) -> Dict[str, Any]:
        """Get status of observability stack"""
        return {
            'metrics': self.metrics_collector.get_metrics_summary(),
            'alert_rules': len(self.alert_manager.alert_rules),
            'dashboards': len(self.dashboard_manager.dashboards),
            'callbacks_registered': len(self.metric_callbacks),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


# Example usage
if __name__ == "__main__":
    async def test_observability():
        # Configure observability stack
        config = {
            'metrics': {
                'metrics_port': 9090,
                'job_name': 'cloudos-test'
            },
            'alerts': {
                'prometheus_config_path': '/tmp/prometheus'
            },
            'dashboards': {
                'grafana_url': 'http://localhost:3000'
            }
        }

        stack = ObservabilityStack(config)
        await stack.start()

        # Simulate some metrics
        stack.record_ai_inference_metric("test_model", 0.5, True)
        stack.record_container_metric("container123", "test-container", {
            'cpu_usage_percent': 45.2,
            'memory_usage_bytes': 128 * 1024 * 1024
        })
        stack.record_security_event("login_attempt", "info")
        stack.record_auth_attempt(True)

        # Get status
        status = stack.get_observability_status()
        print(f"Observability status: {json.dumps(status, indent=2)}")

        # Run for a while to collect metrics
        await asyncio.sleep(60)

        await stack.stop()

    asyncio.run(test_observability())