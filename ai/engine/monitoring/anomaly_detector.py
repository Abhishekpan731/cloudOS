"""
AI-Powered Anomaly Detection and Monitoring System
Detects anomalies in system behavior using machine learning algorithms
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime, timedelta
import statistics
import math

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    from sklearn.decomposition import PCA
    HAS_ML_LIBS = True
except ImportError:
    HAS_ML_LIBS = False
    np = None
    pd = None

logger = logging.getLogger(__name__)

class AnomalyType(Enum):
    PERFORMANCE_ANOMALY = "performance_anomaly"
    RESOURCE_ANOMALY = "resource_anomaly"
    NETWORK_ANOMALY = "network_anomaly"
    SECURITY_ANOMALY = "security_anomaly"
    APPLICATION_ANOMALY = "application_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"

class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SystemMetrics:
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_in: float
    network_out: float
    active_connections: int
    process_count: int
    load_average: float
    response_time: float
    error_rate: float
    throughput: float

@dataclass
class AnomalyAlert:
    id: str
    type: AnomalyType
    severity: SeverityLevel
    timestamp: datetime
    description: str
    affected_metrics: List[str]
    confidence_score: float
    baseline_value: Optional[float]
    current_value: float
    deviation_percentage: float
    suggested_actions: List[str]
    metadata: Dict[str, Any]

@dataclass
class AnomalyPattern:
    pattern_id: str
    pattern_type: str
    occurrences: int
    first_seen: datetime
    last_seen: datetime
    avg_confidence: float
    metrics_involved: List[str]
    description: str

class AIAnomalyDetector:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.metrics_history = []
        self.anomaly_history = []
        self.patterns = {}
        self.models = {}
        self.scalers = {}
        self.baselines = {}
        self.is_initialized = False

        # Detection parameters
        self.detection_params = {
            'window_size': self.config.get('window_size', 100),
            'sensitivity': self.config.get('sensitivity', 0.8),
            'contamination': self.config.get('contamination', 0.1),
            'min_samples': self.config.get('min_samples', 50),
            'statistical_threshold': self.config.get('statistical_threshold', 3.0)
        }

        # Alerting thresholds
        self.alert_thresholds = {
            'cpu_usage': {'high': 85.0, 'critical': 95.0},
            'memory_usage': {'high': 80.0, 'critical': 90.0},
            'disk_usage': {'high': 85.0, 'critical': 95.0},
            'response_time': {'high': 1000.0, 'critical': 5000.0},
            'error_rate': {'high': 5.0, 'critical': 10.0}
        }

    async def initialize(self):
        """Initialize the anomaly detection system"""
        try:
            if not HAS_ML_LIBS:
                logger.warning("ML libraries not available, using statistical methods only")

            await self._initialize_models()
            await self._load_baseline_patterns()
            self.is_initialized = True
            logger.info("AI Anomaly Detector initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize AI Anomaly Detector: {e}")
            raise

    async def _initialize_models(self):
        """Initialize ML models for anomaly detection"""
        if not HAS_ML_LIBS:
            return

        try:
            # Isolation Forest for general anomaly detection
            self.models['isolation_forest'] = IsolationForest(
                contamination=self.detection_params['contamination'],
                random_state=42,
                n_estimators=100
            )

            # DBSCAN for clustering-based anomaly detection
            self.models['dbscan'] = DBSCAN(
                eps=0.5,
                min_samples=self.detection_params['min_samples']
            )

            # PCA for dimensionality reduction
            self.models['pca'] = PCA(n_components=0.95, random_state=42)

            # Standard scaler for normalization
            self.scalers['main'] = StandardScaler()

            logger.info("ML models initialized for anomaly detection")

        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    async def _load_baseline_patterns(self):
        """Load baseline patterns for comparison"""
        try:
            # Initialize baseline patterns
            self.baselines = {
                'cpu_usage': {'mean': 45.0, 'std': 15.0},
                'memory_usage': {'mean': 60.0, 'std': 20.0},
                'disk_usage': {'mean': 40.0, 'std': 10.0},
                'response_time': {'mean': 200.0, 'std': 50.0},
                'error_rate': {'mean': 1.0, 'std': 0.5},
                'throughput': {'mean': 1000.0, 'std': 200.0}
            }

            logger.info("Baseline patterns loaded successfully")

        except Exception as e:
            logger.error(f"Failed to load baseline patterns: {e}")

    async def ingest_metrics(self, metrics: SystemMetrics):
        """Ingest system metrics for anomaly detection"""
        try:
            self.metrics_history.append(metrics)

            # Keep only recent metrics
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.metrics_history = [
                m for m in self.metrics_history
                if m.timestamp > cutoff_time
            ]

            # Update baselines periodically
            if len(self.metrics_history) % 100 == 0:
                await self._update_baselines()

            # Perform real-time anomaly detection
            if len(self.metrics_history) >= self.detection_params['min_samples']:
                anomalies = await self.detect_anomalies([metrics])
                if anomalies:
                    await self._handle_real_time_anomalies(anomalies)

        except Exception as e:
            logger.error(f"Failed to ingest metrics: {e}")

    async def detect_anomalies(self, metrics_batch: List[SystemMetrics] = None) -> List[AnomalyAlert]:
        """Detect anomalies in system metrics"""
        try:
            if not self.is_initialized:
                await self.initialize()

            if metrics_batch is None:
                if len(self.metrics_history) < self.detection_params['min_samples']:
                    return []
                metrics_batch = self.metrics_history[-self.detection_params['window_size']:]

            anomalies = []

            # Statistical anomaly detection
            statistical_anomalies = await self._detect_statistical_anomalies(metrics_batch)
            anomalies.extend(statistical_anomalies)

            # ML-based anomaly detection
            if HAS_ML_LIBS:
                ml_anomalies = await self._detect_ml_anomalies(metrics_batch)
                anomalies.extend(ml_anomalies)

            # Pattern-based anomaly detection
            pattern_anomalies = await self._detect_pattern_anomalies(metrics_batch)
            anomalies.extend(pattern_anomalies)

            # Remove duplicates and sort by severity
            unique_anomalies = await self._deduplicate_anomalies(anomalies)
            sorted_anomalies = sorted(unique_anomalies, key=lambda x: self._severity_score(x.severity), reverse=True)

            # Store anomalies
            self.anomaly_history.extend(sorted_anomalies)

            # Update patterns
            await self._update_anomaly_patterns(sorted_anomalies)

            return sorted_anomalies

        except Exception as e:
            logger.error(f"Failed to detect anomalies: {e}")
            return []

    async def _detect_statistical_anomalies(self, metrics_batch: List[SystemMetrics]) -> List[AnomalyAlert]:
        """Detect anomalies using statistical methods"""
        try:
            anomalies = []

            if len(metrics_batch) < 10:
                return anomalies

            latest_metrics = metrics_batch[-1]
            historical_data = metrics_batch[:-1]

            # Check each metric for statistical anomalies
            metrics_to_check = [
                ('cpu_usage', latest_metrics.cpu_usage),
                ('memory_usage', latest_metrics.memory_usage),
                ('disk_usage', latest_metrics.disk_usage),
                ('response_time', latest_metrics.response_time),
                ('error_rate', latest_metrics.error_rate),
                ('throughput', latest_metrics.throughput)
            ]

            for metric_name, current_value in metrics_to_check:
                historical_values = [getattr(m, metric_name) for m in historical_data]

                if len(historical_values) < 5:
                    continue

                # Calculate statistical measures
                mean_val = statistics.mean(historical_values)
                std_val = statistics.stdev(historical_values) if len(historical_values) > 1 else 1.0
                z_score = abs(current_value - mean_val) / std_val if std_val > 0 else 0

                # Detect anomaly based on z-score
                if z_score > self.detection_params['statistical_threshold']:
                    severity = self._determine_severity(metric_name, current_value, z_score)

                    anomaly = AnomalyAlert(
                        id=f"stat_{metric_name}_{int(latest_metrics.timestamp.timestamp())}",
                        type=self._get_anomaly_type(metric_name),
                        severity=severity,
                        timestamp=latest_metrics.timestamp,
                        description=f"Statistical anomaly detected in {metric_name}",
                        affected_metrics=[metric_name],
                        confidence_score=min(z_score / 5.0, 1.0),
                        baseline_value=mean_val,
                        current_value=current_value,
                        deviation_percentage=((current_value - mean_val) / mean_val) * 100 if mean_val > 0 else 0,
                        suggested_actions=self._get_suggested_actions(metric_name, current_value),
                        metadata={
                            'detection_method': 'statistical',
                            'z_score': z_score,
                            'mean': mean_val,
                            'std': std_val
                        }
                    )
                    anomalies.append(anomaly)

            return anomalies

        except Exception as e:
            logger.error(f"Statistical anomaly detection failed: {e}")
            return []

    async def _detect_ml_anomalies(self, metrics_batch: List[SystemMetrics]) -> List[AnomalyAlert]:
        """Detect anomalies using machine learning models"""
        if not HAS_ML_LIBS:
            return []

        try:
            anomalies = []

            if len(metrics_batch) < self.detection_params['min_samples']:
                return anomalies

            # Prepare data for ML models
            features = await self._extract_features(metrics_batch)
            if len(features) < 10:
                return anomalies

            # Isolation Forest detection
            try:
                isolation_model = self.models['isolation_forest']

                # Fit model if not already fitted
                if not hasattr(isolation_model, 'decision_function'):
                    isolation_model.fit(features)

                # Detect anomalies
                outlier_scores = isolation_model.decision_function(features)
                outliers = isolation_model.predict(features)

                # Process outliers
                for i, (score, is_outlier) in enumerate(zip(outlier_scores, outliers)):
                    if is_outlier == -1:  # Anomaly detected
                        metrics_idx = len(metrics_batch) - len(outlier_scores) + i
                        if metrics_idx >= 0 and metrics_idx < len(metrics_batch):
                            affected_metrics = metrics_batch[metrics_idx]

                            anomaly = AnomalyAlert(
                                id=f"ml_iso_{int(affected_metrics.timestamp.timestamp())}",
                                type=AnomalyType.BEHAVIORAL_ANOMALY,
                                severity=SeverityLevel.MEDIUM,
                                timestamp=affected_metrics.timestamp,
                                description="ML-based behavioral anomaly detected",
                                affected_metrics=['multiple'],
                                confidence_score=abs(score),
                                baseline_value=None,
                                current_value=score,
                                deviation_percentage=0.0,
                                suggested_actions=['Investigate system behavior', 'Check for unusual patterns'],
                                metadata={
                                    'detection_method': 'isolation_forest',
                                    'outlier_score': score
                                }
                            )
                            anomalies.append(anomaly)

            except Exception as e:
                logger.warning(f"Isolation Forest detection failed: {e}")

            return anomalies

        except Exception as e:
            logger.error(f"ML anomaly detection failed: {e}")
            return []

    async def _detect_pattern_anomalies(self, metrics_batch: List[SystemMetrics]) -> List[AnomalyAlert]:
        """Detect anomalies based on known patterns"""
        try:
            anomalies = []

            if len(metrics_batch) < 5:
                return anomalies

            latest_metrics = metrics_batch[-1]

            # Check for known anomaly patterns

            # Pattern 1: High CPU with low throughput (possible bottleneck)
            if (latest_metrics.cpu_usage > 80.0 and
                latest_metrics.throughput < 500.0):

                anomaly = AnomalyAlert(
                    id=f"pattern_cpu_bottleneck_{int(latest_metrics.timestamp.timestamp())}",
                    type=AnomalyType.PERFORMANCE_ANOMALY,
                    severity=SeverityLevel.HIGH,
                    timestamp=latest_metrics.timestamp,
                    description="CPU bottleneck pattern detected: High CPU usage with low throughput",
                    affected_metrics=['cpu_usage', 'throughput'],
                    confidence_score=0.9,
                    baseline_value=500.0,
                    current_value=latest_metrics.throughput,
                    deviation_percentage=((500.0 - latest_metrics.throughput) / 500.0) * 100,
                    suggested_actions=[
                        'Check for CPU-intensive processes',
                        'Optimize application algorithms',
                        'Consider horizontal scaling'
                    ],
                    metadata={'pattern_type': 'cpu_bottleneck'}
                )
                anomalies.append(anomaly)

            # Pattern 2: Memory leak detection
            if len(metrics_batch) >= 10:
                memory_trend = [m.memory_usage for m in metrics_batch[-10:]]
                if len(memory_trend) >= 5 and self._is_increasing_trend(memory_trend, threshold=0.8):
                    anomaly = AnomalyAlert(
                        id=f"pattern_memory_leak_{int(latest_metrics.timestamp.timestamp())}",
                        type=AnomalyType.RESOURCE_ANOMALY,
                        severity=SeverityLevel.HIGH,
                        timestamp=latest_metrics.timestamp,
                        description="Potential memory leak detected: Continuous memory usage increase",
                        affected_metrics=['memory_usage'],
                        confidence_score=0.85,
                        baseline_value=memory_trend[0],
                        current_value=memory_trend[-1],
                        deviation_percentage=((memory_trend[-1] - memory_trend[0]) / memory_trend[0]) * 100,
                        suggested_actions=[
                            'Check for memory leaks in applications',
                            'Restart affected services',
                            'Monitor garbage collection'
                        ],
                        metadata={'pattern_type': 'memory_leak', 'trend_data': memory_trend}
                    )
                    anomalies.append(anomaly)

            # Pattern 3: Network anomaly (unusual traffic patterns)
            recent_network_in = [m.network_in for m in metrics_batch[-5:]]
            recent_network_out = [m.network_out for m in metrics_batch[-5:]]

            if (max(recent_network_in) > statistics.mean(recent_network_in) * 3 or
                max(recent_network_out) > statistics.mean(recent_network_out) * 3):

                anomaly = AnomalyAlert(
                    id=f"pattern_network_spike_{int(latest_metrics.timestamp.timestamp())}",
                    type=AnomalyType.NETWORK_ANOMALY,
                    severity=SeverityLevel.MEDIUM,
                    timestamp=latest_metrics.timestamp,
                    description="Network traffic spike detected",
                    affected_metrics=['network_in', 'network_out'],
                    confidence_score=0.8,
                    baseline_value=statistics.mean(recent_network_in + recent_network_out),
                    current_value=latest_metrics.network_in + latest_metrics.network_out,
                    deviation_percentage=200.0,  # Spike indicates 3x increase
                    suggested_actions=[
                        'Check for DDoS attacks',
                        'Analyze network traffic patterns',
                        'Verify application behavior'
                    ],
                    metadata={'pattern_type': 'network_spike'}
                )
                anomalies.append(anomaly)

            return anomalies

        except Exception as e:
            logger.error(f"Pattern anomaly detection failed: {e}")
            return []

    async def _extract_features(self, metrics_batch: List[SystemMetrics]) -> List[List[float]]:
        """Extract features from metrics for ML analysis"""
        try:
            features = []

            for metrics in metrics_batch:
                feature_vector = [
                    metrics.cpu_usage,
                    metrics.memory_usage,
                    metrics.disk_usage,
                    metrics.network_in,
                    metrics.network_out,
                    float(metrics.active_connections),
                    float(metrics.process_count),
                    metrics.load_average,
                    metrics.response_time,
                    metrics.error_rate,
                    metrics.throughput
                ]
                features.append(feature_vector)

            return features

        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return []

    def _get_anomaly_type(self, metric_name: str) -> AnomalyType:
        """Determine anomaly type based on metric name"""
        type_mapping = {
            'cpu_usage': AnomalyType.PERFORMANCE_ANOMALY,
            'memory_usage': AnomalyType.RESOURCE_ANOMALY,
            'disk_usage': AnomalyType.RESOURCE_ANOMALY,
            'network_in': AnomalyType.NETWORK_ANOMALY,
            'network_out': AnomalyType.NETWORK_ANOMALY,
            'response_time': AnomalyType.PERFORMANCE_ANOMALY,
            'error_rate': AnomalyType.APPLICATION_ANOMALY,
            'throughput': AnomalyType.PERFORMANCE_ANOMALY
        }
        return type_mapping.get(metric_name, AnomalyType.BEHAVIORAL_ANOMALY)

    def _determine_severity(self, metric_name: str, current_value: float, z_score: float) -> SeverityLevel:
        """Determine severity level based on metric and z-score"""
        thresholds = self.alert_thresholds.get(metric_name, {})

        if z_score > 5.0 or current_value > thresholds.get('critical', float('inf')):
            return SeverityLevel.CRITICAL
        elif z_score > 4.0 or current_value > thresholds.get('high', float('inf')):
            return SeverityLevel.HIGH
        elif z_score > 3.5:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def _get_suggested_actions(self, metric_name: str, current_value: float) -> List[str]:
        """Get suggested actions based on metric and value"""
        action_mapping = {
            'cpu_usage': [
                'Check for high CPU processes',
                'Consider scaling horizontally',
                'Optimize application performance'
            ],
            'memory_usage': [
                'Check for memory leaks',
                'Restart affected services',
                'Increase memory allocation'
            ],
            'disk_usage': [
                'Clean up temporary files',
                'Archive old data',
                'Expand storage capacity'
            ],
            'response_time': [
                'Check application performance',
                'Optimize database queries',
                'Review system load'
            ],
            'error_rate': [
                'Check application logs',
                'Review recent deployments',
                'Monitor service dependencies'
            ]
        }
        return action_mapping.get(metric_name, ['Investigate further', 'Monitor closely'])

    def _is_increasing_trend(self, values: List[float], threshold: float = 0.8) -> bool:
        """Check if values show an increasing trend"""
        if len(values) < 3:
            return False

        increases = 0
        total_comparisons = len(values) - 1

        for i in range(1, len(values)):
            if values[i] > values[i-1]:
                increases += 1

        return (increases / total_comparisons) >= threshold

    def _severity_score(self, severity: SeverityLevel) -> int:
        """Convert severity to numeric score for sorting"""
        score_mapping = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1
        }
        return score_mapping.get(severity, 1)

    async def _deduplicate_anomalies(self, anomalies: List[AnomalyAlert]) -> List[AnomalyAlert]:
        """Remove duplicate anomalies based on type and affected metrics"""
        try:
            seen = set()
            unique_anomalies = []

            for anomaly in anomalies:
                key = (anomaly.type.value, frozenset(anomaly.affected_metrics))
                if key not in seen:
                    seen.add(key)
                    unique_anomalies.append(anomaly)

            return unique_anomalies

        except Exception as e:
            logger.error(f"Deduplication failed: {e}")
            return anomalies

    async def _handle_real_time_anomalies(self, anomalies: List[AnomalyAlert]):
        """Handle real-time anomaly detection"""
        try:
            for anomaly in anomalies:
                if anomaly.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                    logger.warning(f"High severity anomaly detected: {anomaly.description}")
                    # In a real implementation, this would trigger alerts/notifications

        except Exception as e:
            logger.error(f"Real-time anomaly handling failed: {e}")

    async def _update_baselines(self):
        """Update baseline metrics from recent data"""
        try:
            if len(self.metrics_history) < 100:
                return

            recent_metrics = self.metrics_history[-100:]

            # Update baselines for each metric
            metrics_to_update = [
                'cpu_usage', 'memory_usage', 'disk_usage',
                'response_time', 'error_rate', 'throughput'
            ]

            for metric_name in metrics_to_update:
                values = [getattr(m, metric_name) for m in recent_metrics]
                if values:
                    self.baselines[metric_name] = {
                        'mean': statistics.mean(values),
                        'std': statistics.stdev(values) if len(values) > 1 else 1.0
                    }

            logger.debug("Baselines updated with recent data")

        except Exception as e:
            logger.error(f"Baseline update failed: {e}")

    async def _update_anomaly_patterns(self, anomalies: List[AnomalyAlert]):
        """Update known anomaly patterns"""
        try:
            for anomaly in anomalies:
                pattern_key = f"{anomaly.type.value}_{hash(tuple(sorted(anomaly.affected_metrics)))}"

                if pattern_key in self.patterns:
                    pattern = self.patterns[pattern_key]
                    pattern.occurrences += 1
                    pattern.last_seen = anomaly.timestamp
                    pattern.avg_confidence = (pattern.avg_confidence + anomaly.confidence_score) / 2
                else:
                    self.patterns[pattern_key] = AnomalyPattern(
                        pattern_id=pattern_key,
                        pattern_type=anomaly.type.value,
                        occurrences=1,
                        first_seen=anomaly.timestamp,
                        last_seen=anomaly.timestamp,
                        avg_confidence=anomaly.confidence_score,
                        metrics_involved=anomaly.affected_metrics,
                        description=anomaly.description
                    )

        except Exception as e:
            logger.error(f"Pattern update failed: {e}")

    async def get_anomaly_report(self) -> Dict[str, Any]:
        """Generate comprehensive anomaly detection report"""
        try:
            recent_anomalies = [a for a in self.anomaly_history
                             if a.timestamp > datetime.now() - timedelta(hours=24)]

            severity_counts = {
                'critical': len([a for a in recent_anomalies if a.severity == SeverityLevel.CRITICAL]),
                'high': len([a for a in recent_anomalies if a.severity == SeverityLevel.HIGH]),
                'medium': len([a for a in recent_anomalies if a.severity == SeverityLevel.MEDIUM]),
                'low': len([a for a in recent_anomalies if a.severity == SeverityLevel.LOW])
            }

            type_counts = {}
            for anomaly_type in AnomalyType:
                type_counts[anomaly_type.value] = len([a for a in recent_anomalies if a.type == anomaly_type])

            report = {
                "timestamp": datetime.now().isoformat(),
                "total_anomalies_detected": len(self.anomaly_history),
                "recent_anomalies": len(recent_anomalies),
                "severity_distribution": severity_counts,
                "type_distribution": type_counts,
                "patterns_identified": len(self.patterns),
                "detection_methods": {
                    "statistical": True,
                    "machine_learning": HAS_ML_LIBS,
                    "pattern_based": True
                },
                "recent_alerts": [
                    {
                        "id": a.id,
                        "type": a.type.value,
                        "severity": a.severity.value,
                        "description": a.description,
                        "timestamp": a.timestamp.isoformat(),
                        "confidence": a.confidence_score
                    }
                    for a in recent_anomalies[-10:]  # Last 10 anomalies
                ],
                "top_patterns": [
                    {
                        "pattern_id": p.pattern_id,
                        "type": p.pattern_type,
                        "occurrences": p.occurrences,
                        "avg_confidence": p.avg_confidence,
                        "description": p.description
                    }
                    for p in sorted(self.patterns.values(), key=lambda x: x.occurrences, reverse=True)[:5]
                ]
            }

            return report

        except Exception as e:
            logger.error(f"Failed to generate anomaly report: {e}")
            return {"error": str(e)}

    async def stop(self):
        """Stop the anomaly detection system"""
        try:
            logger.info("Stopping AI Anomaly Detector")
            self.is_initialized = False

        except Exception as e:
            logger.error(f"Error stopping AI Anomaly Detector: {e}")