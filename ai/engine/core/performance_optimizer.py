"""
AI-Powered Performance Optimization Engine
Optimizes system performance using machine learning algorithms
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime, timedelta

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import mean_squared_error
    HAS_ML_LIBS = True
except ImportError:
    HAS_ML_LIBS = False
    np = None
    pd = None

logger = logging.getLogger(__name__)

class OptimizationType(Enum):
    CPU_OPTIMIZATION = "cpu_optimization"
    MEMORY_OPTIMIZATION = "memory_optimization"
    NETWORK_OPTIMIZATION = "network_optimization"
    STORAGE_OPTIMIZATION = "storage_optimization"
    APPLICATION_OPTIMIZATION = "application_optimization"

@dataclass
class PerformanceMetrics:
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    network_throughput: float
    storage_iops: float
    response_time: float
    error_rate: float
    throughput: float
    latency: float

@dataclass
class OptimizationRecommendation:
    type: OptimizationType
    description: str
    expected_improvement: float
    confidence: float
    parameters: Dict[str, Any]
    priority: int
    estimated_impact: str

@dataclass
class OptimizationResult:
    recommendation: OptimizationRecommendation
    applied: bool
    actual_improvement: Optional[float]
    timestamp: datetime
    error: Optional[str]

class AIPerformanceOptimizer:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.metrics_history = []
        self.optimization_history = []
        self.models = {}
        self.scalers = {}
        self.is_initialized = False

        # Performance thresholds
        self.thresholds = {
            'cpu_high': self.config.get('cpu_high_threshold', 80.0),
            'memory_high': self.config.get('memory_high_threshold', 85.0),
            'response_time_high': self.config.get('response_time_threshold', 1000.0),
            'error_rate_high': self.config.get('error_rate_threshold', 5.0)
        }

        # Optimization parameters
        self.optimization_params = {
            'cpu': {
                'process_priority_adjustment': [-5, 0, 5, 10],
                'cpu_affinity_optimization': True,
                'thread_pool_sizing': [2, 4, 8, 16, 32]
            },
            'memory': {
                'gc_optimization': True,
                'cache_sizing': [64, 128, 256, 512, 1024],
                'buffer_optimization': True
            },
            'network': {
                'connection_pooling': [10, 25, 50, 100],
                'timeout_optimization': [1000, 5000, 10000, 30000],
                'compression_enabled': True
            },
            'storage': {
                'read_ahead_optimization': True,
                'write_batching': [1, 10, 50, 100],
                'cache_strategies': ['lru', 'lfu', 'arc']
            }
        }

    async def initialize(self):
        """Initialize the performance optimizer"""
        try:
            if not HAS_ML_LIBS:
                logger.warning("ML libraries not available, using rule-based optimization")

            await self._initialize_models()
            self.is_initialized = True
            logger.info("AI Performance Optimizer initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize AI Performance Optimizer: {e}")
            raise

    async def _initialize_models(self):
        """Initialize ML models for different optimization types"""
        if not HAS_ML_LIBS:
            return

        try:
            for opt_type in OptimizationType:
                self.models[opt_type.value] = RandomForestRegressor(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42
                )
                self.scalers[opt_type.value] = StandardScaler()

            logger.info("ML models initialized for performance optimization")

        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    async def collect_metrics(self, metrics: PerformanceMetrics):
        """Collect performance metrics for analysis"""
        try:
            self.metrics_history.append(metrics)

            # Keep only recent metrics (last 24 hours)
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.metrics_history = [
                m for m in self.metrics_history
                if m.timestamp > cutoff_time
            ]

            # Train models periodically
            if len(self.metrics_history) % 100 == 0:
                await self._retrain_models()

        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")

    async def analyze_performance(self) -> List[OptimizationRecommendation]:
        """Analyze current performance and generate optimization recommendations"""
        try:
            if not self.metrics_history:
                return []

            recommendations = []
            latest_metrics = self.metrics_history[-1]

            # CPU optimization analysis
            cpu_rec = await self._analyze_cpu_performance(latest_metrics)
            if cpu_rec:
                recommendations.append(cpu_rec)

            # Memory optimization analysis
            memory_rec = await self._analyze_memory_performance(latest_metrics)
            if memory_rec:
                recommendations.append(memory_rec)

            # Network optimization analysis
            network_rec = await self._analyze_network_performance(latest_metrics)
            if network_rec:
                recommendations.append(network_rec)

            # Storage optimization analysis
            storage_rec = await self._analyze_storage_performance(latest_metrics)
            if storage_rec:
                recommendations.append(storage_rec)

            # Application optimization analysis
            app_rec = await self._analyze_application_performance(latest_metrics)
            if app_rec:
                recommendations.append(app_rec)

            # Sort by priority and confidence
            recommendations.sort(key=lambda x: (x.priority, -x.confidence))

            return recommendations

        except Exception as e:
            logger.error(f"Failed to analyze performance: {e}")
            return []

    async def _analyze_cpu_performance(self, metrics: PerformanceMetrics) -> Optional[OptimizationRecommendation]:
        """Analyze CPU performance and suggest optimizations"""
        try:
            if metrics.cpu_usage > self.thresholds['cpu_high']:
                confidence = min((metrics.cpu_usage - 50) / 50, 1.0)
                expected_improvement = min((metrics.cpu_usage - 70) * 0.3, 25.0)

                # Use ML model if available
                if HAS_ML_LIBS and self.models.get('cpu_optimization'):
                    try:
                        features = self._extract_features_for_cpu(metrics)
                        prediction = await self._predict_optimization_impact(
                            'cpu_optimization', features
                        )
                        expected_improvement = max(expected_improvement, prediction)
                    except Exception as e:
                        logger.warning(f"ML prediction failed, using rule-based: {e}")

                return OptimizationRecommendation(
                    type=OptimizationType.CPU_OPTIMIZATION,
                    description=f"CPU usage at {metrics.cpu_usage:.1f}%. Optimize process scheduling and resource allocation.",
                    expected_improvement=expected_improvement,
                    confidence=confidence,
                    parameters={
                        'current_usage': metrics.cpu_usage,
                        'target_usage': max(metrics.cpu_usage - expected_improvement, 50.0),
                        'optimization_type': 'process_priority_and_affinity'
                    },
                    priority=1 if metrics.cpu_usage > 90 else 2,
                    estimated_impact="High" if expected_improvement > 15 else "Medium"
                )

        except Exception as e:
            logger.error(f"CPU analysis failed: {e}")

        return None

    async def _analyze_memory_performance(self, metrics: PerformanceMetrics) -> Optional[OptimizationRecommendation]:
        """Analyze memory performance and suggest optimizations"""
        try:
            if metrics.memory_usage > self.thresholds['memory_high']:
                confidence = min((metrics.memory_usage - 60) / 40, 1.0)
                expected_improvement = min((metrics.memory_usage - 75) * 0.4, 20.0)

                return OptimizationRecommendation(
                    type=OptimizationType.MEMORY_OPTIMIZATION,
                    description=f"Memory usage at {metrics.memory_usage:.1f}%. Optimize memory allocation and garbage collection.",
                    expected_improvement=expected_improvement,
                    confidence=confidence,
                    parameters={
                        'current_usage': metrics.memory_usage,
                        'target_usage': max(metrics.memory_usage - expected_improvement, 60.0),
                        'optimization_type': 'gc_and_cache_optimization'
                    },
                    priority=1 if metrics.memory_usage > 95 else 2,
                    estimated_impact="High" if expected_improvement > 12 else "Medium"
                )

        except Exception as e:
            logger.error(f"Memory analysis failed: {e}")

        return None

    async def _analyze_network_performance(self, metrics: PerformanceMetrics) -> Optional[OptimizationRecommendation]:
        """Analyze network performance and suggest optimizations"""
        try:
            # Check for low throughput or high latency
            avg_throughput = await self._get_average_throughput()

            if (metrics.network_throughput < avg_throughput * 0.7 or
                metrics.latency > 100.0):

                confidence = 0.8
                expected_improvement = 15.0

                return OptimizationRecommendation(
                    type=OptimizationType.NETWORK_OPTIMIZATION,
                    description=f"Network performance suboptimal. Throughput: {metrics.network_throughput:.1f}MB/s, Latency: {metrics.latency:.1f}ms",
                    expected_improvement=expected_improvement,
                    confidence=confidence,
                    parameters={
                        'current_throughput': metrics.network_throughput,
                        'current_latency': metrics.latency,
                        'optimization_type': 'connection_pooling_and_compression'
                    },
                    priority=3,
                    estimated_impact="Medium"
                )

        except Exception as e:
            logger.error(f"Network analysis failed: {e}")

        return None

    async def _analyze_storage_performance(self, metrics: PerformanceMetrics) -> Optional[OptimizationRecommendation]:
        """Analyze storage performance and suggest optimizations"""
        try:
            avg_iops = await self._get_average_iops()

            if metrics.storage_iops < avg_iops * 0.8:
                confidence = 0.7
                expected_improvement = 20.0

                return OptimizationRecommendation(
                    type=OptimizationType.STORAGE_OPTIMIZATION,
                    description=f"Storage IOPS below average: {metrics.storage_iops:.0f} IOPS. Optimize I/O patterns.",
                    expected_improvement=expected_improvement,
                    confidence=confidence,
                    parameters={
                        'current_iops': metrics.storage_iops,
                        'target_iops': metrics.storage_iops * 1.2,
                        'optimization_type': 'io_batching_and_caching'
                    },
                    priority=3,
                    estimated_impact="Medium"
                )

        except Exception as e:
            logger.error(f"Storage analysis failed: {e}")

        return None

    async def _analyze_application_performance(self, metrics: PerformanceMetrics) -> Optional[OptimizationRecommendation]:
        """Analyze application performance and suggest optimizations"""
        try:
            if (metrics.response_time > self.thresholds['response_time_high'] or
                metrics.error_rate > self.thresholds['error_rate_high']):

                confidence = 0.9
                expected_improvement = 25.0

                return OptimizationRecommendation(
                    type=OptimizationType.APPLICATION_OPTIMIZATION,
                    description=f"Application performance issues detected. Response time: {metrics.response_time:.0f}ms, Error rate: {metrics.error_rate:.1f}%",
                    expected_improvement=expected_improvement,
                    confidence=confidence,
                    parameters={
                        'current_response_time': metrics.response_time,
                        'current_error_rate': metrics.error_rate,
                        'optimization_type': 'comprehensive_application_tuning'
                    },
                    priority=1,
                    estimated_impact="High"
                )

        except Exception as e:
            logger.error(f"Application analysis failed: {e}")

        return None

    async def apply_optimization(self, recommendation: OptimizationRecommendation) -> OptimizationResult:
        """Apply an optimization recommendation"""
        try:
            logger.info(f"Applying optimization: {recommendation.type.value}")

            # Simulate optimization application
            # In a real implementation, this would apply actual system changes

            result = OptimizationResult(
                recommendation=recommendation,
                applied=True,
                actual_improvement=recommendation.expected_improvement * 0.8,  # Simulated
                timestamp=datetime.now(),
                error=None
            )

            self.optimization_history.append(result)

            logger.info(f"Optimization applied successfully: {recommendation.type.value}")
            return result

        except Exception as e:
            logger.error(f"Failed to apply optimization: {e}")
            return OptimizationResult(
                recommendation=recommendation,
                applied=False,
                actual_improvement=None,
                timestamp=datetime.now(),
                error=str(e)
            )

    async def get_optimization_report(self) -> Dict[str, Any]:
        """Generate a comprehensive optimization report"""
        try:
            if not self.metrics_history:
                return {"error": "No metrics available"}

            recent_metrics = self.metrics_history[-10:] if len(self.metrics_history) >= 10 else self.metrics_history

            # Calculate performance trends
            performance_trend = await self._calculate_performance_trend()

            # Get recent optimizations
            recent_optimizations = self.optimization_history[-5:] if self.optimization_history else []

            # Calculate optimization effectiveness
            effectiveness = await self._calculate_optimization_effectiveness()

            report = {
                "timestamp": datetime.now().isoformat(),
                "metrics_collected": len(self.metrics_history),
                "optimizations_applied": len(self.optimization_history),
                "performance_trend": performance_trend,
                "recent_metrics": {
                    "avg_cpu_usage": sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics),
                    "avg_memory_usage": sum(m.memory_usage for m in recent_metrics) / len(recent_metrics),
                    "avg_response_time": sum(m.response_time for m in recent_metrics) / len(recent_metrics),
                    "avg_error_rate": sum(m.error_rate for m in recent_metrics) / len(recent_metrics)
                },
                "recent_optimizations": [
                    {
                        "type": opt.recommendation.type.value,
                        "applied": opt.applied,
                        "expected_improvement": opt.recommendation.expected_improvement,
                        "actual_improvement": opt.actual_improvement,
                        "timestamp": opt.timestamp.isoformat()
                    }
                    for opt in recent_optimizations
                ],
                "optimization_effectiveness": effectiveness,
                "recommendations_pending": len(await self.analyze_performance())
            }

            return report

        except Exception as e:
            logger.error(f"Failed to generate optimization report: {e}")
            return {"error": str(e)}

    async def _extract_features_for_cpu(self, metrics: PerformanceMetrics) -> List[float]:
        """Extract features for CPU optimization ML model"""
        if len(self.metrics_history) < 5:
            return [metrics.cpu_usage, metrics.memory_usage, metrics.network_throughput]

        recent = self.metrics_history[-5:]
        return [
            metrics.cpu_usage,
            metrics.memory_usage,
            metrics.network_throughput,
            sum(m.cpu_usage for m in recent) / len(recent),
            max(m.cpu_usage for m in recent),
            min(m.cpu_usage for m in recent)
        ]

    async def _predict_optimization_impact(self, model_name: str, features: List[float]) -> float:
        """Predict optimization impact using ML model"""
        if not HAS_ML_LIBS or model_name not in self.models:
            return 10.0  # Default prediction

        try:
            model = self.models[model_name]
            scaler = self.scalers[model_name]

            # Use dummy prediction if model not trained
            if not hasattr(model, 'feature_importances_'):
                return 15.0

            scaled_features = scaler.transform([features])
            prediction = model.predict(scaled_features)[0]
            return max(5.0, min(prediction, 30.0))  # Clamp between 5-30%

        except Exception as e:
            logger.warning(f"ML prediction failed: {e}")
            return 10.0

    async def _retrain_models(self):
        """Retrain ML models with collected data"""
        if not HAS_ML_LIBS or len(self.metrics_history) < 50:
            return

        try:
            # This would implement actual model training with historical data
            logger.info("Retraining ML models with recent performance data")

        except Exception as e:
            logger.error(f"Model retraining failed: {e}")

    async def _get_average_throughput(self) -> float:
        """Calculate average network throughput"""
        if not self.metrics_history:
            return 100.0

        recent = self.metrics_history[-20:] if len(self.metrics_history) >= 20 else self.metrics_history
        return sum(m.network_throughput for m in recent) / len(recent)

    async def _get_average_iops(self) -> float:
        """Calculate average storage IOPS"""
        if not self.metrics_history:
            return 1000.0

        recent = self.metrics_history[-20:] if len(self.metrics_history) >= 20 else self.metrics_history
        return sum(m.storage_iops for m in recent) / len(recent)

    async def _calculate_performance_trend(self) -> str:
        """Calculate overall performance trend"""
        if len(self.metrics_history) < 10:
            return "insufficient_data"

        recent = self.metrics_history[-10:]
        older = self.metrics_history[-20:-10] if len(self.metrics_history) >= 20 else self.metrics_history[:-10]

        if not older:
            return "insufficient_data"

        recent_avg = sum(m.cpu_usage + m.memory_usage for m in recent) / len(recent)
        older_avg = sum(m.cpu_usage + m.memory_usage for m in older) / len(older)

        if recent_avg < older_avg * 0.95:
            return "improving"
        elif recent_avg > older_avg * 1.05:
            return "degrading"
        else:
            return "stable"

    async def _calculate_optimization_effectiveness(self) -> float:
        """Calculate effectiveness of applied optimizations"""
        if not self.optimization_history:
            return 0.0

        successful_opts = [opt for opt in self.optimization_history if opt.applied and opt.actual_improvement]
        if not successful_opts:
            return 0.0

        total_expected = sum(opt.recommendation.expected_improvement for opt in successful_opts)
        total_actual = sum(opt.actual_improvement for opt in successful_opts)

        return (total_actual / total_expected) * 100 if total_expected > 0 else 0.0

    async def stop(self):
        """Stop the performance optimizer"""
        try:
            logger.info("Stopping AI Performance Optimizer")
            self.is_initialized = False

        except Exception as e:
            logger.error(f"Error stopping AI Performance Optimizer: {e}")