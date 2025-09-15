"""
AI-Powered Cost Optimization Engine
Optimizes cloud infrastructure costs using machine learning algorithms
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime, timedelta
import statistics

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.linear_model import LinearRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import KMeans
    HAS_ML_LIBS = True
except ImportError:
    HAS_ML_LIBS = False
    np = None
    pd = None

logger = logging.getLogger(__name__)

class OptimizationStrategy(Enum):
    RIGHT_SIZING = "right_sizing"
    RESERVED_INSTANCES = "reserved_instances"
    SPOT_INSTANCES = "spot_instances"
    SCHEDULED_SCALING = "scheduled_scaling"
    AUTO_SHUTDOWN = "auto_shutdown"
    STORAGE_OPTIMIZATION = "storage_optimization"
    NETWORK_OPTIMIZATION = "network_optimization"

class ResourceType(Enum):
    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    CONTAINER = "container"

class CostImpact(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ResourceUsage:
    resource_id: str
    resource_type: ResourceType
    timestamp: datetime
    cpu_utilization: float
    memory_utilization: float
    storage_utilization: float
    network_utilization: float
    cost_per_hour: float
    actual_usage_hours: float
    idle_time_percentage: float

@dataclass
class CostOptimizationRecommendation:
    id: str
    strategy: OptimizationStrategy
    resource_id: str
    resource_type: ResourceType
    description: str
    current_cost: float
    projected_cost: float
    savings_amount: float
    savings_percentage: float
    confidence_score: float
    impact: CostImpact
    implementation_effort: str
    risk_level: str
    timeline: str
    prerequisites: List[str]
    metadata: Dict[str, Any]

@dataclass
class CostForecast:
    period: str
    projected_cost: float
    confidence_interval: Tuple[float, float]
    cost_drivers: List[str]
    optimization_potential: float
    forecast_date: datetime

@dataclass
class BudgetAlert:
    alert_id: str
    budget_name: str
    current_spend: float
    budget_limit: float
    percentage_used: float
    projected_overspend: float
    alert_level: str
    timestamp: datetime

class AICostOptimizer:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.usage_history = []
        self.cost_history = []
        self.optimization_history = []
        self.models = {}
        self.scalers = {}
        self.resource_clusters = {}
        self.is_initialized = False

        # Optimization parameters
        self.optimization_params = {
            'utilization_threshold_low': self.config.get('util_threshold_low', 20.0),
            'utilization_threshold_high': self.config.get('util_threshold_high', 80.0),
            'idle_threshold': self.config.get('idle_threshold', 70.0),
            'cost_saving_threshold': self.config.get('cost_saving_threshold', 10.0),
            'forecast_horizon_days': self.config.get('forecast_horizon', 30)
        }

        # Cost thresholds for different resource types
        self.cost_thresholds = {
            ResourceType.COMPUTE: {
                'hourly_waste': 0.10,  # $0.10/hour
                'daily_waste': 2.40,   # $2.40/day
                'monthly_waste': 72.0  # $72/month
            },
            ResourceType.STORAGE: {
                'monthly_waste_gb': 0.023,  # $0.023/GB/month
                'unused_threshold': 50.0     # 50% unused
            },
            ResourceType.DATABASE: {
                'hourly_waste': 0.50,
                'idle_threshold': 80.0
            }
        }

    async def initialize(self):
        """Initialize the cost optimization engine"""
        try:
            if not HAS_ML_LIBS:
                logger.warning("ML libraries not available, using rule-based optimization")

            await self._initialize_models()
            await self._load_pricing_data()
            self.is_initialized = True
            logger.info("AI Cost Optimizer initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize AI Cost Optimizer: {e}")
            raise

    async def _initialize_models(self):
        """Initialize ML models for cost optimization"""
        if not HAS_ML_LIBS:
            return

        try:
            # Cost forecasting model
            self.models['cost_forecast'] = RandomForestRegressor(
                n_estimators=100,
                max_depth=15,
                random_state=42
            )

            # Usage pattern clustering
            self.models['usage_clustering'] = KMeans(
                n_clusters=5,
                random_state=42
            )

            # Right-sizing model
            self.models['right_sizing'] = RandomForestRegressor(
                n_estimators=50,
                max_depth=10,
                random_state=42
            )

            # Cost anomaly detection
            self.models['cost_anomaly'] = LinearRegression()

            # Scalers for normalization
            self.scalers['usage'] = StandardScaler()
            self.scalers['cost'] = StandardScaler()

            logger.info("ML models initialized for cost optimization")

        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    async def _load_pricing_data(self):
        """Load cloud provider pricing data"""
        try:
            # Mock pricing data - in production, this would come from cloud APIs
            self.pricing_data = {
                'aws': {
                    'compute': {
                        't3.micro': 0.0104,
                        't3.small': 0.0208,
                        't3.medium': 0.0416,
                        'm5.large': 0.096,
                        'm5.xlarge': 0.192
                    },
                    'storage': {
                        'ebs_gp2': 0.10,  # per GB/month
                        'ebs_gp3': 0.08,
                        's3_standard': 0.023
                    }
                },
                'gcp': {
                    'compute': {
                        'e2-micro': 0.008,
                        'e2-small': 0.017,
                        'e2-medium': 0.033,
                        'n1-standard-1': 0.048
                    }
                },
                'azure': {
                    'compute': {
                        'B1s': 0.0052,
                        'B2s': 0.0416,
                        'D2s_v3': 0.096
                    }
                }
            }

            logger.info("Pricing data loaded successfully")

        except Exception as e:
            logger.error(f"Failed to load pricing data: {e}")

    async def analyze_resource_usage(self, usage_data: List[ResourceUsage]) -> List[CostOptimizationRecommendation]:
        """Analyze resource usage and generate cost optimization recommendations"""
        try:
            if not self.is_initialized:
                await self.initialize()

            recommendations = []

            # Store usage data
            self.usage_history.extend(usage_data)

            # Keep only recent data (last 30 days)
            cutoff_time = datetime.now() - timedelta(days=30)
            self.usage_history = [
                u for u in self.usage_history
                if u.timestamp > cutoff_time
            ]

            # Cluster resources by usage patterns
            await self._cluster_resources_by_usage()

            # Generate recommendations for each resource
            for usage in usage_data:
                resource_recommendations = await self._analyze_single_resource(usage)
                recommendations.extend(resource_recommendations)

            # Generate global optimization recommendations
            global_recommendations = await self._generate_global_recommendations()
            recommendations.extend(global_recommendations)

            # Sort by savings potential
            recommendations.sort(key=lambda x: x.savings_amount, reverse=True)

            return recommendations

        except Exception as e:
            logger.error(f"Failed to analyze resource usage: {e}")
            return []

    async def _analyze_single_resource(self, usage: ResourceUsage) -> List[CostOptimizationRecommendation]:
        """Analyze a single resource and generate recommendations"""
        try:
            recommendations = []

            # Right-sizing analysis
            right_sizing_rec = await self._analyze_right_sizing(usage)
            if right_sizing_rec:
                recommendations.append(right_sizing_rec)

            # Idle resource analysis
            idle_rec = await self._analyze_idle_resource(usage)
            if idle_rec:
                recommendations.append(idle_rec)

            # Reserved instance analysis
            ri_rec = await self._analyze_reserved_instances(usage)
            if ri_rec:
                recommendations.append(ri_rec)

            # Spot instance analysis
            spot_rec = await self._analyze_spot_instances(usage)
            if spot_rec:
                recommendations.append(spot_rec)

            # Storage optimization analysis
            if usage.resource_type in [ResourceType.STORAGE, ResourceType.COMPUTE]:
                storage_rec = await self._analyze_storage_optimization(usage)
                if storage_rec:
                    recommendations.append(storage_rec)

            return recommendations

        except Exception as e:
            logger.error(f"Failed to analyze single resource {usage.resource_id}: {e}")
            return []

    async def _analyze_right_sizing(self, usage: ResourceUsage) -> Optional[CostOptimizationRecommendation]:
        """Analyze resource for right-sizing opportunities"""
        try:
            if usage.resource_type != ResourceType.COMPUTE:
                return None

            # Check if resource is underutilized
            avg_utilization = (usage.cpu_utilization + usage.memory_utilization) / 2

            if avg_utilization < self.optimization_params['utilization_threshold_low']:
                # Recommend downsizing
                smaller_instance_cost = usage.cost_per_hour * 0.5  # Assume 50% cost reduction
                monthly_savings = (usage.cost_per_hour - smaller_instance_cost) * 24 * 30

                if monthly_savings > self.optimization_params['cost_saving_threshold']:
                    confidence = min((self.optimization_params['utilization_threshold_low'] - avg_utilization) / 20, 1.0)

                    return CostOptimizationRecommendation(
                        id=f"right_size_{usage.resource_id}_{int(usage.timestamp.timestamp())}",
                        strategy=OptimizationStrategy.RIGHT_SIZING,
                        resource_id=usage.resource_id,
                        resource_type=usage.resource_type,
                        description=f"Resource is underutilized (avg: {avg_utilization:.1f}%). Consider downsizing.",
                        current_cost=usage.cost_per_hour * 24 * 30,  # Monthly cost
                        projected_cost=smaller_instance_cost * 24 * 30,
                        savings_amount=monthly_savings,
                        savings_percentage=50.0,
                        confidence_score=confidence,
                        impact=CostImpact.MEDIUM,
                        implementation_effort="Low",
                        risk_level="Low",
                        timeline="1-2 weeks",
                        prerequisites=["Performance testing", "Monitoring setup"],
                        metadata={
                            'current_utilization': avg_utilization,
                            'recommended_action': 'downsize',
                            'instance_type_change': True
                        }
                    )

            elif avg_utilization > self.optimization_params['utilization_threshold_high']:
                # Resource might be oversized, but also check for performance issues
                logger.info(f"Resource {usage.resource_id} has high utilization: {avg_utilization:.1f}%")

        except Exception as e:
            logger.error(f"Right-sizing analysis failed for {usage.resource_id}: {e}")

        return None

    async def _analyze_idle_resource(self, usage: ResourceUsage) -> Optional[CostOptimizationRecommendation]:
        """Analyze resource for idle time optimization"""
        try:
            if usage.idle_time_percentage > self.optimization_params['idle_threshold']:
                # Resource is idle most of the time
                monthly_cost = usage.cost_per_hour * 24 * 30
                potential_savings = monthly_cost * (usage.idle_time_percentage / 100) * 0.8  # 80% of idle time

                if potential_savings > self.optimization_params['cost_saving_threshold']:
                    confidence = min(usage.idle_time_percentage / 100, 0.9)

                    strategy = OptimizationStrategy.AUTO_SHUTDOWN
                    description = f"Resource is idle {usage.idle_time_percentage:.1f}% of the time. Consider auto-shutdown."

                    if usage.resource_type == ResourceType.COMPUTE:
                        description += " Implement scheduled start/stop or auto-scaling."

                    return CostOptimizationRecommendation(
                        id=f"idle_{usage.resource_id}_{int(usage.timestamp.timestamp())}",
                        strategy=strategy,
                        resource_id=usage.resource_id,
                        resource_type=usage.resource_type,
                        description=description,
                        current_cost=monthly_cost,
                        projected_cost=monthly_cost - potential_savings,
                        savings_amount=potential_savings,
                        savings_percentage=(potential_savings / monthly_cost) * 100,
                        confidence_score=confidence,
                        impact=CostImpact.HIGH if potential_savings > 100 else CostImpact.MEDIUM,
                        implementation_effort="Medium",
                        risk_level="Low",
                        timeline="1-3 weeks",
                        prerequisites=["Usage pattern analysis", "Business approval"],
                        metadata={
                            'idle_percentage': usage.idle_time_percentage,
                            'optimization_type': 'scheduled_shutdown'
                        }
                    )

        except Exception as e:
            logger.error(f"Idle resource analysis failed for {usage.resource_id}: {e}")

        return None

    async def _analyze_reserved_instances(self, usage: ResourceUsage) -> Optional[CostOptimizationRecommendation]:
        """Analyze reserved instance opportunities"""
        try:
            if usage.resource_type != ResourceType.COMPUTE:
                return None

            # Check if resource runs consistently (good candidate for RI)
            if (usage.idle_time_percentage < 30.0 and  # Low idle time
                usage.actual_usage_hours > 20):        # High usage hours per day

                # Estimate RI savings (typically 30-60% for 1-year term)
                ri_discount = 0.40  # 40% discount
                monthly_savings = usage.cost_per_hour * 24 * 30 * ri_discount

                if monthly_savings > self.optimization_params['cost_saving_threshold']:
                    return CostOptimizationRecommendation(
                        id=f"reserved_{usage.resource_id}_{int(usage.timestamp.timestamp())}",
                        strategy=OptimizationStrategy.RESERVED_INSTANCES,
                        resource_id=usage.resource_id,
                        resource_type=usage.resource_type,
                        description="Resource has consistent usage pattern. Consider Reserved Instance.",
                        current_cost=usage.cost_per_hour * 24 * 30,
                        projected_cost=usage.cost_per_hour * 24 * 30 * (1 - ri_discount),
                        savings_amount=monthly_savings,
                        savings_percentage=ri_discount * 100,
                        confidence_score=0.85,
                        impact=CostImpact.HIGH,
                        implementation_effort="Low",
                        risk_level="Medium",  # Commitment risk
                        timeline="Immediate",
                        prerequisites=["Usage trend verification", "Budget approval"],
                        metadata={
                            'usage_pattern': 'consistent',
                            'recommended_term': '1_year',
                            'payment_option': 'partial_upfront'
                        }
                    )

        except Exception as e:
            logger.error(f"Reserved instance analysis failed for {usage.resource_id}: {e}")

        return None

    async def _analyze_spot_instances(self, usage: ResourceUsage) -> Optional[CostOptimizationRecommendation]:
        """Analyze spot instance opportunities"""
        try:
            if usage.resource_type != ResourceType.COMPUTE:
                return None

            # Check if workload is fault-tolerant (good for spot instances)
            # This is a simplified check - in practice, would need workload metadata
            if usage.cpu_utilization < 70.0:  # Not critical workload
                spot_discount = 0.70  # 70% discount typical for spot instances
                monthly_savings = usage.cost_per_hour * 24 * 30 * spot_discount

                if monthly_savings > self.optimization_params['cost_saving_threshold']:
                    return CostOptimizationRecommendation(
                        id=f"spot_{usage.resource_id}_{int(usage.timestamp.timestamp())}",
                        strategy=OptimizationStrategy.SPOT_INSTANCES,
                        resource_id=usage.resource_id,
                        resource_type=usage.resource_type,
                        description="Workload suitable for spot instances. Significant cost savings possible.",
                        current_cost=usage.cost_per_hour * 24 * 30,
                        projected_cost=usage.cost_per_hour * 24 * 30 * (1 - spot_discount),
                        savings_amount=monthly_savings,
                        savings_percentage=spot_discount * 100,
                        confidence_score=0.7,  # Lower confidence due to availability risk
                        impact=CostImpact.HIGH,
                        implementation_effort="Medium",
                        risk_level="High",  # Interruption risk
                        timeline="2-4 weeks",
                        prerequisites=["Fault tolerance verification", "Auto-scaling setup"],
                        metadata={
                            'workload_type': 'fault_tolerant',
                            'interruption_handling': 'required'
                        }
                    )

        except Exception as e:
            logger.error(f"Spot instance analysis failed for {usage.resource_id}: {e}")

        return None

    async def _analyze_storage_optimization(self, usage: ResourceUsage) -> Optional[CostOptimizationRecommendation]:
        """Analyze storage optimization opportunities"""
        try:
            if usage.storage_utilization < 50.0:  # Less than 50% storage used
                # Recommend storage class optimization or cleanup
                storage_savings = usage.cost_per_hour * 24 * 30 * 0.3  # 30% savings from optimization

                return CostOptimizationRecommendation(
                    id=f"storage_{usage.resource_id}_{int(usage.timestamp.timestamp())}",
                    strategy=OptimizationStrategy.STORAGE_OPTIMIZATION,
                    resource_id=usage.resource_id,
                    resource_type=usage.resource_type,
                    description=f"Storage utilization is low ({usage.storage_utilization:.1f}%). Optimize storage allocation.",
                    current_cost=usage.cost_per_hour * 24 * 30,
                    projected_cost=usage.cost_per_hour * 24 * 30 * 0.7,
                    savings_amount=storage_savings,
                    savings_percentage=30.0,
                    confidence_score=0.8,
                    impact=CostImpact.MEDIUM,
                    implementation_effort="Low",
                    risk_level="Low",
                    timeline="1 week",
                    prerequisites=["Data backup", "Storage analysis"],
                    metadata={
                        'current_utilization': usage.storage_utilization,
                        'optimization_type': 'cleanup_and_tiering'
                    }
                )

        except Exception as e:
            logger.error(f"Storage optimization analysis failed for {usage.resource_id}: {e}")

        return None

    async def _generate_global_recommendations(self) -> List[CostOptimizationRecommendation]:
        """Generate global cost optimization recommendations"""
        try:
            recommendations = []

            if len(self.usage_history) < 10:
                return recommendations

            # Analyze overall spending patterns
            total_monthly_cost = sum(u.cost_per_hour * 24 * 30 for u in self.usage_history[-30:])

            # Budget optimization recommendation
            if total_monthly_cost > 1000:  # Threshold for budget optimization
                potential_savings = total_monthly_cost * 0.15  # 15% potential savings

                recommendations.append(
                    CostOptimizationRecommendation(
                        id=f"global_budget_{int(datetime.now().timestamp())}",
                        strategy=OptimizationStrategy.SCHEDULED_SCALING,
                        resource_id="global",
                        resource_type=ResourceType.COMPUTE,
                        description="Implement global cost optimization strategy across all resources.",
                        current_cost=total_monthly_cost,
                        projected_cost=total_monthly_cost - potential_savings,
                        savings_amount=potential_savings,
                        savings_percentage=15.0,
                        confidence_score=0.8,
                        impact=CostImpact.HIGH,
                        implementation_effort="High",
                        risk_level="Medium",
                        timeline="1-2 months",
                        prerequisites=["Cost governance setup", "Monitoring implementation"],
                        metadata={
                            'optimization_scope': 'global',
                            'resource_count': len(self.usage_history)
                        }
                    )
                )

            return recommendations

        except Exception as e:
            logger.error(f"Global recommendations generation failed: {e}")
            return []

    async def forecast_costs(self, horizon_days: int = None) -> CostForecast:
        """Generate cost forecast using ML models"""
        try:
            if not horizon_days:
                horizon_days = self.optimization_params['forecast_horizon_days']

            if len(self.usage_history) < 30:
                # Not enough data for accurate forecasting
                current_daily_cost = sum(u.cost_per_hour * 24 for u in self.usage_history[-7:]) / 7
                projected_cost = current_daily_cost * horizon_days

                return CostForecast(
                    period=f"{horizon_days}_days",
                    projected_cost=projected_cost,
                    confidence_interval=(projected_cost * 0.8, projected_cost * 1.2),
                    cost_drivers=["insufficient_data"],
                    optimization_potential=projected_cost * 0.2,
                    forecast_date=datetime.now()
                )

            # Use historical data to forecast
            daily_costs = []
            current_date = datetime.now() - timedelta(days=30)

            for i in range(30):
                date = current_date + timedelta(days=i)
                day_usage = [u for u in self.usage_history if u.timestamp.date() == date.date()]
                daily_cost = sum(u.cost_per_hour * 24 for u in day_usage)
                if daily_cost > 0:
                    daily_costs.append(daily_cost)

            if not daily_costs:
                daily_costs = [100.0]  # Default fallback

            # Simple trend-based forecasting
            if len(daily_costs) >= 7:
                recent_avg = statistics.mean(daily_costs[-7:])
                overall_avg = statistics.mean(daily_costs)
                trend_factor = recent_avg / overall_avg if overall_avg > 0 else 1.0
            else:
                trend_factor = 1.0
                recent_avg = statistics.mean(daily_costs)

            projected_daily_cost = recent_avg * trend_factor
            projected_cost = projected_daily_cost * horizon_days

            # Calculate confidence interval
            if len(daily_costs) > 1:
                std_dev = statistics.stdev(daily_costs)
                confidence_interval = (
                    max(0, projected_cost - std_dev * horizon_days * 0.5),
                    projected_cost + std_dev * horizon_days * 0.5
                )
            else:
                confidence_interval = (projected_cost * 0.8, projected_cost * 1.2)

            # Identify cost drivers
            cost_drivers = []
            if trend_factor > 1.1:
                cost_drivers.append("increasing_usage")
            if projected_daily_cost > 500:
                cost_drivers.append("high_compute_usage")

            return CostForecast(
                period=f"{horizon_days}_days",
                projected_cost=projected_cost,
                confidence_interval=confidence_interval,
                cost_drivers=cost_drivers if cost_drivers else ["stable_usage"],
                optimization_potential=projected_cost * 0.25,  # 25% potential optimization
                forecast_date=datetime.now()
            )

        except Exception as e:
            logger.error(f"Cost forecasting failed: {e}")
            return CostForecast(
                period=f"{horizon_days}_days",
                projected_cost=0.0,
                confidence_interval=(0.0, 0.0),
                cost_drivers=["forecast_error"],
                optimization_potential=0.0,
                forecast_date=datetime.now()
            )

    async def _cluster_resources_by_usage(self):
        """Cluster resources by usage patterns for better optimization"""
        try:
            if not HAS_ML_LIBS or len(self.usage_history) < 20:
                return

            # Extract features for clustering
            features = []
            resource_ids = []

            for usage in self.usage_history[-100:]:  # Recent data
                features.append([
                    usage.cpu_utilization,
                    usage.memory_utilization,
                    usage.storage_utilization,
                    usage.network_utilization,
                    usage.idle_time_percentage,
                    usage.cost_per_hour
                ])
                resource_ids.append(usage.resource_id)

            if len(features) < 5:
                return

            # Normalize features
            scaled_features = self.scalers['usage'].fit_transform(features)

            # Perform clustering
            clusters = self.models['usage_clustering'].fit_predict(scaled_features)

            # Store cluster assignments
            for resource_id, cluster in zip(resource_ids, clusters):
                self.resource_clusters[resource_id] = cluster

            logger.debug(f"Clustered {len(resource_ids)} resources into {len(set(clusters))} clusters")

        except Exception as e:
            logger.error(f"Resource clustering failed: {e}")

    async def get_cost_report(self) -> Dict[str, Any]:
        """Generate comprehensive cost optimization report"""
        try:
            recent_usage = self.usage_history[-100:] if self.usage_history else []

            if not recent_usage:
                return {"error": "No usage data available"}

            # Calculate current spending
            total_hourly_cost = sum(u.cost_per_hour for u in recent_usage[-24:]) if len(recent_usage) >= 24 else 0
            daily_cost = total_hourly_cost * 24
            monthly_cost = daily_cost * 30

            # Calculate utilization averages
            avg_cpu_util = statistics.mean([u.cpu_utilization for u in recent_usage])
            avg_memory_util = statistics.mean([u.memory_utilization for u in recent_usage])
            avg_idle_time = statistics.mean([u.idle_time_percentage for u in recent_usage])

            # Cost breakdown by resource type
            cost_by_type = {}
            for resource_type in ResourceType:
                type_usage = [u for u in recent_usage if u.resource_type == resource_type]
                if type_usage:
                    cost_by_type[resource_type.value] = sum(u.cost_per_hour for u in type_usage) * 24 * 30

            # Generate forecast
            forecast = await self.forecast_costs(30)

            # Calculate optimization potential
            recommendations = await self.analyze_resource_usage(recent_usage[-10:])  # Recent resources
            total_potential_savings = sum(r.savings_amount for r in recommendations)

            report = {
                "timestamp": datetime.now().isoformat(),
                "current_spending": {
                    "hourly": total_hourly_cost,
                    "daily": daily_cost,
                    "monthly": monthly_cost
                },
                "utilization_metrics": {
                    "avg_cpu_utilization": avg_cpu_util,
                    "avg_memory_utilization": avg_memory_util,
                    "avg_idle_time": avg_idle_time
                },
                "cost_breakdown_by_type": cost_by_type,
                "optimization_opportunities": {
                    "total_recommendations": len(recommendations),
                    "potential_monthly_savings": total_potential_savings,
                    "savings_percentage": (total_potential_savings / monthly_cost) * 100 if monthly_cost > 0 else 0
                },
                "cost_forecast": {
                    "period": forecast.period,
                    "projected_cost": forecast.projected_cost,
                    "confidence_interval": forecast.confidence_interval,
                    "optimization_potential": forecast.optimization_potential
                },
                "top_recommendations": [
                    {
                        "strategy": r.strategy.value,
                        "resource_id": r.resource_id,
                        "savings_amount": r.savings_amount,
                        "savings_percentage": r.savings_percentage,
                        "implementation_effort": r.implementation_effort,
                        "risk_level": r.risk_level
                    }
                    for r in recommendations[:5]  # Top 5 recommendations
                ],
                "resource_clusters": len(set(self.resource_clusters.values())) if self.resource_clusters else 0
            }

            return report

        except Exception as e:
            logger.error(f"Failed to generate cost report: {e}")
            return {"error": str(e)}

    async def stop(self):
        """Stop the cost optimization engine"""
        try:
            logger.info("Stopping AI Cost Optimizer")
            self.is_initialized = False

        except Exception as e:
            logger.error(f"Error stopping AI Cost Optimizer: {e}")