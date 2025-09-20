#!/usr/bin/env python3
"""
CloudOS Advanced Cost Optimizer
AI-powered cost optimization with multi-cloud support and predictive analytics
"""

import asyncio
import json
import logging
import math
import statistics
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

# Financial and optimization imports
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from scipy.optimize import minimize, linprog
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

class CloudProvider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITAL_OCEAN = "digitalocean"
    HETZNER = "hetzner"
    LINODE = "linode"

class ResourceType(Enum):
    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    CACHE = "cache"
    LOAD_BALANCER = "load_balancer"

class PricingModel(Enum):
    ON_DEMAND = "on_demand"
    RESERVED = "reserved"
    SPOT = "spot"
    SAVINGS_PLAN = "savings_plan"
    COMMITTED_USE = "committed_use"

class OptimizationStrategy(Enum):
    COST_MINIMIZE = "cost_minimize"
    PERFORMANCE_OPTIMIZE = "performance_optimize"
    BALANCED = "balanced"
    SUSTAINABILITY = "sustainability"

@dataclass
class ResourceUsage:
    """Resource usage metrics"""
    timestamp: datetime
    resource_id: str
    resource_type: ResourceType
    provider: CloudProvider
    cpu_utilization: float
    memory_utilization: float
    storage_utilization: float
    network_io_gb: float
    iops: int
    requests_per_second: float
    active_connections: int
    cost_per_hour: float
    instance_type: str
    region: str

@dataclass
class PricingInfo:
    """Cloud resource pricing information"""
    provider: CloudProvider
    region: str
    instance_type: str
    resource_type: ResourceType
    pricing_model: PricingModel
    cost_per_hour: float
    cost_per_gb_storage: Optional[float] = None
    cost_per_gb_transfer: Optional[float] = None
    minimum_commitment: Optional[timedelta] = None
    discount_percentage: float = 0.0
    availability: str = "high"
    specifications: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CostOptimizationRecommendation:
    """Cost optimization recommendation"""
    resource_id: str
    current_cost_per_hour: float
    recommended_action: str
    target_instance_type: Optional[str] = None
    target_pricing_model: Optional[PricingModel] = None
    target_provider: Optional[CloudProvider] = None
    estimated_savings_per_hour: float = 0.0
    estimated_savings_per_month: float = 0.0
    confidence: float = 0.5
    impact_on_performance: str = "minimal"
    implementation_complexity: str = "low"
    risk_level: str = "low"
    reasoning: str = ""
    prerequisites: List[str] = field(default_factory=list)
    estimated_migration_cost: float = 0.0

@dataclass
class CostForecast:
    """Cost forecasting data"""
    period_start: datetime
    period_end: datetime
    forecasted_cost: float
    confidence_interval: Tuple[float, float]
    trend: str  # increasing, decreasing, stable
    factors: List[str]
    recommendations: List[str]

class AdvancedCostOptimizer:
    """
    Advanced cost optimization engine with AI-powered recommendations,
    multi-cloud support, and predictive analytics
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Optimization settings
        self.optimization_strategy = OptimizationStrategy(
            self.config.get('strategy', 'balanced')
        )
        self.cost_target_reduction = self.config.get('target_reduction_percent', 20.0)
        self.performance_tolerance = self.config.get('performance_tolerance', 0.1)

        # Data storage
        self.usage_history: List[ResourceUsage] = []
        self.pricing_catalog: Dict[str, List[PricingInfo]] = defaultdict(list)
        self.historical_costs: List[Dict[str, Any]] = []
        self.optimization_history: List[CostOptimizationRecommendation] = []

        # ML models for prediction
        self.cost_forecast_model = None
        self.usage_prediction_model = None
        self.anomaly_detector = None

        # Caching for performance
        self.pricing_cache: Dict[str, PricingInfo] = {}
        self.recommendation_cache: Dict[str, List[CostOptimizationRecommendation]] = {}
        self.cache_ttl = timedelta(hours=1)
        self.cache_timestamps: Dict[str, datetime] = {}

        # Monitoring and alerting
        self.cost_thresholds: Dict[str, float] = {}
        self.budget_alerts: List[Dict[str, Any]] = []

        self.logger.info(f"Advanced Cost Optimizer initialized with strategy: {self.optimization_strategy.value}")

    async def add_usage_data(self, usage: ResourceUsage):
        """Add resource usage data for analysis"""
        self.usage_history.append(usage)

        # Keep only recent history (last 30 days)
        cutoff_time = datetime.now() - timedelta(days=30)
        self.usage_history = [u for u in self.usage_history if u.timestamp > cutoff_time]

        # Update cost tracking
        await self._update_cost_tracking(usage)

        self.logger.debug(f"Added usage data for {usage.resource_id}: ${usage.cost_per_hour:.3f}/hour")

    async def load_pricing_catalog(self, pricing_data: List[PricingInfo]):
        """Load cloud provider pricing catalog"""
        for pricing in pricing_data:
            key = f"{pricing.provider.value}_{pricing.region}_{pricing.resource_type.value}"
            self.pricing_catalog[key].append(pricing)

        self.logger.info(f"Loaded pricing data for {len(pricing_data)} resources")

    async def generate_cost_optimization_recommendations(self,
                                                       resource_ids: Optional[List[str]] = None
                                                       ) -> List[CostOptimizationRecommendation]:
        """Generate comprehensive cost optimization recommendations"""
        if not self.usage_history:
            return []

        # Filter resources if specified
        if resource_ids:
            relevant_usage = [u for u in self.usage_history if u.resource_id in resource_ids]
        else:
            relevant_usage = self.usage_history

        recommendations = []

        # Group usage by resource
        resource_usage = defaultdict(list)
        for usage in relevant_usage:
            resource_usage[usage.resource_id].append(usage)

        # Analyze each resource
        for resource_id, usage_data in resource_usage.items():
            if not usage_data:
                continue

            latest_usage = usage_data[-1]

            # Calculate utilization patterns
            utilization_analysis = await self._analyze_resource_utilization(usage_data)

            # Get optimization recommendations
            resource_recommendations = await self._generate_resource_recommendations(
                resource_id, latest_usage, utilization_analysis
            )

            recommendations.extend(resource_recommendations)

        # Sort by potential savings
        recommendations.sort(key=lambda x: x.estimated_savings_per_month, reverse=True)

        # Cache recommendations
        cache_key = f"recommendations_{resource_ids or 'all'}"
        self.recommendation_cache[cache_key] = recommendations
        self.cache_timestamps[cache_key] = datetime.now()

        self.logger.info(f"Generated {len(recommendations)} cost optimization recommendations")
        return recommendations

    async def _analyze_resource_utilization(self, usage_data: List[ResourceUsage]) -> Dict[str, Any]:
        """Analyze resource utilization patterns"""
        if not usage_data:
            return {}

        # Calculate statistics
        cpu_values = [u.cpu_utilization for u in usage_data]
        memory_values = [u.memory_utilization for u in usage_data]
        storage_values = [u.storage_utilization for u in usage_data]

        analysis = {
            'avg_cpu': statistics.mean(cpu_values),
            'max_cpu': max(cpu_values),
            'min_cpu': min(cpu_values),
            'cpu_variance': statistics.variance(cpu_values) if len(cpu_values) > 1 else 0,

            'avg_memory': statistics.mean(memory_values),
            'max_memory': max(memory_values),
            'min_memory': min(memory_values),
            'memory_variance': statistics.variance(memory_values) if len(memory_values) > 1 else 0,

            'avg_storage': statistics.mean(storage_values),
            'max_storage': max(storage_values),

            'utilization_pattern': self._classify_utilization_pattern(cpu_values, memory_values),
            'efficiency_score': self._calculate_efficiency_score(usage_data),
            'cost_trend': self._analyze_cost_trend(usage_data),
            'peak_usage_times': self._identify_peak_usage_times(usage_data)
        }

        return analysis

    def _classify_utilization_pattern(self, cpu_values: List[float], memory_values: List[float]) -> str:
        """Classify the utilization pattern"""
        if not cpu_values or not memory_values:
            return "unknown"

        avg_cpu = statistics.mean(cpu_values)
        avg_memory = statistics.mean(memory_values)
        cpu_variance = statistics.variance(cpu_values) if len(cpu_values) > 1 else 0
        memory_variance = statistics.variance(memory_values) if len(memory_values) > 1 else 0

        if avg_cpu < 30 and avg_memory < 30:
            return "underutilized"
        elif avg_cpu > 80 or avg_memory > 80:
            return "overutilized"
        elif cpu_variance > 500 or memory_variance > 500:
            return "highly_variable"
        elif avg_cpu > 50 and avg_memory > 50:
            return "well_utilized"
        else:
            return "moderate"

    def _calculate_efficiency_score(self, usage_data: List[ResourceUsage]) -> float:
        """Calculate resource efficiency score (0-100)"""
        if not usage_data:
            return 0.0

        total_score = 0
        for usage in usage_data:
            # Efficiency based on utilization vs cost
            utilization_score = (usage.cpu_utilization + usage.memory_utilization) / 2
            cost_efficiency = min(100, (utilization_score / max(1, usage.cost_per_hour)) * 10)
            total_score += cost_efficiency

        return total_score / len(usage_data)

    def _analyze_cost_trend(self, usage_data: List[ResourceUsage]) -> str:
        """Analyze cost trend over time"""
        if len(usage_data) < 2:
            return "stable"

        costs = [u.cost_per_hour for u in usage_data[-7:]]  # Last 7 data points
        if len(costs) < 2:
            return "stable"

        # Simple trend analysis
        trend = statistics.mean(costs[-3:]) - statistics.mean(costs[:3]) if len(costs) >= 6 else costs[-1] - costs[0]

        if trend > 0.1:
            return "increasing"
        elif trend < -0.1:
            return "decreasing"
        else:
            return "stable"

    def _identify_peak_usage_times(self, usage_data: List[ResourceUsage]) -> List[int]:
        """Identify peak usage hours (0-23)"""
        hourly_usage = defaultdict(list)

        for usage in usage_data:
            hour = usage.timestamp.hour
            avg_utilization = (usage.cpu_utilization + usage.memory_utilization) / 2
            hourly_usage[hour].append(avg_utilization)

        # Calculate average utilization per hour
        hourly_averages = {}
        for hour, utilizations in hourly_usage.items():
            hourly_averages[hour] = statistics.mean(utilizations)

        if not hourly_averages:
            return []

        # Find hours with above-average utilization
        overall_avg = statistics.mean(hourly_averages.values())
        peak_hours = [hour for hour, avg in hourly_averages.items() if avg > overall_avg * 1.2]

        return sorted(peak_hours)

    async def _generate_resource_recommendations(self,
                                               resource_id: str,
                                               latest_usage: ResourceUsage,
                                               utilization_analysis: Dict[str, Any]
                                               ) -> List[CostOptimizationRecommendation]:
        """Generate recommendations for a specific resource"""
        recommendations = []

        # Right-sizing recommendation
        rightsizing_rec = await self._analyze_rightsizing(resource_id, latest_usage, utilization_analysis)
        if rightsizing_rec:
            recommendations.append(rightsizing_rec)

        # Pricing model optimization
        pricing_rec = await self._analyze_pricing_model_optimization(resource_id, latest_usage, utilization_analysis)
        if pricing_rec:
            recommendations.append(pricing_rec)

        # Multi-cloud comparison
        multicloud_rec = await self._analyze_multicloud_opportunities(resource_id, latest_usage)
        if multicloud_rec:
            recommendations.append(multicloud_rec)

        # Scheduling optimization
        scheduling_rec = await self._analyze_scheduling_optimization(resource_id, latest_usage, utilization_analysis)
        if scheduling_rec:
            recommendations.append(scheduling_rec)

        return recommendations

    async def _analyze_rightsizing(self,
                                 resource_id: str,
                                 usage: ResourceUsage,
                                 analysis: Dict[str, Any]
                                 ) -> Optional[CostOptimizationRecommendation]:
        """Analyze right-sizing opportunities"""

        pattern = analysis.get('utilization_pattern', 'unknown')
        avg_cpu = analysis.get('avg_cpu', 0)
        avg_memory = analysis.get('avg_memory', 0)
        max_cpu = analysis.get('max_cpu', 0)
        max_memory = analysis.get('max_memory', 0)

        if pattern == "underutilized" and avg_cpu < 25 and avg_memory < 25:
            # Recommend smaller instance
            target_instance = await self._find_smaller_instance(usage)
            if target_instance:
                savings = usage.cost_per_hour - target_instance.cost_per_hour
                return CostOptimizationRecommendation(
                    resource_id=resource_id,
                    current_cost_per_hour=usage.cost_per_hour,
                    recommended_action="downsize_instance",
                    target_instance_type=target_instance.instance_type,
                    estimated_savings_per_hour=savings,
                    estimated_savings_per_month=savings * 24 * 30,
                    confidence=0.8,
                    impact_on_performance="minimal",
                    implementation_complexity="low",
                    risk_level="low",
                    reasoning=f"Resource is underutilized (CPU: {avg_cpu:.1f}%, Memory: {avg_memory:.1f}%)",
                    prerequisites=["Monitor performance after downsizing"]
                )

        elif pattern == "overutilized" and (max_cpu > 90 or max_memory > 90):
            # Recommend larger instance
            target_instance = await self._find_larger_instance(usage)
            if target_instance:
                additional_cost = target_instance.cost_per_hour - usage.cost_per_hour
                return CostOptimizationRecommendation(
                    resource_id=resource_id,
                    current_cost_per_hour=usage.cost_per_hour,
                    recommended_action="upsize_instance",
                    target_instance_type=target_instance.instance_type,
                    estimated_savings_per_hour=-additional_cost,  # Negative savings (cost increase)
                    estimated_savings_per_month=-additional_cost * 24 * 30,
                    confidence=0.9,
                    impact_on_performance="significant_improvement",
                    implementation_complexity="low",
                    risk_level="low",
                    reasoning=f"Resource is overutilized (Max CPU: {max_cpu:.1f}%, Max Memory: {max_memory:.1f}%)",
                    prerequisites=["Performance will improve but cost will increase"]
                )

        return None

    async def _analyze_pricing_model_optimization(self,
                                                resource_id: str,
                                                usage: ResourceUsage,
                                                analysis: Dict[str, Any]
                                                ) -> Optional[CostOptimizationRecommendation]:
        """Analyze pricing model optimization opportunities"""

        # Look for reserved instance opportunities
        if usage.instance_type and analysis.get('utilization_pattern') in ['well_utilized', 'overutilized']:
            reserved_pricing = await self._find_reserved_pricing(usage)
            if reserved_pricing and reserved_pricing.cost_per_hour < usage.cost_per_hour:
                savings = usage.cost_per_hour - reserved_pricing.cost_per_hour
                return CostOptimizationRecommendation(
                    resource_id=resource_id,
                    current_cost_per_hour=usage.cost_per_hour,
                    recommended_action="switch_to_reserved",
                    target_pricing_model=reserved_pricing.pricing_model,
                    estimated_savings_per_hour=savings,
                    estimated_savings_per_month=savings * 24 * 30,
                    confidence=0.85,
                    impact_on_performance="none",
                    implementation_complexity="medium",
                    risk_level="low",
                    reasoning="Consistent usage pattern suitable for reserved instances",
                    prerequisites=["Commit to 1-3 year term", "Upfront payment may be required"]
                )

        # Look for spot instance opportunities
        if analysis.get('utilization_pattern') != 'overutilized':
            spot_pricing = await self._find_spot_pricing(usage)
            if spot_pricing and spot_pricing.cost_per_hour < usage.cost_per_hour * 0.7:
                savings = usage.cost_per_hour - spot_pricing.cost_per_hour
                return CostOptimizationRecommendation(
                    resource_id=resource_id,
                    current_cost_per_hour=usage.cost_per_hour,
                    recommended_action="switch_to_spot",
                    target_pricing_model=PricingModel.SPOT,
                    estimated_savings_per_hour=savings,
                    estimated_savings_per_month=savings * 24 * 30,
                    confidence=0.6,
                    impact_on_performance="potential_interruption",
                    implementation_complexity="high",
                    risk_level="medium",
                    reasoning="Workload can tolerate interruptions for significant cost savings",
                    prerequisites=["Implement fault tolerance", "Monitor spot pricing"]
                )

        return None

    async def _analyze_multicloud_opportunities(self,
                                              resource_id: str,
                                              usage: ResourceUsage
                                              ) -> Optional[CostOptimizationRecommendation]:
        """Analyze multi-cloud cost opportunities"""

        # Find equivalent instances on other cloud providers
        alternatives = await self._find_multicloud_alternatives(usage)

        if alternatives:
            best_alternative = min(alternatives, key=lambda x: x.cost_per_hour)
            if best_alternative.cost_per_hour < usage.cost_per_hour * 0.9:  # At least 10% savings
                savings = usage.cost_per_hour - best_alternative.cost_per_hour
                return CostOptimizationRecommendation(
                    resource_id=resource_id,
                    current_cost_per_hour=usage.cost_per_hour,
                    recommended_action="migrate_to_different_provider",
                    target_provider=best_alternative.provider,
                    target_instance_type=best_alternative.instance_type,
                    estimated_savings_per_hour=savings,
                    estimated_savings_per_month=savings * 24 * 30,
                    confidence=0.7,
                    impact_on_performance="minimal",
                    implementation_complexity="high",
                    risk_level="medium",
                    reasoning=f"Better pricing available on {best_alternative.provider.value}",
                    prerequisites=["Data migration planning", "Network reconfiguration", "Testing"],
                    estimated_migration_cost=500.0  # Estimated migration cost
                )

        return None

    async def _analyze_scheduling_optimization(self,
                                             resource_id: str,
                                             usage: ResourceUsage,
                                             analysis: Dict[str, Any]
                                             ) -> Optional[CostOptimizationRecommendation]:
        """Analyze scheduling-based cost optimization"""

        peak_hours = analysis.get('peak_usage_times', [])
        pattern = analysis.get('utilization_pattern', 'unknown')

        if pattern == 'highly_variable' and len(peak_hours) < 12:  # Less than 12 hours of peak usage
            # Recommend auto-scaling or scheduled scaling
            estimated_savings = usage.cost_per_hour * 0.3 * (24 - len(peak_hours))  # 30% savings during off-peak

            return CostOptimizationRecommendation(
                resource_id=resource_id,
                current_cost_per_hour=usage.cost_per_hour,
                recommended_action="implement_auto_scaling",
                estimated_savings_per_hour=estimated_savings / 24,
                estimated_savings_per_month=estimated_savings * 30,
                confidence=0.75,
                impact_on_performance="improved_during_peaks",
                implementation_complexity="medium",
                risk_level="low",
                reasoning=f"Variable usage pattern with {len(peak_hours)} peak hours per day",
                prerequisites=["Implement auto-scaling policies", "Monitor scaling metrics"]
            )

        return None

    async def _find_smaller_instance(self, current_usage: ResourceUsage) -> Optional[PricingInfo]:
        """Find a smaller instance type with lower cost"""
        key = f"{current_usage.provider.value}_{current_usage.region}_{current_usage.resource_type.value}"
        available_pricing = self.pricing_catalog.get(key, [])

        # Filter for smaller instances (lower cost)
        smaller_instances = [
            p for p in available_pricing
            if p.cost_per_hour < current_usage.cost_per_hour and
               p.instance_type != current_usage.instance_type
        ]

        if smaller_instances:
            return min(smaller_instances, key=lambda x: x.cost_per_hour)
        return None

    async def _find_larger_instance(self, current_usage: ResourceUsage) -> Optional[PricingInfo]:
        """Find a larger instance type for better performance"""
        key = f"{current_usage.provider.value}_{current_usage.region}_{current_usage.resource_type.value}"
        available_pricing = self.pricing_catalog.get(key, [])

        # Filter for larger instances (higher cost but better specs)
        larger_instances = [
            p for p in available_pricing
            if p.cost_per_hour > current_usage.cost_per_hour and
               p.instance_type != current_usage.instance_type
        ]

        if larger_instances:
            return min(larger_instances, key=lambda x: x.cost_per_hour)
        return None

    async def _find_reserved_pricing(self, current_usage: ResourceUsage) -> Optional[PricingInfo]:
        """Find reserved instance pricing for current instance type"""
        key = f"{current_usage.provider.value}_{current_usage.region}_{current_usage.resource_type.value}"
        available_pricing = self.pricing_catalog.get(key, [])

        reserved_instances = [
            p for p in available_pricing
            if p.instance_type == current_usage.instance_type and
               p.pricing_model in [PricingModel.RESERVED, PricingModel.SAVINGS_PLAN]
        ]

        if reserved_instances:
            return min(reserved_instances, key=lambda x: x.cost_per_hour)
        return None

    async def _find_spot_pricing(self, current_usage: ResourceUsage) -> Optional[PricingInfo]:
        """Find spot instance pricing for current instance type"""
        key = f"{current_usage.provider.value}_{current_usage.region}_{current_usage.resource_type.value}"
        available_pricing = self.pricing_catalog.get(key, [])

        spot_instances = [
            p for p in available_pricing
            if p.instance_type == current_usage.instance_type and
               p.pricing_model == PricingModel.SPOT
        ]

        if spot_instances:
            return min(spot_instances, key=lambda x: x.cost_per_hour)
        return None

    async def _find_multicloud_alternatives(self, current_usage: ResourceUsage) -> List[PricingInfo]:
        """Find equivalent instances on other cloud providers"""
        alternatives = []

        # Look for similar specs on other providers
        for provider in CloudProvider:
            if provider == current_usage.provider:
                continue

            key = f"{provider.value}_{current_usage.region}_{current_usage.resource_type.value}"
            available_pricing = self.pricing_catalog.get(key, [])

            # Filter for similar instance types (simplified matching)
            for pricing in available_pricing:
                if self._is_similar_instance(current_usage, pricing):
                    alternatives.append(pricing)

        return alternatives

    def _is_similar_instance(self, current: ResourceUsage, alternative: PricingInfo) -> bool:
        """Check if two instances have similar specifications"""
        # Simplified similarity check - in production, this would compare
        # CPU cores, memory, storage, network performance, etc.
        current_specs = getattr(current, 'specifications', {})
        alt_specs = alternative.specifications

        # Basic similarity based on cost range
        cost_ratio = alternative.cost_per_hour / max(current.cost_per_hour, 0.01)
        return 0.5 <= cost_ratio <= 2.0  # Within 50%-200% cost range

    async def _update_cost_tracking(self, usage: ResourceUsage):
        """Update cost tracking and monitoring"""
        # Track daily costs
        today = usage.timestamp.date()
        daily_cost = usage.cost_per_hour * 24  # Assume 24-hour usage

        # Store in historical costs
        self.historical_costs.append({
            'date': today.isoformat(),
            'resource_id': usage.resource_id,
            'cost': daily_cost,
            'provider': usage.provider.value,
            'resource_type': usage.resource_type.value
        })

        # Keep only last 90 days
        cutoff_date = datetime.now().date() - timedelta(days=90)
        self.historical_costs = [
            c for c in self.historical_costs
            if datetime.fromisoformat(c['date']).date() > cutoff_date
        ]

    async def generate_cost_forecast(self, days_ahead: int = 30) -> CostForecast:
        """Generate cost forecast using historical data"""
        if not self.historical_costs:
            return CostForecast(
                period_start=datetime.now(),
                period_end=datetime.now() + timedelta(days=days_ahead),
                forecasted_cost=0.0,
                confidence_interval=(0.0, 0.0),
                trend="unknown",
                factors=["Insufficient historical data"],
                recommendations=["Collect more cost data for accurate forecasting"]
            )

        # Aggregate daily costs
        daily_totals = defaultdict(float)
        for cost_entry in self.historical_costs:
            daily_totals[cost_entry['date']] += cost_entry['cost']

        # Sort by date
        sorted_dates = sorted(daily_totals.keys())
        costs = [daily_totals[date] for date in sorted_dates]

        if len(costs) < 7:
            # Not enough data for reliable forecast
            avg_cost = statistics.mean(costs) if costs else 0
            forecasted_cost = avg_cost * days_ahead

            return CostForecast(
                period_start=datetime.now(),
                period_end=datetime.now() + timedelta(days=days_ahead),
                forecasted_cost=forecasted_cost,
                confidence_interval=(forecasted_cost * 0.8, forecasted_cost * 1.2),
                trend="stable",
                factors=["Limited historical data"],
                recommendations=["Continue monitoring for better predictions"]
            )

        # Calculate trend
        if HAS_NUMPY:
            x = np.arange(len(costs))
            z = np.polyfit(x, costs, 1)
            trend_slope = z[0]
        else:
            # Simple trend calculation
            trend_slope = (costs[-1] - costs[0]) / max(len(costs) - 1, 1)

        # Determine trend direction
        if trend_slope > 0.1:
            trend = "increasing"
        elif trend_slope < -0.1:
            trend = "decreasing"
        else:
            trend = "stable"

        # Forecast future costs
        recent_avg = statistics.mean(costs[-7:])  # Last 7 days average
        forecasted_cost = recent_avg * days_ahead + (trend_slope * days_ahead * days_ahead / 2)

        # Calculate confidence interval based on variance
        variance = statistics.variance(costs) if len(costs) > 1 else 0
        std_dev = math.sqrt(variance)
        confidence_interval = (
            max(0, forecasted_cost - 1.96 * std_dev),
            forecasted_cost + 1.96 * std_dev
        )

        # Generate factors and recommendations
        factors = []
        recommendations = []

        if trend == "increasing":
            factors.append("Rising cost trend detected")
            recommendations.append("Review cost optimization recommendations")
            recommendations.append("Consider implementing auto-scaling")
        elif trend == "decreasing":
            factors.append("Decreasing cost trend detected")
            recommendations.append("Continue current optimization efforts")

        return CostForecast(
            period_start=datetime.now(),
            period_end=datetime.now() + timedelta(days=days_ahead),
            forecasted_cost=forecasted_cost,
            confidence_interval=confidence_interval,
            trend=trend,
            factors=factors,
            recommendations=recommendations
        )

    async def get_cost_summary(self) -> Dict[str, Any]:
        """Get comprehensive cost summary and analytics"""
        if not self.usage_history:
            return {"error": "No usage data available"}

        # Current costs
        total_current_cost = sum(u.cost_per_hour for u in self.usage_history[-50:]) / min(50, len(self.usage_history))

        # Cost by provider
        provider_costs = defaultdict(list)
        for usage in self.usage_history[-100:]:  # Last 100 entries
            provider_costs[usage.provider.value].append(usage.cost_per_hour)

        provider_summary = {
            provider: {
                'total_hourly_cost': sum(costs),
                'avg_hourly_cost': statistics.mean(costs),
                'resource_count': len(costs)
            }
            for provider, costs in provider_costs.items()
        }

        # Cost by resource type
        resource_type_costs = defaultdict(list)
        for usage in self.usage_history[-100:]:
            resource_type_costs[usage.resource_type.value].append(usage.cost_per_hour)

        resource_summary = {
            resource_type: {
                'total_hourly_cost': sum(costs),
                'avg_hourly_cost': statistics.mean(costs),
                'resource_count': len(costs)
            }
            for resource_type, costs in resource_type_costs.items()
        }

        # Get recent recommendations
        recent_recommendations = await self.generate_cost_optimization_recommendations()
        total_potential_savings = sum(r.estimated_savings_per_month for r in recent_recommendations)

        # Cost forecast
        forecast = await self.generate_cost_forecast(30)

        return {
            'current_summary': {
                'total_hourly_cost': total_current_cost,
                'estimated_monthly_cost': total_current_cost * 24 * 30,
                'active_resources': len(set(u.resource_id for u in self.usage_history[-50:]))
            },
            'cost_by_provider': provider_summary,
            'cost_by_resource_type': resource_summary,
            'optimization_potential': {
                'total_monthly_savings': total_potential_savings,
                'optimization_opportunities': len(recent_recommendations),
                'top_recommendations': recent_recommendations[:5]  # Top 5 recommendations
            },
            'cost_forecast': {
                'next_30_days': forecast.forecasted_cost,
                'trend': forecast.trend,
                'confidence_range': forecast.confidence_interval
            },
            'analytics': {
                'optimization_strategy': self.optimization_strategy.value,
                'cost_efficiency_score': await self._calculate_overall_efficiency(),
                'last_updated': datetime.now().isoformat()
            }
        }

    async def _calculate_overall_efficiency(self) -> float:
        """Calculate overall cost efficiency score"""
        if not self.usage_history:
            return 0.0

        efficiency_scores = []
        resource_usage = defaultdict(list)

        for usage in self.usage_history[-100:]:
            resource_usage[usage.resource_id].append(usage)

        for resource_id, usage_data in resource_usage.items():
            score = self._calculate_efficiency_score(usage_data)
            efficiency_scores.append(score)

        return statistics.mean(efficiency_scores) if efficiency_scores else 0.0

    def set_cost_alerts(self, alerts: List[Dict[str, Any]]):
        """Set up cost alerting thresholds"""
        self.budget_alerts = alerts
        self.logger.info(f"Set up {len(alerts)} cost alerts")

    async def check_cost_alerts(self) -> List[Dict[str, Any]]:
        """Check for cost alert triggers"""
        triggered_alerts = []

        if not self.historical_costs:
            return triggered_alerts

        # Calculate current daily cost
        today_costs = [
            c['cost'] for c in self.historical_costs
            if c['date'] == datetime.now().date().isoformat()
        ]
        today_total = sum(today_costs)

        # Calculate monthly cost trend
        monthly_costs = [
            c['cost'] for c in self.historical_costs
            if datetime.fromisoformat(c['date']).date() > datetime.now().date() - timedelta(days=30)
        ]
        monthly_total = sum(monthly_costs)

        # Check each alert
        for alert in self.budget_alerts:
            alert_type = alert.get('type', 'daily')
            threshold = alert.get('threshold', 0)

            if alert_type == 'daily' and today_total > threshold:
                triggered_alerts.append({
                    'type': 'daily_budget_exceeded',
                    'threshold': threshold,
                    'actual': today_total,
                    'message': f"Daily cost ${today_total:.2f} exceeds threshold ${threshold:.2f}"
                })
            elif alert_type == 'monthly' and monthly_total > threshold:
                triggered_alerts.append({
                    'type': 'monthly_budget_exceeded',
                    'threshold': threshold,
                    'actual': monthly_total,
                    'message': f"Monthly cost ${monthly_total:.2f} exceeds threshold ${threshold:.2f}"
                })

        return triggered_alerts

# Example usage
if __name__ == "__main__":
    async def test_cost_optimizer():
        optimizer = AdvancedCostOptimizer()

        # Add sample pricing data
        sample_pricing = [
            PricingInfo(
                provider=CloudProvider.AWS,
                region="us-east-1",
                instance_type="t3.medium",
                resource_type=ResourceType.COMPUTE,
                pricing_model=PricingModel.ON_DEMAND,
                cost_per_hour=0.0416,
                specifications={"cpu": 2, "memory": 4}
            ),
            PricingInfo(
                provider=CloudProvider.AWS,
                region="us-east-1",
                instance_type="t3.small",
                resource_type=ResourceType.COMPUTE,
                pricing_model=PricingModel.ON_DEMAND,
                cost_per_hour=0.0208,
                specifications={"cpu": 2, "memory": 2}
            ),
            PricingInfo(
                provider=CloudProvider.GCP,
                region="us-east1",
                instance_type="e2-medium",
                resource_type=ResourceType.COMPUTE,
                pricing_model=PricingModel.ON_DEMAND,
                cost_per_hour=0.0335,
                specifications={"cpu": 1, "memory": 4}
            )
        ]

        await optimizer.load_pricing_catalog(sample_pricing)

        # Add sample usage data
        base_time = datetime.now()
        for i in range(20):
            usage = ResourceUsage(
                timestamp=base_time + timedelta(hours=i),
                resource_id="web-server-1",
                resource_type=ResourceType.COMPUTE,
                provider=CloudProvider.AWS,
                cpu_utilization=20 + 10 * math.sin(i * 0.1),  # Low utilization
                memory_utilization=25 + 15 * math.cos(i * 0.1),
                storage_utilization=60,
                network_io_gb=10.5,
                iops=100,
                requests_per_second=150,
                active_connections=50,
                cost_per_hour=0.0416,
                instance_type="t3.medium",
                region="us-east-1"
            )
            await optimizer.add_usage_data(usage)

        # Generate recommendations
        recommendations = await optimizer.generate_cost_optimization_recommendations()
        print(f"Generated {len(recommendations)} recommendations:")
        for rec in recommendations:
            print(f"- {rec.recommended_action}: Save ${rec.estimated_savings_per_month:.2f}/month")
            print(f"  Reasoning: {rec.reasoning}")

        # Get cost summary
        summary = await optimizer.get_cost_summary()
        print(f"\nCost Summary: {json.dumps(summary, indent=2, default=str)}")

    asyncio.run(test_cost_optimizer())