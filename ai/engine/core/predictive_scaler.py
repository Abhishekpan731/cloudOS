#!/usr/bin/env python3
"""
CloudOS Predictive Scaling System
AI-powered workload prediction and intelligent auto-scaling
"""

import asyncio
import json
import logging
import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from .ai_engine import CloudOSAIEngine, AIRequest, AITaskType

class ScalingAction(Enum):
    SCALE_OUT = "scale_out"
    SCALE_IN = "scale_in"
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    MAINTAIN = "maintain"

class WorkloadPattern(Enum):
    STEADY = "steady"
    GROWING = "growing"
    DECLINING = "declining"
    SPIKY = "spiky"
    PERIODIC = "periodic"
    UNKNOWN = "unknown"

@dataclass
class ScalingMetrics:
    timestamp: datetime
    cpu_utilization: float
    memory_utilization: float
    network_io: float
    request_rate: float
    response_time: float
    error_rate: float
    active_connections: int

@dataclass
class ScalingPrediction:
    predicted_cpu: float
    predicted_memory: float
    predicted_requests: float
    confidence: float
    time_horizon: timedelta
    pattern: WorkloadPattern
    reasoning: str

@dataclass
class ScalingDecision:
    action: ScalingAction
    target_instances: int
    target_resources: Dict[str, float]
    urgency: str  # low, medium, high, critical
    reasoning: str
    estimated_impact: Dict[str, Any]
    rollback_plan: Dict[str, Any]

class PredictiveScaler:
    """
    AI-powered predictive scaling system for CloudOS
    """

    def __init__(self, ai_engine: CloudOSAIEngine, config: Dict[str, Any] = None):
        self.ai_engine = ai_engine
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Scaling configuration
        self.min_instances = self.config.get('min_instances', 1)
        self.max_instances = self.config.get('max_instances', 50)
        self.target_cpu_utilization = self.config.get('target_cpu', 70.0)
        self.target_memory_utilization = self.config.get('target_memory', 70.0)

        # Prediction settings
        self.prediction_window = timedelta(minutes=self.config.get('prediction_window_minutes', 30))
        self.metrics_history_size = self.config.get('metrics_history_size', 1000)
        self.confidence_threshold = self.config.get('confidence_threshold', 0.7)

        # Metrics storage
        self.metrics_history: List[ScalingMetrics] = []
        self.predictions_history: List[ScalingPrediction] = []

        # Pattern detection
        self.detected_patterns: Dict[str, WorkloadPattern] = {}
        self.pattern_confidence: Dict[str, float] = {}

        # Scaling state
        self.current_instances = 1
        self.last_scaling_action = None
        self.last_scaling_time = None
        self.cooldown_period = timedelta(minutes=self.config.get('cooldown_minutes', 5))

        # Learning system
        self.prediction_accuracy = []
        self.scaling_effectiveness = []

        self.logger.info("Predictive Scaler initialized")

    async def add_metrics(self, metrics: ScalingMetrics):
        """Add new metrics for analysis"""
        self.metrics_history.append(metrics)

        # Keep only recent history
        if len(self.metrics_history) > self.metrics_history_size:
            self.metrics_history = self.metrics_history[-self.metrics_history_size:]

        # Update pattern detection
        await self._update_pattern_detection()

        self.logger.debug(f"Added metrics: CPU={metrics.cpu_utilization:.1f}%, "
                         f"Memory={metrics.memory_utilization:.1f}%, "
                         f"Requests={metrics.request_rate:.1f}/s")

    async def predict_workload(self, time_horizon: timedelta = None) -> ScalingPrediction:
        """Predict future workload patterns"""
        if time_horizon is None:
            time_horizon = self.prediction_window

        if len(self.metrics_history) < 10:
            # Not enough data for prediction
            latest = self.metrics_history[-1] if self.metrics_history else None
            if latest:
                return ScalingPrediction(
                    predicted_cpu=latest.cpu_utilization,
                    predicted_memory=latest.memory_utilization,
                    predicted_requests=latest.request_rate,
                    confidence=0.3,
                    time_horizon=time_horizon,
                    pattern=WorkloadPattern.UNKNOWN,
                    reasoning="Insufficient historical data for prediction"
                )

        # Prepare data for AI prediction
        recent_metrics = self.metrics_history[-50:]  # Last 50 data points
        historical_data = [
            {
                'timestamp': m.timestamp.isoformat(),
                'cpu_usage': m.cpu_utilization,
                'memory_usage': m.memory_utilization,
                'request_rate': m.request_rate,
                'response_time': m.response_time
            } for m in recent_metrics
        ]

        # Request prediction from AI engine
        request = AIRequest(
            task_id=f"workload_pred_{int(datetime.now().timestamp())}",
            task_type=AITaskType.WORKLOAD_PREDICTION,
            data={
                'historical_metrics': historical_data,
                'time_horizon_minutes': int(time_horizon.total_seconds() / 60),
                'current_instances': self.current_instances
            }
        )

        # For immediate response, use statistical prediction
        # In production, this would await the AI response
        prediction = await self._statistical_prediction(time_horizon)

        # Store prediction for accuracy tracking
        self.predictions_history.append(prediction)
        if len(self.predictions_history) > 100:
            self.predictions_history = self.predictions_history[-100:]

        return prediction

    async def make_scaling_decision(self) -> Optional[ScalingDecision]:
        """Make an intelligent scaling decision"""
        if len(self.metrics_history) < 5:
            return None

        # Check cooldown period
        if (self.last_scaling_time and
            datetime.now() - self.last_scaling_time < self.cooldown_period):
            self.logger.debug("Scaling in cooldown period")
            return None

        # Get current state
        latest_metrics = self.metrics_history[-1]
        recent_avg = self._calculate_recent_averages(minutes=5)

        # Get prediction
        prediction = await self.predict_workload()

        # Analyze scaling needs
        scaling_decision = await self._analyze_scaling_needs(
            latest_metrics, recent_avg, prediction
        )

        if scaling_decision and scaling_decision.action != ScalingAction.MAINTAIN:
            self.last_scaling_action = scaling_decision
            self.last_scaling_time = datetime.now()
            self.logger.info(f"Scaling decision: {scaling_decision.action.value} "
                           f"to {scaling_decision.target_instances} instances")

        return scaling_decision

    async def execute_scaling(self, decision: ScalingDecision) -> bool:
        """Execute a scaling decision"""
        try:
            self.logger.info(f"Executing scaling action: {decision.action.value}")

            # In a real implementation, this would:
            # 1. Call cloud provider APIs
            # 2. Update container orchestrator
            # 3. Monitor scaling progress
            # 4. Handle rollback if needed

            # Update current state
            if decision.action in [ScalingAction.SCALE_OUT, ScalingAction.SCALE_IN]:
                old_instances = self.current_instances
                self.current_instances = decision.target_instances

                self.logger.info(f"Scaled from {old_instances} to {self.current_instances} instances")

            return True

        except Exception as e:
            self.logger.error(f"Scaling execution failed: {e}")
            return False

    async def get_scaling_recommendations(self) -> Dict[str, Any]:
        """Get comprehensive scaling recommendations"""
        if not self.metrics_history:
            return {'error': 'No metrics available'}

        # Current state
        latest = self.metrics_history[-1]
        recent_avg = self._calculate_recent_averages(minutes=10)

        # Predictions
        short_term = await self.predict_workload(timedelta(minutes=15))
        medium_term = await self.predict_workload(timedelta(minutes=60))

        # Scaling analysis
        scaling_decision = await self.make_scaling_decision()

        # Pattern analysis
        detected_pattern = await self._detect_current_pattern()

        return {
            'current_state': {
                'instances': self.current_instances,
                'cpu_utilization': latest.cpu_utilization,
                'memory_utilization': latest.memory_utilization,
                'request_rate': latest.request_rate,
                'response_time': latest.response_time
            },
            'recent_averages': recent_avg,
            'predictions': {
                'short_term': {
                    'cpu': short_term.predicted_cpu,
                    'memory': short_term.predicted_memory,
                    'confidence': short_term.confidence
                },
                'medium_term': {
                    'cpu': medium_term.predicted_cpu,
                    'memory': medium_term.predicted_memory,
                    'confidence': medium_term.confidence
                }
            },
            'pattern_detection': {
                'current_pattern': detected_pattern.value,
                'confidence': self.pattern_confidence.get(detected_pattern.value, 0.5)
            },
            'scaling_recommendation': {
                'action': scaling_decision.action.value if scaling_decision else 'maintain',
                'target_instances': scaling_decision.target_instances if scaling_decision else self.current_instances,
                'reasoning': scaling_decision.reasoning if scaling_decision else 'No scaling needed',
                'urgency': scaling_decision.urgency if scaling_decision else 'none'
            },
            'performance_metrics': {
                'prediction_accuracy': statistics.mean(self.prediction_accuracy) if self.prediction_accuracy else 0,
                'scaling_effectiveness': statistics.mean(self.scaling_effectiveness) if self.scaling_effectiveness else 0
            },
            'timestamp': datetime.now().isoformat()
        }

    async def _statistical_prediction(self, time_horizon: timedelta) -> ScalingPrediction:
        """Statistical prediction as fallback when AI is not available"""
        recent_metrics = self.metrics_history[-20:]  # Last 20 data points

        # Calculate trends
        cpu_values = [m.cpu_utilization for m in recent_metrics]
        memory_values = [m.memory_utilization for m in recent_metrics]
        request_values = [m.request_rate for m in recent_metrics]

        # Simple linear trend
        def calculate_trend(values):
            if len(values) < 2:
                return 0
            x = list(range(len(values)))
            n = len(values)
            sum_x = sum(x)
            sum_y = sum(values)
            sum_xy = sum(x[i] * values[i] for i in range(n))
            sum_x2 = sum(xi * xi for xi in x)

            if n * sum_x2 - sum_x * sum_x == 0:
                return 0

            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            return slope

        cpu_trend = calculate_trend(cpu_values)
        memory_trend = calculate_trend(memory_values)
        request_trend = calculate_trend(request_values)

        # Project future values
        time_steps = int(time_horizon.total_seconds() / 300)  # 5-minute intervals

        predicted_cpu = max(0, min(100, cpu_values[-1] + cpu_trend * time_steps))
        predicted_memory = max(0, min(100, memory_values[-1] + memory_trend * time_steps))
        predicted_requests = max(0, request_values[-1] + request_trend * time_steps)

        # Estimate confidence based on trend consistency
        cpu_variance = statistics.variance(cpu_values) if len(cpu_values) > 1 else 100
        confidence = max(0.3, min(0.9, 1.0 - (cpu_variance / 100)))

        # Detect pattern
        pattern = await self._detect_current_pattern()

        return ScalingPrediction(
            predicted_cpu=predicted_cpu,
            predicted_memory=predicted_memory,
            predicted_requests=predicted_requests,
            confidence=confidence,
            time_horizon=time_horizon,
            pattern=pattern,
            reasoning=f"Statistical trend analysis: CPU trend={cpu_trend:.2f}, confidence={confidence:.2f}"
        )

    async def _analyze_scaling_needs(self, latest: ScalingMetrics,
                                   recent_avg: Dict[str, float],
                                   prediction: ScalingPrediction) -> Optional[ScalingDecision]:
        """Analyze current state and predictions to make scaling decision"""

        # Current resource utilization
        cpu_util = recent_avg['cpu_utilization']
        memory_util = recent_avg['memory_utilization']

        # Predicted utilization
        pred_cpu = prediction.predicted_cpu
        pred_memory = prediction.predicted_memory

        # Decision factors
        current_overload = (cpu_util > 80 or memory_util > 80)
        predicted_overload = (pred_cpu > 80 or pred_memory > 80)
        current_underload = (cpu_util < 30 and memory_util < 30 and self.current_instances > self.min_instances)
        predicted_underload = (pred_cpu < 30 and pred_memory < 30)

        # High confidence predictions carry more weight
        prediction_weight = prediction.confidence

        action = ScalingAction.MAINTAIN
        target_instances = self.current_instances
        urgency = "low"
        reasoning = "Current load is within acceptable range"

        if current_overload or (predicted_overload and prediction_weight > 0.6):
            # Scale out needed
            if current_overload:
                urgency = "high"
                reasoning = "Current resource utilization is too high"
            else:
                urgency = "medium"
                reasoning = f"Predicted overload in {prediction.time_horizon} (confidence: {prediction.confidence:.2f})"

            # Calculate target instances
            max_util = max(cpu_util, memory_util, pred_cpu, pred_memory)
            scale_factor = max_util / self.target_cpu_utilization
            target_instances = min(self.max_instances,
                                 max(self.current_instances + 1,
                                     math.ceil(self.current_instances * scale_factor)))
            action = ScalingAction.SCALE_OUT

        elif current_underload and (predicted_underload or prediction_weight < 0.4):
            # Scale in possible
            urgency = "low"
            reasoning = "Resources are underutilized"

            # Conservative scale-in
            target_instances = max(self.min_instances, self.current_instances - 1)
            action = ScalingAction.SCALE_IN

        # Additional checks based on other metrics
        if latest.response_time > 1000:  # High response time
            if action == ScalingAction.SCALE_IN:
                action = ScalingAction.MAINTAIN
                reasoning = "High response time prevents scale-in"
            elif action == ScalingAction.MAINTAIN:
                action = ScalingAction.SCALE_OUT
                target_instances = self.current_instances + 1
                urgency = "medium"
                reasoning = "High response time indicates need for more resources"

        if latest.error_rate > 5:  # High error rate
            if action == ScalingAction.SCALE_IN:
                action = ScalingAction.MAINTAIN
                reasoning = "High error rate prevents scale-in"

        if action == ScalingAction.MAINTAIN:
            return None

        # Estimate impact
        estimated_impact = {
            'cpu_reduction': (max_util - self.target_cpu_utilization) / target_instances if action == ScalingAction.SCALE_OUT else 0,
            'cost_change': self._estimate_cost_change(self.current_instances, target_instances),
            'performance_improvement': 'high' if urgency == 'high' else 'medium'
        }

        # Rollback plan
        rollback_plan = {
            'condition': 'If metrics don\'t improve within 10 minutes',
            'action': f'Return to {self.current_instances} instances'
        }

        return ScalingDecision(
            action=action,
            target_instances=target_instances,
            target_resources={'cpu': self.target_cpu_utilization, 'memory': self.target_memory_utilization},
            urgency=urgency,
            reasoning=reasoning,
            estimated_impact=estimated_impact,
            rollback_plan=rollback_plan
        )

    def _calculate_recent_averages(self, minutes: int = 5) -> Dict[str, float]:
        """Calculate average metrics for recent time window"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        recent_metrics = [m for m in self.metrics_history if m.timestamp > cutoff_time]

        if not recent_metrics:
            return {}

        return {
            'cpu_utilization': statistics.mean(m.cpu_utilization for m in recent_metrics),
            'memory_utilization': statistics.mean(m.memory_utilization for m in recent_metrics),
            'request_rate': statistics.mean(m.request_rate for m in recent_metrics),
            'response_time': statistics.mean(m.response_time for m in recent_metrics),
            'error_rate': statistics.mean(m.error_rate for m in recent_metrics)
        }

    async def _update_pattern_detection(self):
        """Update workload pattern detection"""
        if len(self.metrics_history) < 50:
            return

        # Analyze recent patterns
        recent_cpu = [m.cpu_utilization for m in self.metrics_history[-50:]]

        # Calculate variance and trend
        variance = statistics.variance(recent_cpu)
        trend = self._calculate_trend(recent_cpu)

        # Pattern classification
        if variance < 100:  # Low variance
            if abs(trend) < 0.1:
                pattern = WorkloadPattern.STEADY
            elif trend > 0.1:
                pattern = WorkloadPattern.GROWING
            else:
                pattern = WorkloadPattern.DECLINING
        else:  # High variance
            if self._detect_periodicity(recent_cpu):
                pattern = WorkloadPattern.PERIODIC
            else:
                pattern = WorkloadPattern.SPIKY

        # Update pattern confidence
        pattern_key = pattern.value
        if pattern_key not in self.pattern_confidence:
            self.pattern_confidence[pattern_key] = 0.5

        # Increase confidence if pattern is consistent
        if pattern_key in self.detected_patterns and self.detected_patterns[pattern_key] == pattern:
            self.pattern_confidence[pattern_key] = min(0.95, self.pattern_confidence[pattern_key] + 0.05)
        else:
            self.pattern_confidence[pattern_key] = 0.6

        self.detected_patterns[pattern_key] = pattern

    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate linear trend in values"""
        if len(values) < 2:
            return 0

        x = list(range(len(values)))
        n = len(values)
        sum_x = sum(x)
        sum_y = sum(values)
        sum_xy = sum(x[i] * values[i] for i in range(n))
        sum_x2 = sum(xi * xi for xi in x)

        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0

        slope = (n * sum_xy - sum_x * sum_y) / denominator
        return slope

    def _detect_periodicity(self, values: List[float]) -> bool:
        """Simple periodicity detection"""
        if len(values) < 20:
            return False

        # Check for repeated patterns
        for period in range(5, len(values) // 4):
            correlation = 0
            comparisons = 0

            for i in range(period, len(values)):
                diff = abs(values[i] - values[i - period])
                correlation += 1 if diff < statistics.stdev(values) else 0
                comparisons += 1

            if comparisons > 0 and correlation / comparisons > 0.7:
                return True

        return False

    async def _detect_current_pattern(self) -> WorkloadPattern:
        """Detect current workload pattern"""
        if not self.detected_patterns:
            return WorkloadPattern.UNKNOWN

        # Return most confident pattern
        best_pattern = max(self.pattern_confidence.items(), key=lambda x: x[1])
        pattern_name = best_pattern[0]

        for pattern in WorkloadPattern:
            if pattern.value == pattern_name:
                return pattern

        return WorkloadPattern.UNKNOWN

    def _estimate_cost_change(self, current_instances: int, target_instances: int) -> str:
        """Estimate cost change from scaling"""
        if target_instances > current_instances:
            increase = (target_instances - current_instances) / current_instances * 100
            return f"+{increase:.1f}% cost increase"
        elif target_instances < current_instances:
            decrease = (current_instances - target_instances) / current_instances * 100
            return f"-{decrease:.1f}% cost reduction"
        else:
            return "No cost change"

if __name__ == "__main__":
    # Example usage
    import asyncio
    from .ai_engine import CloudOSAIEngine

    async def test_predictive_scaler():
        # Initialize components
        ai_engine = CloudOSAIEngine()
        await ai_engine.start()

        scaler = PredictiveScaler(ai_engine)

        # Simulate metrics
        base_time = datetime.now()
        for i in range(50):
            metrics = ScalingMetrics(
                timestamp=base_time + timedelta(minutes=i * 5),
                cpu_utilization=50 + 20 * math.sin(i * 0.1) + (i * 0.5),
                memory_utilization=40 + 15 * math.cos(i * 0.1),
                network_io=100 + 50 * math.sin(i * 0.2),
                request_rate=200 + 100 * math.sin(i * 0.15),
                response_time=200 + 50 * math.sin(i * 0.1),
                error_rate=1 + 2 * math.sin(i * 0.05),
                active_connections=500 + 200 * math.sin(i * 0.1)
            )
            await scaler.add_metrics(metrics)

        # Get predictions and recommendations
        prediction = await scaler.predict_workload()
        print(f"Workload prediction: {prediction.predicted_cpu:.1f}% CPU, confidence: {prediction.confidence:.2f}")

        recommendations = await scaler.get_scaling_recommendations()
        print(f"Scaling recommendations: {json.dumps(recommendations, indent=2)}")

        # Make scaling decision
        decision = await scaler.make_scaling_decision()
        if decision:
            print(f"Scaling decision: {decision.action.value} to {decision.target_instances} instances")
            print(f"Reasoning: {decision.reasoning}")

        await ai_engine.stop()

    # Run test
    asyncio.run(test_predictive_scaler())