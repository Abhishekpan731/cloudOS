#!/usr/bin/env python3
"""
Unit tests for CloudOS AI Engine
"""

import asyncio
import json
import pytest
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

# Add AI engine to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../ai/engine/core'))

from ai_engine import (
    CloudOSAIEngine, AIRequest, AIResponse, AITaskType, AIBackend,
    ResourceOptimizationModel, WorkloadPredictionModel, AnomalyDetectionModel
)

class TestCloudOSAIEngine:
    """Test suite for CloudOS AI Engine"""

    @pytest.fixture
    async def ai_engine(self):
        """Create AI engine instance for testing"""
        config = {'ai_workers': 2}
        engine = CloudOSAIEngine(config)
        await engine.start()
        yield engine
        await engine.stop()

    @pytest.fixture
    def sample_request(self):
        """Create sample AI request"""
        return AIRequest(
            task_id="test_001",
            task_type=AITaskType.RESOURCE_OPTIMIZATION,
            data={
                'node_metrics': {
                    'node1': {'cpu_usage': 85, 'memory_usage': 70},
                    'node2': {'cpu_usage': 60, 'memory_usage': 90}
                }
            }
        )

    def test_ai_engine_initialization(self):
        """Test AI engine initialization"""
        engine = CloudOSAIEngine()

        assert engine.backend in [AIBackend.TENSORFLOW, AIBackend.PYTORCH, AIBackend.ONNX, AIBackend.NUMPY]
        assert len(engine.models) == 7  # All task types should have models
        assert engine.metrics['tasks_processed'] == 0
        assert not engine.running

    def test_backend_detection(self):
        """Test AI backend detection"""
        engine = CloudOSAIEngine()
        backend = engine._detect_best_backend()

        # Should detect available backend
        assert isinstance(backend, AIBackend)
        assert backend.value in ['tensorflow', 'pytorch', 'onnx', 'numpy']

    @pytest.mark.asyncio
    async def test_engine_start_stop(self, ai_engine):
        """Test engine start and stop"""
        assert ai_engine.running
        assert len(ai_engine.worker_threads) == 2

        # Test stop (already called in fixture teardown)
        await ai_engine.stop()
        assert not ai_engine.running

    @pytest.mark.asyncio
    async def test_submit_task(self, ai_engine, sample_request):
        """Test task submission"""
        task_id = await ai_engine.submit_task(sample_request)

        assert task_id == sample_request.task_id
        # Give workers time to process
        await asyncio.sleep(0.5)

        # Check metrics
        metrics = ai_engine.get_metrics()
        assert metrics['tasks_processed'] >= 1

    def test_health_check(self, ai_engine):
        """Test health check functionality"""
        health = ai_engine.health_check()

        assert 'status' in health
        assert 'backend' in health
        assert 'models_status' in health
        assert 'last_check' in health

        # Should have status for all models
        assert len(health['models_status']) == 7

    def test_get_metrics(self, ai_engine):
        """Test metrics retrieval"""
        metrics = ai_engine.get_metrics()

        required_keys = [
            'tasks_processed', 'successful_requests', 'failed_requests',
            'avg_execution_time', 'models_loaded', 'backend', 'last_updated'
        ]

        for key in required_keys:
            assert key in metrics

class TestResourceOptimizationModel:
    """Test suite for Resource Optimization Model"""

    @pytest.fixture
    def model(self):
        """Create resource optimization model"""
        return ResourceOptimizationModel(AIBackend.NUMPY)

    def test_model_initialization(self, model):
        """Test model initialization"""
        assert model.backend == AIBackend.NUMPY
        assert model.is_trained
        assert model.model is not None

    def test_prediction_with_valid_data(self, model):
        """Test prediction with valid input data"""
        data = {
            'node_metrics': {
                'node1': {'cpu_usage': 85, 'memory_usage': 70},
                'node2': {'cpu_usage': 30, 'memory_usage': 40}
            }
        }

        result = model.predict(data)

        assert 'recommendations' in result
        assert 'confidence' in result
        assert 'timestamp' in result
        assert isinstance(result['recommendations'], dict)
        assert 0 <= result['confidence'] <= 1

    def test_prediction_high_cpu(self, model):
        """Test prediction for high CPU usage"""
        data = {
            'node_metrics': {
                'node1': {'cpu_usage': 90, 'memory_usage': 60}
            }
        }

        result = model.predict(data)
        recommendations = result['recommendations']

        assert 'node1' in recommendations
        assert recommendations['node1']['action'] == 'scale_out'
        assert recommendations['node1']['priority'] == 'high'

    def test_prediction_high_memory(self, model):
        """Test prediction for high memory usage"""
        data = {
            'node_metrics': {
                'node1': {'cpu_usage': 60, 'memory_usage': 90}
            }
        }

        result = model.predict(data)
        recommendations = result['recommendations']

        assert 'node1' in recommendations
        assert recommendations['node1']['action'] == 'add_memory'
        assert recommendations['node1']['priority'] == 'medium'

    def test_prediction_with_empty_data(self, model):
        """Test prediction with empty data"""
        data = {'node_metrics': {}}

        result = model.predict(data)

        assert 'recommendations' in result
        assert len(result['recommendations']) == 0

    def test_health_check(self, model):
        """Test model health check"""
        assert model.health_check() is True

class TestWorkloadPredictionModel:
    """Test suite for Workload Prediction Model"""

    @pytest.fixture
    def model(self):
        """Create workload prediction model"""
        return WorkloadPredictionModel(AIBackend.NUMPY)

    def test_prediction_with_historical_data(self, model):
        """Test prediction with historical data"""
        historical_data = []
        base_time = datetime.now()

        for i in range(10):
            historical_data.append({
                'timestamp': (base_time - timedelta(minutes=i*5)).isoformat(),
                'cpu_usage': 50 + i * 2,
                'memory_usage': 40 + i * 1.5
            })

        data = {'historical_metrics': historical_data}
        result = model.predict(data)

        assert 'predictions' in result
        assert 'confidence' in result
        assert 'timestamp' in result

        predictions = result['predictions']
        assert 'next_hour' in predictions
        assert 'trend' in predictions

    def test_prediction_without_data(self, model):
        """Test prediction without historical data"""
        data = {'historical_metrics': []}
        result = model.predict(data)

        assert 'error' in result
        assert result['confidence'] == 0.0

    def test_trend_analysis(self, model):
        """Test trend analysis functionality"""
        # Increasing trend data
        increasing_data = []
        for i in range(10):
            increasing_data.append({
                'timestamp': datetime.now().isoformat(),
                'cpu_usage': 30 + i * 5,  # Increasing
                'memory_usage': 40 + i * 3
            })

        data = {'historical_metrics': increasing_data}
        result = model.predict(data)

        predictions = result['predictions']
        assert predictions['trend']['cpu'] == 'increasing'

class TestAnomalyDetectionModel:
    """Test suite for Anomaly Detection Model"""

    @pytest.fixture
    def model(self):
        """Create anomaly detection model"""
        return AnomalyDetectionModel(AIBackend.NUMPY)

    def test_anomaly_detection_normal_metrics(self, model):
        """Test anomaly detection with normal metrics"""
        data = {
            'current_metrics': {
                'cpu_usage': 50,
                'memory_usage': 60,
                'response_time': 200
            },
            'baseline_metrics': {
                'cpu_usage': 55,
                'memory_usage': 58,
                'response_time': 210
            }
        }

        result = model.predict(data)

        assert 'anomalies' in result
        assert 'anomaly_count' in result
        assert result['anomaly_count'] == 0

    def test_anomaly_detection_with_anomalies(self, model):
        """Test anomaly detection with actual anomalies"""
        data = {
            'current_metrics': {
                'cpu_usage': 95,  # Very high
                'memory_usage': 30,  # Very low compared to baseline
                'response_time': 1000  # Very high
            },
            'baseline_metrics': {
                'cpu_usage': 50,
                'memory_usage': 60,
                'response_time': 200
            }
        }

        result = model.predict(data)

        assert result['anomaly_count'] > 0
        anomalies = result['anomalies']

        # Should detect CPU and response time anomalies
        anomaly_metrics = [a['metric'] for a in anomalies]
        assert 'cpu_usage' in anomaly_metrics
        assert 'response_time' in anomaly_metrics

    def test_severity_classification(self, model):
        """Test anomaly severity classification"""
        data = {
            'current_metrics': {
                'cpu_usage': 150,  # 200% deviation
                'memory_usage': 120
            },
            'baseline_metrics': {
                'cpu_usage': 50,
                'memory_usage': 60
            }
        }

        result = model.predict(data)
        anomalies = result['anomalies']

        # High deviation should result in high severity
        cpu_anomaly = next(a for a in anomalies if a['metric'] == 'cpu_usage')
        assert cpu_anomaly['severity'] == 'high'

class TestAIRequestResponse:
    """Test suite for AI Request/Response data structures"""

    def test_ai_request_creation(self):
        """Test AI request creation"""
        request = AIRequest(
            task_id="test_123",
            task_type=AITaskType.WORKLOAD_PREDICTION,
            data={'test': 'data'},
            priority=5
        )

        assert request.task_id == "test_123"
        assert request.task_type == AITaskType.WORKLOAD_PREDICTION
        assert request.data == {'test': 'data'}
        assert request.priority == 5
        assert isinstance(request.timestamp, datetime)

    def test_ai_request_auto_timestamp(self):
        """Test automatic timestamp generation"""
        request = AIRequest(
            task_id="test_auto",
            task_type=AITaskType.ANOMALY_DETECTION,
            data={}
        )

        assert request.timestamp is not None
        assert isinstance(request.timestamp, datetime)

    def test_ai_response_creation(self):
        """Test AI response creation"""
        response = AIResponse(
            task_id="test_123",
            task_type=AITaskType.COST_OPTIMIZATION,
            result={'savings': 100},
            confidence=0.85,
            execution_time=1.5
        )

        assert response.task_id == "test_123"
        assert response.task_type == AITaskType.COST_OPTIMIZATION
        assert response.result == {'savings': 100}
        assert response.confidence == 0.85
        assert response.execution_time == 1.5
        assert isinstance(response.timestamp, datetime)

@pytest.mark.asyncio
async def test_concurrent_task_processing():
    """Test concurrent task processing"""
    engine = CloudOSAIEngine({'ai_workers': 3})
    await engine.start()

    try:
        # Submit multiple tasks concurrently
        tasks = []
        for i in range(10):
            request = AIRequest(
                task_id=f"concurrent_test_{i}",
                task_type=AITaskType.RESOURCE_OPTIMIZATION,
                data={'node_metrics': {'node1': {'cpu_usage': 50 + i * 5, 'memory_usage': 60}}}
            )
            tasks.append(engine.submit_task(request))

        # Wait for all submissions
        await asyncio.gather(*tasks)

        # Give workers time to process
        await asyncio.sleep(2)

        # Check that all tasks were processed
        metrics = engine.get_metrics()
        assert metrics['tasks_processed'] >= 10

    finally:
        await engine.stop()

@pytest.mark.integration
class TestAIEngineIntegration:
    """Integration tests for AI Engine"""

    @pytest.mark.asyncio
    async def test_full_workflow(self):
        """Test complete AI engine workflow"""
        engine = CloudOSAIEngine()
        await engine.start()

        try:
            # Submit different types of tasks
            tasks = [
                AIRequest(
                    task_id="workflow_optimization",
                    task_type=AITaskType.RESOURCE_OPTIMIZATION,
                    data={'node_metrics': {'node1': {'cpu_usage': 85, 'memory_usage': 70}}}
                ),
                AIRequest(
                    task_id="workflow_prediction",
                    task_type=AITaskType.WORKLOAD_PREDICTION,
                    data={'historical_metrics': [
                        {'cpu_usage': 50, 'memory_usage': 60, 'timestamp': datetime.now().isoformat()}
                    ]}
                ),
                AIRequest(
                    task_id="workflow_anomaly",
                    task_type=AITaskType.ANOMALY_DETECTION,
                    data={
                        'current_metrics': {'cpu_usage': 95},
                        'baseline_metrics': {'cpu_usage': 50}
                    }
                )
            ]

            # Submit all tasks
            for task in tasks:
                await engine.submit_task(task)

            # Wait for processing
            await asyncio.sleep(3)

            # Verify processing
            metrics = engine.get_metrics()
            assert metrics['tasks_processed'] >= 3
            assert metrics['successful_requests'] >= 3

            # Health check should be positive
            health = engine.health_check()
            assert health['status'] == 'healthy'

        finally:
            await engine.stop()

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])