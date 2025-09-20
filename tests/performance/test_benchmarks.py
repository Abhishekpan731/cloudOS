#!/usr/bin/env python3
"""
Performance benchmarks for CloudOS components
"""

import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from statistics import mean, stdev
from typing import Dict, List, Any
import pytest

# Add project paths
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "ai" / "engine" / "core"))
sys.path.insert(0, str(project_root / "ai" / "core"))

try:
    from ai_engine import CloudOSAIEngine, AIRequest, AITaskType
    from runtime import AIRuntime, ModelMetadata, ModelFormat, InferenceRequest, InferenceMode
    HAS_AI_MODULES = True
except ImportError:
    HAS_AI_MODULES = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PerformanceTimer:
    """Context manager for timing operations"""

    def __init__(self, name: str):
        self.name = name
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()

    @property
    def duration(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

class BenchmarkResult:
    """Container for benchmark results"""

    def __init__(self, name: str, duration: float, throughput: float = 0.0,
                 memory_usage: float = 0.0, metadata: Dict[str, Any] = None):
        self.name = name
        self.duration = duration
        self.throughput = throughput
        self.memory_usage = memory_usage
        self.metadata = metadata or {}
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'duration': self.duration,
            'throughput': self.throughput,
            'memory_usage': self.memory_usage,
            'metadata': self.metadata,
            'timestamp': self.timestamp
        }

@pytest.mark.skipif(not HAS_AI_MODULES, reason="AI modules not available")
class TestAIEngineBenchmarks:
    """Benchmark tests for AI Engine performance"""

    @pytest.fixture
    async def ai_engine(self):
        """Create AI engine for benchmarking"""
        config = {
            'ai_workers': 4,
            'max_queue_size': 1000
        }
        engine = CloudOSAIEngine(config)
        await engine.start()
        yield engine
        await engine.stop()

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_ai_engine_startup_time(self):
        """Benchmark AI engine startup time"""
        results = []

        for i in range(5):  # Run 5 times for average
            with PerformanceTimer(f"startup_{i}") as timer:
                engine = CloudOSAIEngine({'ai_workers': 2})
                await engine.start()
                await engine.stop()

            results.append(timer.duration)

        avg_startup = mean(results)
        std_startup = stdev(results) if len(results) > 1 else 0

        # Performance assertions
        assert avg_startup < 5.0, f"Startup time too slow: {avg_startup:.2f}s"

        benchmark = BenchmarkResult(
            name="ai_engine_startup",
            duration=avg_startup,
            metadata={
                'std_dev': std_startup,
                'min_time': min(results),
                'max_time': max(results),
                'samples': len(results)
            }
        )

        logger.info(f"AI Engine Startup: {avg_startup:.2f}s ± {std_startup:.2f}s")
        return benchmark

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_single_task_latency(self, ai_engine):
        """Benchmark single task processing latency"""
        latencies = []

        for i in range(100):
            request = AIRequest(
                task_id=f"latency_test_{i}",
                task_type=AITaskType.RESOURCE_OPTIMIZATION,
                data={'node_metrics': {'node1': {'cpu_usage': 50 + i % 40, 'memory_usage': 60}}}
            )

            start_time = time.perf_counter()
            await ai_engine.submit_task(request)
            # For latency test, we measure submission time
            end_time = time.perf_counter()

            latencies.append((end_time - start_time) * 1000)  # Convert to ms

        # Wait for processing to complete
        await asyncio.sleep(2)

        avg_latency = mean(latencies)
        p95_latency = sorted(latencies)[int(0.95 * len(latencies))]
        p99_latency = sorted(latencies)[int(0.99 * len(latencies))]

        # Performance assertions
        assert avg_latency < 10.0, f"Average latency too high: {avg_latency:.2f}ms"
        assert p95_latency < 50.0, f"P95 latency too high: {p95_latency:.2f}ms"

        benchmark = BenchmarkResult(
            name="single_task_latency",
            duration=avg_latency / 1000,  # Convert back to seconds
            metadata={
                'avg_latency_ms': avg_latency,
                'p95_latency_ms': p95_latency,
                'p99_latency_ms': p99_latency,
                'min_latency_ms': min(latencies),
                'max_latency_ms': max(latencies)
            }
        )

        logger.info(f"Task Latency - Avg: {avg_latency:.2f}ms, P95: {p95_latency:.2f}ms, P99: {p99_latency:.2f}ms")
        return benchmark

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_throughput_capacity(self, ai_engine):
        """Benchmark maximum throughput capacity"""
        task_counts = [10, 50, 100, 200, 500]
        throughput_results = []

        for task_count in task_counts:
            with PerformanceTimer(f"throughput_{task_count}") as timer:
                tasks = []
                for i in range(task_count):
                    request = AIRequest(
                        task_id=f"throughput_test_{task_count}_{i}",
                        task_type=AITaskType.RESOURCE_OPTIMIZATION,
                        data={'node_metrics': {'node1': {'cpu_usage': 50, 'memory_usage': 60}}}
                    )
                    tasks.append(ai_engine.submit_task(request))

                # Submit all tasks
                await asyncio.gather(*tasks)

                # Wait for processing
                await asyncio.sleep(max(1, task_count / 100))  # Scale wait time

            throughput = task_count / timer.duration
            throughput_results.append((task_count, throughput, timer.duration))

        # Find peak throughput
        peak_throughput = max(throughput_results, key=lambda x: x[1])

        # Performance assertion
        assert peak_throughput[1] > 100, f"Peak throughput too low: {peak_throughput[1]:.2f} tasks/sec"

        benchmark = BenchmarkResult(
            name="throughput_capacity",
            duration=peak_throughput[2],
            throughput=peak_throughput[1],
            metadata={
                'peak_task_count': peak_throughput[0],
                'all_results': throughput_results
            }
        )

        logger.info(f"Peak Throughput: {peak_throughput[1]:.2f} tasks/sec with {peak_throughput[0]} tasks")
        return benchmark

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_concurrent_load(self, ai_engine):
        """Benchmark performance under concurrent load"""
        concurrent_levels = [1, 2, 4, 8, 16]
        results = []

        for concurrency in concurrent_levels:
            tasks_per_worker = 50
            total_tasks = concurrency * tasks_per_worker

            async def worker(worker_id: int):
                worker_start = time.perf_counter()
                for i in range(tasks_per_worker):
                    request = AIRequest(
                        task_id=f"concurrent_test_{concurrency}_{worker_id}_{i}",
                        task_type=AITaskType.WORKLOAD_PREDICTION,
                        data={'historical_metrics': [{'cpu_usage': 50, 'memory_usage': 60}]}
                    )
                    await ai_engine.submit_task(request)
                return time.perf_counter() - worker_start

            with PerformanceTimer(f"concurrent_{concurrency}") as timer:
                # Run workers concurrently
                worker_tasks = [worker(i) for i in range(concurrency)]
                worker_times = await asyncio.gather(*worker_tasks)

                # Wait for processing
                await asyncio.sleep(2)

            avg_worker_time = mean(worker_times)
            throughput = total_tasks / timer.duration

            results.append({
                'concurrency': concurrency,
                'total_tasks': total_tasks,
                'duration': timer.duration,
                'throughput': throughput,
                'avg_worker_time': avg_worker_time
            })

        # Find best concurrency level
        best_result = max(results, key=lambda x: x['throughput'])

        benchmark = BenchmarkResult(
            name="concurrent_load",
            duration=best_result['duration'],
            throughput=best_result['throughput'],
            metadata={
                'best_concurrency': best_result['concurrency'],
                'all_results': results
            }
        )

        logger.info(f"Best Concurrency: {best_result['concurrency']} workers, "
                   f"Throughput: {best_result['throughput']:.2f} tasks/sec")
        return benchmark

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_memory_efficiency(self, ai_engine):
        """Benchmark memory usage patterns"""
        import psutil
        import os

        process = psutil.Process(os.getpid())

        # Baseline memory
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Submit varying loads and measure memory
        load_tests = [100, 500, 1000, 2000]
        memory_results = []

        for load_size in load_tests:
            # Submit tasks
            tasks = []
            for i in range(load_size):
                request = AIRequest(
                    task_id=f"memory_test_{load_size}_{i}",
                    task_type=AITaskType.ANOMALY_DETECTION,
                    data={
                        'current_metrics': {'cpu_usage': 70, 'memory_usage': 80},
                        'baseline_metrics': {'cpu_usage': 50, 'memory_usage': 60}
                    }
                )
                tasks.append(ai_engine.submit_task(request))

            await asyncio.gather(*tasks)

            # Measure peak memory
            peak_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = peak_memory - baseline_memory

            # Wait for processing
            await asyncio.sleep(1)

            # Measure memory after processing
            post_memory = process.memory_info().rss / 1024 / 1024  # MB

            memory_results.append({
                'load_size': load_size,
                'baseline_mb': baseline_memory,
                'peak_mb': peak_memory,
                'post_mb': post_memory,
                'increase_mb': memory_increase,
                'mb_per_task': memory_increase / load_size if load_size > 0 else 0
            })

        # Check for memory leaks
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_leak = final_memory - baseline_memory

        # Performance assertions
        avg_mb_per_task = mean([r['mb_per_task'] for r in memory_results])
        assert avg_mb_per_task < 1.0, f"Memory usage per task too high: {avg_mb_per_task:.2f} MB/task"
        assert memory_leak < 50, f"Potential memory leak: {memory_leak:.2f} MB"

        benchmark = BenchmarkResult(
            name="memory_efficiency",
            duration=0.0,  # Not time-based
            memory_usage=final_memory,
            metadata={
                'baseline_memory_mb': baseline_memory,
                'final_memory_mb': final_memory,
                'memory_leak_mb': memory_leak,
                'avg_mb_per_task': avg_mb_per_task,
                'all_results': memory_results
            }
        )

        logger.info(f"Memory Efficiency - {avg_mb_per_task:.3f} MB/task, "
                   f"Leak: {memory_leak:.2f} MB")
        return benchmark

@pytest.mark.skipif(not HAS_AI_MODULES, reason="AI modules not available")
class TestAIRuntimeBenchmarks:
    """Benchmark tests for AI Runtime performance"""

    @pytest.fixture
    async def ai_runtime(self):
        """Create AI runtime for benchmarking"""
        config = {
            'num_workers': 4,
            'max_queue_size': 1000,
            'max_batch_size': 32
        }
        runtime = AIRuntime(config)
        await runtime.start()
        yield runtime
        await runtime.stop()

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_inference_latency(self, ai_runtime):
        """Benchmark inference request latency"""
        # Register a simple test model
        metadata = ModelMetadata(
            model_id="benchmark_model",
            name="Benchmark Model",
            version="1.0",
            format=ModelFormat.CUSTOM,
            input_shape={"input": [1, 10]},
            output_shape={"output": [1, 1]},
            model_path="/tmp/benchmark_model"
        )

        await ai_runtime.register_model(metadata)

        latencies = []

        for i in range(100):
            request = InferenceRequest(
                model_id="benchmark_model",
                inputs={"input": [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]},
                mode=InferenceMode.SYNC
            )

            start_time = time.perf_counter()
            response = await ai_runtime.predict(request)
            end_time = time.perf_counter()

            latencies.append((end_time - start_time) * 1000)  # ms

        avg_latency = mean(latencies)
        p95_latency = sorted(latencies)[int(0.95 * len(latencies))]

        benchmark = BenchmarkResult(
            name="inference_latency",
            duration=avg_latency / 1000,
            metadata={
                'avg_latency_ms': avg_latency,
                'p95_latency_ms': p95_latency,
                'min_latency_ms': min(latencies),
                'max_latency_ms': max(latencies)
            }
        )

        logger.info(f"Inference Latency - Avg: {avg_latency:.2f}ms, P95: {p95_latency:.2f}ms")
        return benchmark

    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_batch_processing_efficiency(self, ai_runtime):
        """Benchmark batch processing efficiency"""
        # Register test model
        metadata = ModelMetadata(
            model_id="batch_model",
            name="Batch Model",
            version="1.0",
            format=ModelFormat.CUSTOM,
            input_shape={"input": [32, 10]},  # Batch size 32
            output_shape={"output": [32, 1]},
            model_path="/tmp/batch_model",
            max_batch_size=32
        )

        await ai_runtime.register_model(metadata)

        batch_sizes = [1, 4, 8, 16, 32]
        results = []

        for batch_size in batch_sizes:
            requests = []
            for i in range(batch_size):
                request = InferenceRequest(
                    model_id="batch_model",
                    inputs={"input": [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]},
                    mode=InferenceMode.BATCH
                )
                requests.append(request)

            with PerformanceTimer(f"batch_{batch_size}") as timer:
                # Submit batch requests
                tasks = [ai_runtime.predict(req) for req in requests]
                await asyncio.gather(*tasks)

            throughput = batch_size / timer.duration
            results.append({
                'batch_size': batch_size,
                'duration': timer.duration,
                'throughput': throughput
            })

        # Find most efficient batch size
        best_result = max(results, key=lambda x: x['throughput'])

        benchmark = BenchmarkResult(
            name="batch_processing",
            duration=best_result['duration'],
            throughput=best_result['throughput'],
            metadata={
                'optimal_batch_size': best_result['batch_size'],
                'all_results': results
            }
        )

        logger.info(f"Optimal Batch Size: {best_result['batch_size']}, "
                   f"Throughput: {best_result['throughput']:.2f} req/sec")
        return benchmark

class TestSystemBenchmarks:
    """System-level benchmark tests"""

    @pytest.mark.benchmark
    def test_file_io_performance(self):
        """Benchmark file I/O performance"""
        import tempfile

        file_sizes = [1024, 10240, 102400, 1048576]  # 1KB to 1MB
        results = []

        for size in file_sizes:
            data = b'x' * size

            with tempfile.NamedTemporaryFile() as tmp_file:
                # Write benchmark
                with PerformanceTimer(f"write_{size}") as write_timer:
                    tmp_file.write(data)
                    tmp_file.flush()

                # Read benchmark
                tmp_file.seek(0)
                with PerformanceTimer(f"read_{size}") as read_timer:
                    read_data = tmp_file.read()

                assert len(read_data) == size

                write_throughput = size / write_timer.duration / 1024 / 1024  # MB/s
                read_throughput = size / read_timer.duration / 1024 / 1024  # MB/s

                results.append({
                    'size_bytes': size,
                    'write_duration': write_timer.duration,
                    'read_duration': read_timer.duration,
                    'write_throughput_mb_s': write_throughput,
                    'read_throughput_mb_s': read_throughput
                })

        # Performance assertions
        avg_write_throughput = mean([r['write_throughput_mb_s'] for r in results])
        avg_read_throughput = mean([r['read_throughput_mb_s'] for r in results])

        assert avg_write_throughput > 50, f"Write throughput too low: {avg_write_throughput:.2f} MB/s"
        assert avg_read_throughput > 100, f"Read throughput too low: {avg_read_throughput:.2f} MB/s"

        benchmark = BenchmarkResult(
            name="file_io_performance",
            duration=0.0,
            throughput=avg_write_throughput,
            metadata={
                'avg_write_throughput_mb_s': avg_write_throughput,
                'avg_read_throughput_mb_s': avg_read_throughput,
                'all_results': results
            }
        )

        logger.info(f"File I/O - Write: {avg_write_throughput:.2f} MB/s, "
                   f"Read: {avg_read_throughput:.2f} MB/s")
        return benchmark

    @pytest.mark.benchmark
    def test_json_processing_performance(self):
        """Benchmark JSON processing performance"""
        import json

        # Create test data of varying sizes
        test_data_sizes = [100, 1000, 10000, 100000]  # Number of records
        results = []

        for size in test_data_sizes:
            # Generate test data
            test_data = {
                'metrics': [
                    {
                        'timestamp': time.time() + i,
                        'cpu_usage': 50 + (i % 50),
                        'memory_usage': 60 + (i % 40),
                        'node_id': f'node_{i % 100}',
                        'tags': {'env': 'test', 'version': '1.0'}
                    }
                    for i in range(size)
                ]
            }

            # Serialize benchmark
            with PerformanceTimer(f"json_serialize_{size}") as serialize_timer:
                json_str = json.dumps(test_data)

            # Deserialize benchmark
            with PerformanceTimer(f"json_deserialize_{size}") as deserialize_timer:
                parsed_data = json.loads(json_str)

            assert len(parsed_data['metrics']) == size

            serialize_rate = size / serialize_timer.duration
            deserialize_rate = size / deserialize_timer.duration

            results.append({
                'size': size,
                'serialize_duration': serialize_timer.duration,
                'deserialize_duration': deserialize_timer.duration,
                'serialize_rate': serialize_rate,
                'deserialize_rate': deserialize_rate,
                'json_size_bytes': len(json_str)
            })

        avg_serialize_rate = mean([r['serialize_rate'] for r in results])
        avg_deserialize_rate = mean([r['deserialize_rate'] for r in results])

        benchmark = BenchmarkResult(
            name="json_processing",
            duration=0.0,
            throughput=avg_serialize_rate,
            metadata={
                'avg_serialize_rate': avg_serialize_rate,
                'avg_deserialize_rate': avg_deserialize_rate,
                'all_results': results
            }
        )

        logger.info(f"JSON Processing - Serialize: {avg_serialize_rate:.0f} records/sec, "
                   f"Deserialize: {avg_deserialize_rate:.0f} records/sec")
        return benchmark

def save_benchmark_results(results: List[BenchmarkResult], output_file: str = None):
    """Save benchmark results to file"""
    if output_file is None:
        output_file = f"benchmark_results_{int(time.time())}.json"

    output_data = {
        'timestamp': time.time(),
        'results': [result.to_dict() for result in results]
    }

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    logger.info(f"Benchmark results saved to {output_file}")

if __name__ == "__main__":
    # Run benchmarks with appropriate markers
    pytest.main([
        __file__,
        "-v",
        "-m", "benchmark",
        "--tb=short",
        "--log-cli-level=INFO"
    ])