#!/usr/bin/env python3
"""
CloudOS AI Runtime - Core Infrastructure for AI Engine Operations
Provides high-performance inference runtime with model management and optimization
"""

import asyncio
import gc
import json
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable
import weakref

# Import AI/ML backends with fallbacks
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False

try:
    import torch
    HAS_PYTORCH = True
except ImportError:
    HAS_PYTORCH = False

try:
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False

class ModelFormat(Enum):
    TENSORFLOW_SAVEDMODEL = "tensorflow_savedmodel"
    TENSORFLOW_LITE = "tensorflow_lite"
    PYTORCH_JIT = "pytorch_jit"
    PYTORCH_STATE_DICT = "pytorch_state_dict"
    ONNX = "onnx"
    CUSTOM = "custom"

class ModelStatus(Enum):
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    WARMING_UP = "warming_up"
    READY = "ready"
    ERROR = "error"
    UNLOADING = "unloading"

class InferenceMode(Enum):
    SYNC = "sync"
    ASYNC = "async"
    BATCH = "batch"
    STREAMING = "streaming"

@dataclass
class ModelMetadata:
    """Metadata for AI models"""
    model_id: str
    name: str
    version: str
    format: ModelFormat
    input_shape: Dict[str, List[int]]
    output_shape: Dict[str, List[int]]
    model_path: str
    config_path: Optional[str] = None
    warmup_samples: int = 10
    max_batch_size: int = 32
    memory_usage_mb: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)

@dataclass
class InferenceRequest:
    """Request for model inference"""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str = ""
    inputs: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    mode: InferenceMode = InferenceMode.SYNC
    priority: int = 1
    timeout_seconds: float = 30.0
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class InferenceResponse:
    """Response from model inference"""
    request_id: str
    model_id: str
    outputs: Dict[str, Any]
    latency_ms: float
    status: str = "success"
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    completed_at: datetime = field(default_factory=datetime.now)

class ModelWrapper:
    """Wrapper for different model formats with unified interface"""

    def __init__(self, metadata: ModelMetadata):
        self.metadata = metadata
        self.model = None
        self.session = None
        self.status = ModelStatus.UNLOADED
        self.load_time = None
        self.last_inference = None
        self.inference_count = 0
        self.total_latency = 0.0
        self.logger = logging.getLogger(f"{__name__}.{metadata.model_id}")

    async def load(self) -> bool:
        """Load the model into memory"""
        try:
            self.status = ModelStatus.LOADING
            self.load_time = time.time()

            if self.metadata.format == ModelFormat.TENSORFLOW_SAVEDMODEL:
                await self._load_tensorflow_savedmodel()
            elif self.metadata.format == ModelFormat.TENSORFLOW_LITE:
                await self._load_tensorflow_lite()
            elif self.metadata.format == ModelFormat.PYTORCH_JIT:
                await self._load_pytorch_jit()
            elif self.metadata.format == ModelFormat.PYTORCH_STATE_DICT:
                await self._load_pytorch_state_dict()
            elif self.metadata.format == ModelFormat.ONNX:
                await self._load_onnx()
            else:
                raise ValueError(f"Unsupported model format: {self.metadata.format}")

            self.status = ModelStatus.LOADED
            await self._warmup()
            self.status = ModelStatus.READY

            self.logger.info(f"Model {self.metadata.model_id} loaded successfully")
            return True

        except Exception as e:
            self.status = ModelStatus.ERROR
            self.logger.error(f"Failed to load model {self.metadata.model_id}: {e}")
            return False

    async def _load_tensorflow_savedmodel(self):
        """Load TensorFlow SavedModel"""
        if not HAS_TENSORFLOW:
            raise RuntimeError("TensorFlow not available")

        self.model = tf.saved_model.load(self.metadata.model_path)

    async def _load_tensorflow_lite(self):
        """Load TensorFlow Lite model"""
        if not HAS_TENSORFLOW:
            raise RuntimeError("TensorFlow not available")

        self.model = tf.lite.Interpreter(model_path=self.metadata.model_path)
        self.model.allocate_tensors()

    async def _load_pytorch_jit(self):
        """Load PyTorch JIT model"""
        if not HAS_PYTORCH:
            raise RuntimeError("PyTorch not available")

        self.model = torch.jit.load(self.metadata.model_path)
        self.model.eval()

    async def _load_pytorch_state_dict(self):
        """Load PyTorch state dict (requires model architecture)"""
        if not HAS_PYTORCH:
            raise RuntimeError("PyTorch not available")

        # This would require the model architecture to be defined
        # For now, this is a placeholder
        raise NotImplementedError("PyTorch state dict loading requires model architecture")

    async def _load_onnx(self):
        """Load ONNX model"""
        if not HAS_ONNX:
            raise RuntimeError("ONNX Runtime not available")

        providers = ['CPUExecutionProvider']
        if ort.get_device() == 'GPU':
            providers.insert(0, 'CUDAExecutionProvider')

        self.session = ort.InferenceSession(self.metadata.model_path, providers=providers)

    async def _warmup(self):
        """Warm up the model with sample inputs"""
        try:
            self.status = ModelStatus.WARMING_UP

            # Generate dummy inputs based on input shape
            dummy_inputs = {}
            for input_name, shape in self.metadata.input_shape.items():
                if HAS_NUMPY:
                    dummy_inputs[input_name] = np.random.random(shape).astype(np.float32)
                else:
                    # Fallback for systems without numpy
                    dummy_inputs[input_name] = [[0.0] * shape[-1]] * shape[0] if len(shape) > 1 else [0.0] * shape[0]

            # Run warmup inferences
            for _ in range(self.metadata.warmup_samples):
                await self._infer(dummy_inputs)

            self.logger.info(f"Model {self.metadata.model_id} warmed up with {self.metadata.warmup_samples} samples")

        except Exception as e:
            self.logger.warning(f"Warmup failed for model {self.metadata.model_id}: {e}")

    async def _infer(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Perform inference with the loaded model"""
        if self.metadata.format == ModelFormat.TENSORFLOW_SAVEDMODEL:
            return await self._infer_tensorflow_savedmodel(inputs)
        elif self.metadata.format == ModelFormat.TENSORFLOW_LITE:
            return await self._infer_tensorflow_lite(inputs)
        elif self.metadata.format == ModelFormat.PYTORCH_JIT:
            return await self._infer_pytorch_jit(inputs)
        elif self.metadata.format == ModelFormat.ONNX:
            return await self._infer_onnx(inputs)
        else:
            raise ValueError(f"Inference not implemented for format: {self.metadata.format}")

    async def _infer_tensorflow_savedmodel(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """TensorFlow SavedModel inference"""
        if HAS_TENSORFLOW:
            tf_inputs = {k: tf.constant(v) for k, v in inputs.items()}
            outputs = self.model(**tf_inputs)
            if isinstance(outputs, dict):
                return {k: v.numpy().tolist() for k, v in outputs.items()}
            else:
                return {"output": outputs.numpy().tolist()}
        else:
            return {"error": "TensorFlow not available"}

    async def _infer_tensorflow_lite(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """TensorFlow Lite inference"""
        if HAS_TENSORFLOW:
            input_details = self.model.get_input_details()
            output_details = self.model.get_output_details()

            # Set inputs
            for i, (name, data) in enumerate(inputs.items()):
                self.model.set_tensor(input_details[i]['index'], data)

            # Run inference
            self.model.invoke()

            # Get outputs
            outputs = {}
            for output_detail in output_details:
                output_data = self.model.get_tensor(output_detail['index'])
                outputs[output_detail['name']] = output_data.tolist()

            return outputs
        else:
            return {"error": "TensorFlow not available"}

    async def _infer_pytorch_jit(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """PyTorch JIT inference"""
        if HAS_PYTORCH:
            torch_inputs = [torch.tensor(v) for v in inputs.values()]
            with torch.no_grad():
                outputs = self.model(*torch_inputs)

            if isinstance(outputs, torch.Tensor):
                return {"output": outputs.cpu().numpy().tolist()}
            elif isinstance(outputs, (list, tuple)):
                return {f"output_{i}": out.cpu().numpy().tolist() for i, out in enumerate(outputs)}
            else:
                return {"output": str(outputs)}
        else:
            return {"error": "PyTorch not available"}

    async def _infer_onnx(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """ONNX inference"""
        if HAS_ONNX:
            input_feed = {}
            for input_meta in self.session.get_inputs():
                if input_meta.name in inputs:
                    input_feed[input_meta.name] = inputs[input_meta.name]

            outputs = self.session.run(None, input_feed)
            output_names = [output.name for output in self.session.get_outputs()]

            return {name: output.tolist() for name, output in zip(output_names, outputs)}
        else:
            return {"error": "ONNX Runtime not available"}

    async def predict(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Main prediction method with metrics tracking"""
        if self.status != ModelStatus.READY:
            return {"error": f"Model not ready (status: {self.status.value})"}

        start_time = time.time()
        try:
            outputs = await self._infer(inputs)
            latency = (time.time() - start_time) * 1000  # Convert to milliseconds

            # Update metrics
            self.inference_count += 1
            self.total_latency += latency
            self.last_inference = datetime.now()

            return outputs

        except Exception as e:
            latency = (time.time() - start_time) * 1000
            self.logger.error(f"Inference error for model {self.metadata.model_id}: {e}")
            return {"error": str(e)}

    async def unload(self):
        """Unload the model from memory"""
        try:
            self.status = ModelStatus.UNLOADING

            # Clear model references
            self.model = None
            self.session = None

            # Force garbage collection
            gc.collect()

            self.status = ModelStatus.UNLOADED
            self.logger.info(f"Model {self.metadata.model_id} unloaded")

        except Exception as e:
            self.logger.error(f"Error unloading model {self.metadata.model_id}: {e}")
            self.status = ModelStatus.ERROR

    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics"""
        avg_latency = self.total_latency / max(self.inference_count, 1)

        return {
            "model_id": self.metadata.model_id,
            "status": self.status.value,
            "inference_count": self.inference_count,
            "avg_latency_ms": round(avg_latency, 2),
            "total_latency_ms": round(self.total_latency, 2),
            "last_inference": self.last_inference.isoformat() if self.last_inference else None,
            "load_time": self.load_time,
            "memory_usage_mb": self.metadata.memory_usage_mb
        }

class AIRuntime:
    """High-performance AI inference runtime for CloudOS"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Model registry and management
        self.models: Dict[str, ModelWrapper] = {}
        self.model_registry: Dict[str, ModelMetadata] = {}
        self.model_locks: Dict[str, asyncio.Lock] = {}

        # Request queue and processing
        self.request_queue = asyncio.Queue(maxsize=self.config.get('max_queue_size', 1000))
        self.batch_queue = asyncio.Queue(maxsize=self.config.get('max_batch_queue_size', 100))

        # Thread pool for CPU-intensive operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', os.cpu_count())
        )

        # Runtime state
        self.running = False
        self.worker_tasks = []
        self.batch_worker_task = None

        # Metrics and monitoring
        self.metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'avg_latency_ms': 0.0,
            'models_loaded': 0,
            'queue_size': 0,
            'last_updated': datetime.now()
        }

        self.logger.info("AI Runtime initialized")

    async def start(self):
        """Start the AI runtime"""
        if self.running:
            return

        self.running = True
        self.logger.info("Starting AI Runtime...")

        # Start worker tasks
        num_workers = self.config.get('num_workers', 4)
        for i in range(num_workers):
            task = asyncio.create_task(self._worker_loop(i))
            self.worker_tasks.append(task)

        # Start batch processing worker
        self.batch_worker_task = asyncio.create_task(self._batch_worker_loop())

        self.logger.info(f"AI Runtime started with {num_workers} workers")

    async def stop(self):
        """Stop the AI runtime"""
        if not self.running:
            return

        self.running = False
        self.logger.info("Stopping AI Runtime...")

        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()

        if self.batch_worker_task:
            self.batch_worker_task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(*self.worker_tasks, self.batch_worker_task, return_exceptions=True)

        # Unload all models
        for model_id in list(self.models.keys()):
            await self.unload_model(model_id)

        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)

        self.logger.info("AI Runtime stopped")

    async def register_model(self, metadata: ModelMetadata) -> bool:
        """Register a new model in the runtime"""
        try:
            self.model_registry[metadata.model_id] = metadata
            self.model_locks[metadata.model_id] = asyncio.Lock()

            self.logger.info(f"Model {metadata.model_id} registered successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to register model {metadata.model_id}: {e}")
            return False

    async def load_model(self, model_id: str) -> bool:
        """Load a model into memory"""
        if model_id not in self.model_registry:
            self.logger.error(f"Model {model_id} not found in registry")
            return False

        if model_id in self.models:
            self.logger.info(f"Model {model_id} already loaded")
            return True

        async with self.model_locks[model_id]:
            try:
                metadata = self.model_registry[model_id]
                wrapper = ModelWrapper(metadata)

                success = await wrapper.load()
                if success:
                    self.models[model_id] = wrapper
                    self.metrics['models_loaded'] += 1
                    self.logger.info(f"Model {model_id} loaded successfully")
                    return True
                else:
                    return False

            except Exception as e:
                self.logger.error(f"Failed to load model {model_id}: {e}")
                return False

    async def unload_model(self, model_id: str) -> bool:
        """Unload a model from memory"""
        if model_id not in self.models:
            self.logger.warning(f"Model {model_id} not loaded")
            return True

        async with self.model_locks[model_id]:
            try:
                wrapper = self.models[model_id]
                await wrapper.unload()
                del self.models[model_id]
                self.metrics['models_loaded'] -= 1

                self.logger.info(f"Model {model_id} unloaded successfully")
                return True

            except Exception as e:
                self.logger.error(f"Failed to unload model {model_id}: {e}")
                return False

    async def predict(self, request: InferenceRequest) -> InferenceResponse:
        """Submit a prediction request"""
        if request.mode == InferenceMode.BATCH:
            await self.batch_queue.put(request)
        else:
            await self.request_queue.put(request)

        # For async mode, return immediately with request ID
        if request.mode == InferenceMode.ASYNC:
            return InferenceResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                outputs={"status": "submitted"},
                latency_ms=0.0,
                status="submitted"
            )

        # For sync mode, this would need a response mechanism
        # For now, return a placeholder
        return InferenceResponse(
            request_id=request.request_id,
            model_id=request.model_id,
            outputs={"status": "processing"},
            latency_ms=0.0,
            status="processing"
        )

    async def _worker_loop(self, worker_id: int):
        """Main worker loop for processing inference requests"""
        self.logger.info(f"Worker {worker_id} started")

        while self.running:
            try:
                # Get request with timeout
                try:
                    request = await asyncio.wait_for(self.request_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                # Process the request
                response = await self._process_request(request)

                # Update metrics
                self.metrics['total_requests'] += 1
                if response.status == "success":
                    self.metrics['successful_requests'] += 1
                else:
                    self.metrics['failed_requests'] += 1

                # Update average latency
                total_successful = self.metrics['successful_requests']
                if total_successful > 0:
                    current_avg = self.metrics['avg_latency_ms']
                    self.metrics['avg_latency_ms'] = (
                        (current_avg * (total_successful - 1) + response.latency_ms) / total_successful
                    )

                self.logger.debug(f"Worker {worker_id} processed request {request.request_id}")

            except Exception as e:
                self.logger.error(f"Worker {worker_id} error: {e}")
                await asyncio.sleep(0.1)

    async def _batch_worker_loop(self):
        """Worker for processing batch requests"""
        self.logger.info("Batch worker started")

        while self.running:
            try:
                batch_requests = []
                batch_timeout = self.config.get('batch_timeout_ms', 100) / 1000  # Convert to seconds
                max_batch_size = self.config.get('max_batch_size', 32)

                # Collect requests for batching
                end_time = time.time() + batch_timeout
                while len(batch_requests) < max_batch_size and time.time() < end_time:
                    try:
                        remaining_time = max(0, end_time - time.time())
                        request = await asyncio.wait_for(self.batch_queue.get(), timeout=remaining_time)
                        batch_requests.append(request)
                    except asyncio.TimeoutError:
                        break

                if batch_requests:
                    await self._process_batch(batch_requests)

            except Exception as e:
                self.logger.error(f"Batch worker error: {e}")
                await asyncio.sleep(0.1)

    async def _process_request(self, request: InferenceRequest) -> InferenceResponse:
        """Process a single inference request"""
        start_time = time.time()

        try:
            # Check if model is loaded
            if request.model_id not in self.models:
                # Try to load the model automatically
                if not await self.load_model(request.model_id):
                    return InferenceResponse(
                        request_id=request.request_id,
                        model_id=request.model_id,
                        outputs={},
                        latency_ms=(time.time() - start_time) * 1000,
                        status="error",
                        error=f"Model {request.model_id} not available"
                    )

            # Get model wrapper
            wrapper = self.models[request.model_id]

            # Perform inference
            outputs = await wrapper.predict(request.inputs)

            latency_ms = (time.time() - start_time) * 1000

            return InferenceResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                outputs=outputs,
                latency_ms=latency_ms,
                status="success" if "error" not in outputs else "error",
                error=outputs.get("error")
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            self.logger.error(f"Error processing request {request.request_id}: {e}")

            return InferenceResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                outputs={},
                latency_ms=latency_ms,
                status="error",
                error=str(e)
            )

    async def _process_batch(self, requests: List[InferenceRequest]):
        """Process a batch of requests"""
        self.logger.debug(f"Processing batch of {len(requests)} requests")

        # Group requests by model
        model_batches = {}
        for request in requests:
            if request.model_id not in model_batches:
                model_batches[request.model_id] = []
            model_batches[request.model_id].append(request)

        # Process each model's batch
        for model_id, model_requests in model_batches.items():
            try:
                if model_id not in self.models:
                    await self.load_model(model_id)

                if model_id in self.models:
                    # For now, process each request individually
                    # TODO: Implement true batch inference for supported models
                    for request in model_requests:
                        await self._process_request(request)

            except Exception as e:
                self.logger.error(f"Error processing batch for model {model_id}: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get runtime metrics"""
        self.metrics['queue_size'] = self.request_queue.qsize()
        self.metrics['batch_queue_size'] = self.batch_queue.qsize()
        self.metrics['last_updated'] = datetime.now()

        return self.metrics.copy()

    def get_model_stats(self, model_id: str = None) -> Dict[str, Any]:
        """Get statistics for specific model or all models"""
        if model_id:
            if model_id in self.models:
                return self.models[model_id].get_stats()
            else:
                return {"error": f"Model {model_id} not loaded"}
        else:
            return {model_id: wrapper.get_stats() for model_id, wrapper in self.models.items()}

    def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
        healthy_models = sum(1 for wrapper in self.models.values() if wrapper.status == ModelStatus.READY)

        return {
            "status": "healthy" if self.running else "stopped",
            "models_registered": len(self.model_registry),
            "models_loaded": len(self.models),
            "healthy_models": healthy_models,
            "queue_size": self.request_queue.qsize(),
            "batch_queue_size": self.batch_queue.qsize(),
            "worker_count": len([task for task in self.worker_tasks if not task.done()]),
            "last_check": datetime.now().isoformat()
        }

# Example usage and testing
async def main():
    """Example usage of the AI Runtime"""
    logging.basicConfig(level=logging.INFO)

    # Create runtime
    runtime = AIRuntime({
        'num_workers': 2,
        'max_queue_size': 100,
        'max_batch_size': 16
    })

    # Register a dummy model
    metadata = ModelMetadata(
        model_id="test_model",
        name="Test Model",
        version="1.0",
        format=ModelFormat.CUSTOM,
        input_shape={"input": [1, 10]},
        output_shape={"output": [1, 1]},
        model_path="/tmp/test_model"
    )

    await runtime.register_model(metadata)

    # Start runtime
    await runtime.start()

    # Submit test request
    request = InferenceRequest(
        model_id="test_model",
        inputs={"input": [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]},
        mode=InferenceMode.SYNC
    )

    response = await runtime.predict(request)
    print(f"Response: {response}")

    # Check metrics
    metrics = runtime.get_metrics()
    print(f"Metrics: {json.dumps(metrics, indent=2, default=str)}")

    # Health check
    health = runtime.health_check()
    print(f"Health: {json.dumps(health, indent=2)}")

    # Stop runtime
    await runtime.stop()

if __name__ == "__main__":
    asyncio.run(main())