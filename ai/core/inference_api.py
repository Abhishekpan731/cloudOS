#!/usr/bin/env python3
"""
CloudOS AI Inference API - REST and gRPC APIs for AI model inference
Provides high-level APIs for accessing AI models in CloudOS
"""

import asyncio
import json
import logging
import time
import traceback
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

# FastAPI for REST API
try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, StreamingResponse
    from pydantic import BaseModel, Field, validator
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

# gRPC for high-performance API
try:
    import grpc
    from concurrent import futures
    HAS_GRPC = True
except ImportError:
    HAS_GRPC = False

from .runtime import AIRuntime, InferenceRequest, InferenceResponse, InferenceMode, ModelMetadata, ModelFormat

# Pydantic models for API validation
class PredictionInput(BaseModel):
    """Input data for model prediction"""
    inputs: Dict[str, Any] = Field(..., description="Input data for the model")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Optional inference parameters")
    mode: str = Field(default="sync", description="Inference mode: sync, async, batch, streaming")
    priority: int = Field(default=1, ge=1, le=10, description="Request priority (1-10)")
    timeout_seconds: float = Field(default=30.0, gt=0, description="Request timeout in seconds")

    @validator('mode')
    def validate_mode(cls, v):
        if v not in ["sync", "async", "batch", "streaming"]:
            raise ValueError("Mode must be one of: sync, async, batch, streaming")
        return v

class PredictionOutput(BaseModel):
    """Output from model prediction"""
    request_id: str = Field(..., description="Unique request identifier")
    model_id: str = Field(..., description="Model identifier")
    outputs: Dict[str, Any] = Field(..., description="Model outputs")
    latency_ms: float = Field(..., description="Inference latency in milliseconds")
    status: str = Field(..., description="Request status")
    error: Optional[str] = Field(None, description="Error message if failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    completed_at: str = Field(..., description="Completion timestamp")

class ModelInfo(BaseModel):
    """Model information"""
    model_id: str
    name: str
    version: str
    format: str
    input_shape: Dict[str, List[int]]
    output_shape: Dict[str, List[int]]
    status: str
    tags: Dict[str, str] = Field(default_factory=dict)

class RuntimeStats(BaseModel):
    """Runtime statistics"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_latency_ms: float
    models_loaded: int
    queue_size: int
    last_updated: str

class HealthStatus(BaseModel):
    """Health check response"""
    status: str
    models_registered: int
    models_loaded: int
    healthy_models: int
    queue_size: int
    batch_queue_size: int
    worker_count: int
    last_check: str

class InferenceAPI:
    """High-level API for AI inference operations"""

    def __init__(self, runtime: AIRuntime, config: Dict[str, Any] = None):
        self.runtime = runtime
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Request tracking
        self.active_requests: Dict[str, InferenceRequest] = {}
        self.completed_requests: Dict[str, InferenceResponse] = {}
        self.max_completed_cache = self.config.get('max_completed_cache', 1000)

        # API servers
        self.rest_app = None
        self.grpc_server = None

        if HAS_FASTAPI:
            self._setup_rest_api()

        if HAS_GRPC:
            self._setup_grpc_api()

    def _setup_rest_api(self):
        """Setup FastAPI REST server"""
        self.rest_app = FastAPI(
            title="CloudOS AI Inference API",
            description="REST API for AI model inference in CloudOS",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )

        # Add CORS middleware
        self.rest_app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Add routes
        self._add_rest_routes()

        self.logger.info("REST API initialized")

    def _add_rest_routes(self):
        """Add REST API routes"""

        @self.rest_app.get("/health", response_model=HealthStatus)
        async def health_check():
            """Health check endpoint"""
            try:
                health = self.runtime.health_check()
                return HealthStatus(**health)
            except Exception as e:
                self.logger.error(f"Health check error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.rest_app.get("/metrics", response_model=RuntimeStats)
        async def get_metrics():
            """Get runtime metrics"""
            try:
                metrics = self.runtime.get_metrics()
                return RuntimeStats(
                    total_requests=metrics['total_requests'],
                    successful_requests=metrics['successful_requests'],
                    failed_requests=metrics['failed_requests'],
                    avg_latency_ms=metrics['avg_latency_ms'],
                    models_loaded=metrics['models_loaded'],
                    queue_size=metrics['queue_size'],
                    last_updated=metrics['last_updated'].isoformat()
                )
            except Exception as e:
                self.logger.error(f"Metrics error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.rest_app.get("/models", response_model=List[ModelInfo])
        async def list_models():
            """List all registered models"""
            try:
                models = []
                for model_id, metadata in self.runtime.model_registry.items():
                    status = "unloaded"
                    if model_id in self.runtime.models:
                        status = self.runtime.models[model_id].status.value

                    models.append(ModelInfo(
                        model_id=metadata.model_id,
                        name=metadata.name,
                        version=metadata.version,
                        format=metadata.format.value,
                        input_shape=metadata.input_shape,
                        output_shape=metadata.output_shape,
                        status=status,
                        tags=metadata.tags
                    ))
                return models
            except Exception as e:
                self.logger.error(f"List models error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.rest_app.get("/models/{model_id}", response_model=ModelInfo)
        async def get_model_info(model_id: str):
            """Get information about a specific model"""
            try:
                if model_id not in self.runtime.model_registry:
                    raise HTTPException(status_code=404, detail=f"Model {model_id} not found")

                metadata = self.runtime.model_registry[model_id]
                status = "unloaded"
                if model_id in self.runtime.models:
                    status = self.runtime.models[model_id].status.value

                return ModelInfo(
                    model_id=metadata.model_id,
                    name=metadata.name,
                    version=metadata.version,
                    format=metadata.format.value,
                    input_shape=metadata.input_shape,
                    output_shape=metadata.output_shape,
                    status=status,
                    tags=metadata.tags
                )
            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Get model info error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.rest_app.post("/models/{model_id}/load")
        async def load_model(model_id: str, background_tasks: BackgroundTasks):
            """Load a model into memory"""
            try:
                if model_id not in self.runtime.model_registry:
                    raise HTTPException(status_code=404, detail=f"Model {model_id} not found")

                if model_id in self.runtime.models:
                    return {"message": f"Model {model_id} already loaded"}

                # Load model in background
                background_tasks.add_task(self.runtime.load_model, model_id)
                return {"message": f"Loading model {model_id}"}

            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Load model error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.rest_app.post("/models/{model_id}/unload")
        async def unload_model(model_id: str):
            """Unload a model from memory"""
            try:
                if model_id not in self.runtime.models:
                    return {"message": f"Model {model_id} not loaded"}

                success = await self.runtime.unload_model(model_id)
                if success:
                    return {"message": f"Model {model_id} unloaded"}
                else:
                    raise HTTPException(status_code=500, detail=f"Failed to unload model {model_id}")

            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Unload model error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.rest_app.post("/models/{model_id}/predict", response_model=PredictionOutput)
        async def predict(model_id: str, input_data: PredictionInput):
            """Make a prediction with the specified model"""
            try:
                if model_id not in self.runtime.model_registry:
                    raise HTTPException(status_code=404, detail=f"Model {model_id} not found")

                # Create inference request
                request = InferenceRequest(
                    model_id=model_id,
                    inputs=input_data.inputs,
                    parameters=input_data.parameters,
                    mode=getattr(InferenceMode, input_data.mode.upper()),
                    priority=input_data.priority,
                    timeout_seconds=input_data.timeout_seconds
                )

                # Track request
                self.active_requests[request.request_id] = request

                # Submit for processing
                response = await self.runtime.predict(request)

                # For async mode, return immediately
                if input_data.mode == "async":
                    return PredictionOutput(
                        request_id=response.request_id,
                        model_id=response.model_id,
                        outputs=response.outputs,
                        latency_ms=response.latency_ms,
                        status=response.status,
                        error=response.error,
                        metadata=response.metadata,
                        completed_at=response.completed_at.isoformat()
                    )

                # For sync mode, wait for completion
                # This is a simplified implementation
                return PredictionOutput(
                    request_id=response.request_id,
                    model_id=response.model_id,
                    outputs=response.outputs,
                    latency_ms=response.latency_ms,
                    status=response.status,
                    error=response.error,
                    metadata=response.metadata,
                    completed_at=response.completed_at.isoformat()
                )

            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Prediction error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.rest_app.get("/requests/{request_id}", response_model=PredictionOutput)
        async def get_request_status(request_id: str):
            """Get the status of a prediction request"""
            try:
                if request_id in self.completed_requests:
                    response = self.completed_requests[request_id]
                    return PredictionOutput(
                        request_id=response.request_id,
                        model_id=response.model_id,
                        outputs=response.outputs,
                        latency_ms=response.latency_ms,
                        status=response.status,
                        error=response.error,
                        metadata=response.metadata,
                        completed_at=response.completed_at.isoformat()
                    )
                elif request_id in self.active_requests:
                    return PredictionOutput(
                        request_id=request_id,
                        model_id=self.active_requests[request_id].model_id,
                        outputs={},
                        latency_ms=0.0,
                        status="processing",
                        error=None,
                        metadata={},
                        completed_at=""
                    )
                else:
                    raise HTTPException(status_code=404, detail=f"Request {request_id} not found")

            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Get request status error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.rest_app.post("/models/{model_id}/predict/batch")
        async def batch_predict(model_id: str, input_data: List[PredictionInput]):
            """Make batch predictions with the specified model"""
            try:
                if model_id not in self.runtime.model_registry:
                    raise HTTPException(status_code=404, detail=f"Model {model_id} not found")

                responses = []
                for item in input_data:
                    # Create inference request
                    request = InferenceRequest(
                        model_id=model_id,
                        inputs=item.inputs,
                        parameters=item.parameters,
                        mode=InferenceMode.BATCH,
                        priority=item.priority,
                        timeout_seconds=item.timeout_seconds
                    )

                    # Submit for processing
                    response = await self.runtime.predict(request)
                    responses.append(PredictionOutput(
                        request_id=response.request_id,
                        model_id=response.model_id,
                        outputs=response.outputs,
                        latency_ms=response.latency_ms,
                        status=response.status,
                        error=response.error,
                        metadata=response.metadata,
                        completed_at=response.completed_at.isoformat()
                    ))

                return responses

            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Batch prediction error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

    def _setup_grpc_api(self):
        """Setup gRPC API server"""
        # This would implement gRPC service definitions
        # For now, this is a placeholder
        self.logger.info("gRPC API setup placeholder")

    async def start_rest_server(self, host: str = "0.0.0.0", port: int = 8000):
        """Start the REST API server"""
        if not HAS_FASTAPI:
            raise RuntimeError("FastAPI not available")

        config = uvicorn.Config(
            app=self.rest_app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config)

        self.logger.info(f"Starting REST API server on {host}:{port}")
        await server.serve()

    async def start_grpc_server(self, host: str = "0.0.0.0", port: int = 50051):
        """Start the gRPC API server"""
        if not HAS_GRPC:
            raise RuntimeError("gRPC not available")

        # Placeholder for gRPC server implementation
        self.logger.info(f"gRPC server would start on {host}:{port}")

    def register_model_from_config(self, config: Dict[str, Any]) -> bool:
        """Register a model from configuration"""
        try:
            metadata = ModelMetadata(
                model_id=config['model_id'],
                name=config['name'],
                version=config['version'],
                format=ModelFormat(config['format']),
                input_shape=config['input_shape'],
                output_shape=config['output_shape'],
                model_path=config['model_path'],
                config_path=config.get('config_path'),
                warmup_samples=config.get('warmup_samples', 10),
                max_batch_size=config.get('max_batch_size', 32),
                tags=config.get('tags', {})
            )

            return asyncio.create_task(self.runtime.register_model(metadata))

        except Exception as e:
            self.logger.error(f"Failed to register model from config: {e}")
            return False

    def create_streaming_response(self, model_id: str, inputs: Dict[str, Any]):
        """Create a streaming response for real-time inference"""
        async def generate_predictions():
            try:
                # This is a placeholder for streaming implementation
                for i in range(5):  # Simulate 5 streaming responses
                    request = InferenceRequest(
                        model_id=model_id,
                        inputs=inputs,
                        mode=InferenceMode.STREAMING
                    )

                    response = await self.runtime.predict(request)

                    yield f"data: {json.dumps({
                        'sequence': i,
                        'request_id': response.request_id,
                        'outputs': response.outputs,
                        'timestamp': datetime.now().isoformat()
                    })}\n\n"

                    await asyncio.sleep(0.1)  # Simulate processing time

            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return StreamingResponse(
            generate_predictions(),
            media_type="text/plain",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
        )

# Example usage and integration
class AIService:
    """High-level AI service that combines runtime and API"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.runtime = AIRuntime(self.config.get('runtime', {}))
        self.api = InferenceAPI(self.runtime, self.config.get('api', {}))
        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the AI service"""
        # Start the runtime
        await self.runtime.start()

        # Load any pre-configured models
        models_config = self.config.get('models', [])
        for model_config in models_config:
            success = self.api.register_model_from_config(model_config)
            if success:
                await self.runtime.load_model(model_config['model_id'])

        self.logger.info("AI Service started")

    async def stop(self):
        """Stop the AI service"""
        await self.runtime.stop()
        self.logger.info("AI Service stopped")

    async def serve_rest(self, host: str = "0.0.0.0", port: int = 8000):
        """Start serving REST API"""
        await self.api.start_rest_server(host, port)

    async def serve_grpc(self, host: str = "0.0.0.0", port: int = 50051):
        """Start serving gRPC API"""
        await self.api.start_grpc_server(host, port)

# Example configuration
EXAMPLE_CONFIG = {
    "runtime": {
        "num_workers": 4,
        "max_queue_size": 1000,
        "max_batch_size": 32,
        "batch_timeout_ms": 100
    },
    "api": {
        "max_completed_cache": 1000
    },
    "models": [
        {
            "model_id": "resource_optimizer",
            "name": "Resource Optimization Model",
            "version": "1.0",
            "format": "custom",
            "input_shape": {"metrics": [1, 10]},
            "output_shape": {"recommendations": [1, 5]},
            "model_path": "/models/resource_optimizer",
            "tags": {"type": "optimization", "domain": "infrastructure"}
        }
    ]
}

# Main entry point
async def main():
    """Example usage of the AI Service"""
    logging.basicConfig(level=logging.INFO)

    service = AIService(EXAMPLE_CONFIG)
    await service.start()

    # Start REST API server
    await service.serve_rest()

if __name__ == "__main__":
    asyncio.run(main())