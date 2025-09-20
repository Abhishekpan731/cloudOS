"""
CloudOS AI Core - Central AI infrastructure for CloudOS
Provides runtime, APIs, and model management for AI operations
"""

from .runtime import (
    AIRuntime,
    ModelWrapper,
    ModelMetadata,
    ModelFormat,
    ModelStatus,
    InferenceRequest,
    InferenceResponse,
    InferenceMode
)

from .inference_api import (
    InferenceAPI,
    AIService,
    PredictionInput,
    PredictionOutput,
    ModelInfo,
    RuntimeStats,
    HealthStatus
)

__version__ = "1.0.0"
__all__ = [
    # Runtime components
    "AIRuntime",
    "ModelWrapper",
    "ModelMetadata",
    "ModelFormat",
    "ModelStatus",
    "InferenceRequest",
    "InferenceResponse",
    "InferenceMode",

    # API components
    "InferenceAPI",
    "AIService",
    "PredictionInput",
    "PredictionOutput",
    "ModelInfo",
    "RuntimeStats",
    "HealthStatus"
]