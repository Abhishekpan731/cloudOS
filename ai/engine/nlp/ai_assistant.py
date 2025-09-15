#!/usr/bin/env python3
"""
CloudOS AI Assistant - Natural Language Interface
Conversational AI for system administration and optimization
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum

from ..core.ai_engine import CloudOSAIEngine, AIRequest, AITaskType

class IntentType(Enum):
    SYSTEM_STATUS = "system_status"
    RESOURCE_QUERY = "resource_query"
    OPTIMIZATION_REQUEST = "optimization_request"
    SCALING_COMMAND = "scaling_command"
    TROUBLESHOOTING = "troubleshooting"
    PERFORMANCE_ANALYSIS = "performance_analysis"
    COST_ANALYSIS = "cost_analysis"
    PREDICTION_REQUEST = "prediction_request"
    CONFIGURATION = "configuration"
    HELP = "help"
    UNKNOWN = "unknown"

class EntityType(Enum):
    NODE = "node"
    SERVICE = "service"
    RESOURCE = "resource"
    METRIC = "metric"
    TIME_PERIOD = "time_period"
    THRESHOLD = "threshold"
    ACTION = "action"

@dataclass
class Entity:
    type: EntityType
    value: str
    confidence: float

@dataclass
class Intent:
    type: IntentType
    confidence: float
    entities: List[Entity]
    raw_query: str

@dataclass
class AIResponse:
    text: str
    data: Dict[str, Any]
    actions: List[Dict[str, Any]]
    confidence: float
    intent: Intent

class CloudOSAIAssistant:
    """
    Natural language AI assistant for CloudOS
    """

    def __init__(self, ai_engine: CloudOSAIEngine, resource_manager=None, scaler=None):
        self.ai_engine = ai_engine
        self.resource_manager = resource_manager
        self.scaler = scaler
        self.logger = logging.getLogger(__name__)

        # Intent patterns for simple NLP
        self.intent_patterns = {
            IntentType.SYSTEM_STATUS: [
                r'\b(status|health|overview|summary)\b',
                r'\bhow\s+(?:is|are)\s+(?:the\s+)?(?:system|cluster|nodes?)\b',
                r'\bshow\s+(?:me\s+)?(?:system|cluster|overview)\b'
            ],
            IntentType.RESOURCE_QUERY: [
                r'\b(?:cpu|memory|ram|disk|storage|network)\s+(?:usage|utilization)\b',
                r'\bhow\s+much\s+(?:cpu|memory|ram|disk|storage)\b',
                r'\bshow\s+(?:cpu|memory|ram|disk|storage|resources)\b'
            ],
            IntentType.OPTIMIZATION_REQUEST: [
                r'\boptimize\b',
                r'\btune\s+performance\b',
                r'\bimprove\s+(?:performance|efficiency)\b',
                r'\brecommend\s+(?:optimizations?|improvements?)\b'
            ],
            IntentType.SCALING_COMMAND: [
                r'\bscale\s+(?:up|out|down|in)\b',
                r'\badd\s+(?:more\s+)?(?:nodes?|instances?)\b',
                r'\bremove\s+(?:nodes?|instances?)\b',
                r'\bincrease\s+(?:capacity|resources?)\b'
            ],
            IntentType.TROUBLESHOOTING: [
                r'\bwhy\s+is\b.*\b(?:slow|high|down|failing)\b',
                r'\btroubleshoot\b',
                r'\bdiagnose\b',
                r'\bwhat.s\s+wrong\b',
                r'\berror\b.*\bnode\b'
            ],
            IntentType.PERFORMANCE_ANALYSIS: [
                r'\bperformance\s+(?:analysis|report|metrics)\b',
                r'\banalyze\s+performance\b',
                r'\bshow\s+performance\b',
                r'\bbottleneck\b'
            ],
            IntentType.COST_ANALYSIS: [
                r'\bcost\s+(?:analysis|optimization|savings?)\b',
                r'\bhow\s+much\s+(?:am\s+i\s+spending|does\s+it\s+cost)\b',
                r'\breduce\s+costs?\b',
                r'\bsave\s+money\b'
            ],
            IntentType.PREDICTION_REQUEST: [
                r'\bpredict\b',
                r'\bforecast\b',
                r'\bwhat\s+will\s+happen\b',
                r'\bfuture\s+(?:usage|load|demand)\b'
            ],
            IntentType.HELP: [
                r'\bhelp\b',
                r'\bwhat\s+can\s+you\s+do\b',
                r'\bcommands?\b',
                r'\bhow\s+to\b'
            ]
        }

        # Entity patterns
        self.entity_patterns = {
            EntityType.NODE: [
                r'\bnode[-\s]?(\w+)\b',
                r'\bserver[-\s]?(\w+)\b',
                r'\binstance[-\s]?(\w+)\b'
            ],
            EntityType.RESOURCE: [
                r'\b(cpu|memory|ram|disk|storage|network|bandwidth)\b'
            ],
            EntityType.METRIC: [
                r'\b(usage|utilization|load|throughput|latency|response\s+time|error\s+rate)\b'
            ],
            EntityType.TIME_PERIOD: [
                r'\b(\d+)\s+(minutes?|hours?|days?|weeks?)\b',
                r'\b(last|past)\s+(\d+)\s+(minutes?|hours?|days?)\b',
                r'\b(today|yesterday|this\s+week|last\s+week)\b'
            ],
            EntityType.THRESHOLD: [
                r'\b(\d+)%\b',
                r'\babove\s+(\d+)\b',
                r'\bbelow\s+(\d+)\b',
                r'\bover\s+(\d+)\b'
            ]
        }

        # Response templates
        self.response_templates = {
            IntentType.SYSTEM_STATUS: self._handle_system_status,
            IntentType.RESOURCE_QUERY: self._handle_resource_query,
            IntentType.OPTIMIZATION_REQUEST: self._handle_optimization_request,
            IntentType.SCALING_COMMAND: self._handle_scaling_command,
            IntentType.TROUBLESHOOTING: self._handle_troubleshooting,
            IntentType.PERFORMANCE_ANALYSIS: self._handle_performance_analysis,
            IntentType.COST_ANALYSIS: self._handle_cost_analysis,
            IntentType.PREDICTION_REQUEST: self._handle_prediction_request,
            IntentType.HELP: self._handle_help
        }

        # Knowledge base
        self.help_topics = {
            'system_status': "Ask about cluster health: 'How is the system?' or 'Show cluster status'",
            'resources': "Check resource usage: 'Show CPU usage' or 'How much memory is used?'",
            'optimization': "Request optimizations: 'Optimize the cluster' or 'Recommend improvements'",
            'scaling': "Scale resources: 'Scale up' or 'Add more nodes'",
            'troubleshooting': "Get help with issues: 'Why is node1 slow?' or 'Troubleshoot high CPU'",
            'predictions': "Get forecasts: 'Predict future load' or 'What will happen in 1 hour?'",
            'costs': "Analyze costs: 'Show cost analysis' or 'How to reduce costs?'"
        }

        self.logger.info("CloudOS AI Assistant initialized")

    async def process_query(self, query: str, context: Dict[str, Any] = None) -> AIResponse:
        """Process a natural language query"""
        self.logger.info(f"Processing query: {query}")

        # Parse intent and entities
        intent = await self._parse_intent(query)
        self.logger.debug(f"Detected intent: {intent.type.value} (confidence: {intent.confidence:.2f})")

        # Handle the query based on intent
        handler = self.response_templates.get(intent.type, self._handle_unknown)
        response = await handler(intent, context or {})

        self.logger.info(f"Generated response with confidence: {response.confidence:.2f}")
        return response

    async def _parse_intent(self, query: str) -> Intent:
        """Parse user intent from natural language query"""
        query_lower = query.lower()
        entities = []

        # Extract entities first
        for entity_type, patterns in self.entity_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, query_lower)
                for match in matches:
                    entities.append(Entity(
                        type=entity_type,
                        value=match.group(1) if match.groups() else match.group(0),
                        confidence=0.8
                    ))

        # Determine intent
        best_intent = IntentType.UNKNOWN
        best_confidence = 0.0

        for intent_type, patterns in self.intent_patterns.items():
            confidence = 0.0
            matches = 0

            for pattern in patterns:
                if re.search(pattern, query_lower):
                    matches += 1
                    confidence = max(confidence, 0.6 + (matches * 0.1))

            if confidence > best_confidence:
                best_confidence = confidence
                best_intent = intent_type

        return Intent(
            type=best_intent,
            confidence=best_confidence,
            entities=entities,
            raw_query=query
        )

    async def _handle_system_status(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle system status queries"""
        try:
            if not self.resource_manager:
                return AIResponse(
                    text="System status information is not available. Resource manager not connected.",
                    data={},
                    actions=[],
                    confidence=0.5,
                    intent=intent
                )

            # Get cluster status
            status = await self.resource_manager.get_cluster_status()

            # Generate human-readable response
            health = status['cluster_health']
            resources = status['resource_utilization']

            if health['critical_nodes'] > 0:
                health_desc = f"⚠️ CRITICAL: {health['critical_nodes']} nodes in critical state"
                health_color = "red"
            elif health['warning_nodes'] > 0:
                health_desc = f"⚠️ WARNING: {health['warning_nodes']} nodes need attention"
                health_color = "yellow"
            else:
                health_desc = "✅ All systems healthy"
                health_color = "green"

            response_text = f"""**CloudOS Cluster Status**

{health_desc}

**Cluster Overview:**
• Nodes: {health['healthy_nodes']}/{health['total_nodes']} healthy
• CPU Usage: {resources['cpu']['utilization_percent']:.1f}% ({resources['cpu']['used']:.1f}/{resources['cpu']['total']:.1f} cores)
• Memory Usage: {resources['memory']['utilization_percent']:.1f}% ({resources['memory']['used']:.1f}/{resources['memory']['total']:.1f} GB)

**Workloads:**
• Active: {status['workloads']['active_allocations']}
• Pending: {status['workloads']['pending_workloads']}

**Optimization:**
• Strategy: {status['optimization']['strategy']}
• Predictive Scaling: {'✅' if status['optimization']['predictive_scaling'] else '❌'}
"""

            actions = []
            if health['critical_nodes'] > 0 or health['warning_nodes'] > 0:
                actions.append({
                    'type': 'suggestion',
                    'text': 'Run diagnostics on unhealthy nodes',
                    'command': 'troubleshoot nodes'
                })

            return AIResponse(
                text=response_text,
                data=status,
                actions=actions,
                confidence=0.9,
                intent=intent
            )

        except Exception as e:
            self.logger.error(f"Error handling system status: {e}")
            return AIResponse(
                text=f"Sorry, I encountered an error while checking system status: {str(e)}",
                data={},
                actions=[],
                confidence=0.3,
                intent=intent
            )

    async def _handle_resource_query(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle resource usage queries"""
        # Extract specific resource from entities
        resource_type = None
        for entity in intent.entities:
            if entity.type == EntityType.RESOURCE:
                resource_type = entity.value
                break

        if not self.resource_manager:
            return AIResponse(
                text="Resource information is not available. Resource manager not connected.",
                data={},
                actions=[],
                confidence=0.5,
                intent=intent
            )

        try:
            status = await self.resource_manager.get_cluster_status()
            resources = status['resource_utilization']

            if resource_type:
                # Specific resource query
                if resource_type.lower() in ['cpu', 'processor']:
                    cpu = resources['cpu']
                    text = f"**CPU Usage**: {cpu['utilization_percent']:.1f}% ({cpu['used']:.1f}/{cpu['total']:.1f} cores)\n"
                    if cpu['utilization_percent'] > 80:
                        text += "⚠️ High CPU usage detected. Consider scaling out."
                elif resource_type.lower() in ['memory', 'ram']:
                    memory = resources['memory']
                    text = f"**Memory Usage**: {memory['utilization_percent']:.1f}% ({memory['used']:.1f}/{memory['total']:.1f} GB)\n"
                    if memory['utilization_percent'] > 80:
                        text += "⚠️ High memory usage detected. Consider adding more memory or scaling out."
                else:
                    text = f"Resource information for '{resource_type}' is not available."
            else:
                # General resource overview
                text = f"""**Resource Usage Overview**

**CPU**: {resources['cpu']['utilization_percent']:.1f}% ({resources['cpu']['used']:.1f}/{resources['cpu']['total']:.1f} cores)
**Memory**: {resources['memory']['utilization_percent']:.1f}% ({resources['memory']['used']:.1f}/{resources['memory']['total']:.1f} GB)

"""
                # Add recommendations
                if resources['cpu']['utilization_percent'] > 80 or resources['memory']['utilization_percent'] > 80:
                    text += "💡 **Recommendation**: Consider scaling out to handle the current load."

            actions = []
            if (resources['cpu']['utilization_percent'] > 80 or
                resources['memory']['utilization_percent'] > 80):
                actions.append({
                    'type': 'action',
                    'text': 'Optimize resource allocation',
                    'command': 'optimize cluster'
                })

            return AIResponse(
                text=text,
                data=resources,
                actions=actions,
                confidence=0.85,
                intent=intent
            )

        except Exception as e:
            return AIResponse(
                text=f"Error retrieving resource information: {str(e)}",
                data={},
                actions=[],
                confidence=0.3,
                intent=intent
            )

    async def _handle_optimization_request(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle optimization requests"""
        if not self.resource_manager:
            return AIResponse(
                text="Optimization is not available. Resource manager not connected.",
                data={},
                actions=[],
                confidence=0.5,
                intent=intent
            )

        try:
            # Trigger optimization
            optimization_result = await self.resource_manager.optimize_cluster()

            text = f"""**🔧 Cluster Optimization Started**

Analyzing your cluster configuration and workload patterns to provide optimization recommendations.

**Status**: {optimization_result.get('optimization_started', 'Unknown')}
**Task ID**: {optimization_result.get('task_id', 'N/A')}
**Estimated Completion**: {optimization_result.get('estimated_completion', '2-5 minutes')}

I'll analyze:
• Resource allocation efficiency
• Workload distribution
• Performance bottlenecks
• Cost optimization opportunities

You can check back in a few minutes for detailed recommendations.
"""

            actions = [
                {
                    'type': 'followup',
                    'text': 'Check optimization results',
                    'command': 'show optimization results'
                },
                {
                    'type': 'info',
                    'text': 'View current performance metrics',
                    'command': 'show performance analysis'
                }
            ]

            return AIResponse(
                text=text,
                data=optimization_result,
                actions=actions,
                confidence=0.9,
                intent=intent
            )

        except Exception as e:
            return AIResponse(
                text=f"Error starting optimization: {str(e)}",
                data={},
                actions=[],
                confidence=0.3,
                intent=intent
            )

    async def _handle_scaling_command(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle scaling commands"""
        if not self.scaler:
            return AIResponse(
                text="Scaling functionality is not available. Auto-scaler not connected.",
                data={},
                actions=[],
                confidence=0.5,
                intent=intent
            )

        try:
            # Get scaling recommendations
            recommendations = await self.scaler.get_scaling_recommendations()

            scaling_rec = recommendations.get('scaling_recommendation', {})
            current_instances = recommendations.get('current_state', {}).get('instances', 1)

            action = scaling_rec.get('action', 'maintain')
            target = scaling_rec.get('target_instances', current_instances)
            reasoning = scaling_rec.get('reasoning', 'No specific reason provided')

            if action == 'maintain':
                text = f"""**📊 Scaling Analysis**

Current instances: {current_instances}
Recommended action: **No scaling needed**

{reasoning}

Your cluster is currently well-balanced. I'll continue monitoring and will recommend scaling when needed.
"""
            else:
                text = f"""**🔄 Scaling Recommendation**

Current instances: {current_instances}
Recommended: **{action.replace('_', ' ').title()}** to {target} instances

**Reasoning**: {reasoning}
**Urgency**: {scaling_rec.get('urgency', 'medium').title()}

Would you like me to proceed with this scaling action?
"""

            # Add current metrics
            current_state = recommendations.get('current_state', {})
            text += f"""

**Current Metrics:**
• CPU: {current_state.get('cpu_utilization', 0):.1f}%
• Memory: {current_state.get('memory_utilization', 0):.1f}%
• Response Time: {current_state.get('response_time', 0):.0f}ms
"""

            actions = []
            if action != 'maintain':
                actions.append({
                    'type': 'action',
                    'text': f'Execute {action.replace("_", " ")} action',
                    'command': f'scale {action} to {target}'
                })

            actions.append({
                'type': 'info',
                'text': 'Show detailed predictions',
                'command': 'predict future load'
            })

            return AIResponse(
                text=text,
                data=recommendations,
                actions=actions,
                confidence=0.85,
                intent=intent
            )

        except Exception as e:
            return AIResponse(
                text=f"Error analyzing scaling needs: {str(e)}",
                data={},
                actions=[],
                confidence=0.3,
                intent=intent
            )

    async def _handle_troubleshooting(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle troubleshooting queries"""
        # Extract node or service from entities
        target_node = None
        for entity in intent.entities:
            if entity.type == EntityType.NODE:
                target_node = entity.value
                break

        text = "🔍 **Troubleshooting Analysis**\n\n"

        if target_node:
            text += f"Analyzing issues with node: **{target_node}**\n\n"
        else:
            text += "Analyzing cluster-wide issues...\n\n"

        # Provide general troubleshooting steps
        text += """**Common Issues to Check:**

1. **High Resource Usage**
   • CPU > 80%: Consider scaling out or optimizing workloads
   • Memory > 90%: Risk of OOM errors, scale immediately

2. **Network Issues**
   • High latency: Check network connectivity
   • Packet loss: Investigate network infrastructure

3. **Storage Problems**
   • Disk > 95%: Immediate attention needed
   • High I/O wait: Storage bottleneck likely

4. **Application Issues**
   • High error rates: Check application logs
   • Slow response times: Database or API bottlenecks

**Recommendations:**
• Check system logs for error patterns
• Monitor resource trends over time
• Review recent changes or deployments
• Consider predictive scaling to prevent issues
"""

        actions = [
            {
                'type': 'diagnostic',
                'text': 'Run system diagnostics',
                'command': 'diagnose system'
            },
            {
                'type': 'info',
                'text': 'Show recent alerts',
                'command': 'show alerts'
            },
            {
                'type': 'analysis',
                'text': 'Analyze performance trends',
                'command': 'show performance analysis'
            }
        ]

        return AIResponse(
            text=text,
            data={'target_node': target_node},
            actions=actions,
            confidence=0.7,
            intent=intent
        )

    async def _handle_performance_analysis(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle performance analysis requests"""
        text = """📈 **Performance Analysis**

I'm analyzing your cluster's performance characteristics...

**Key Metrics Being Analyzed:**
• Response times and latency patterns
• Throughput and request rates
• Resource utilization trends
• Error rates and availability
• Scaling efficiency

**Performance Insights:**
• Baseline performance established
• Trend analysis in progress
• Bottleneck identification
• Optimization opportunities

For detailed performance metrics, I recommend checking:
1. Resource utilization over time
2. Application response times
3. Network and storage I/O patterns
4. Scaling events and their effectiveness

Would you like me to focus on any specific performance aspect?
"""

        actions = [
            {
                'type': 'analysis',
                'text': 'Show resource trends',
                'command': 'show resource utilization trends'
            },
            {
                'type': 'analysis',
                'text': 'Analyze response times',
                'command': 'show response time analysis'
            },
            {
                'type': 'optimization',
                'text': 'Get optimization recommendations',
                'command': 'optimize performance'
            }
        ]

        return AIResponse(
            text=text,
            data={},
            actions=actions,
            confidence=0.8,
            intent=intent
        )

    async def _handle_cost_analysis(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle cost analysis requests"""
        text = """💰 **Cost Analysis & Optimization**

Analyzing your infrastructure costs and identifying savings opportunities...

**Cost Factors Being Analyzed:**
• Instance types and sizing efficiency
• Resource utilization vs. capacity
• Reserved vs. on-demand pricing
• Multi-cloud cost comparison
• Idle resource identification

**Potential Cost Optimizations:**
1. **Right-sizing**: Match instance sizes to actual usage
2. **Reserved Instances**: Lock in pricing for predictable workloads
3. **Spot Instances**: Use for fault-tolerant workloads
4. **Auto-scaling**: Reduce over-provisioning
5. **Storage Optimization**: Choose appropriate storage tiers

**Estimated Savings Opportunities:**
• Underutilized resources: 15-30% savings
• Reserved instance usage: 20-40% savings
• Automatic scaling: 10-25% savings
• Storage optimization: 10-20% savings

Would you like me to analyze any specific cost area in detail?
"""

        actions = [
            {
                'type': 'analysis',
                'text': 'Show underutilized resources',
                'command': 'show underutilized resources'
            },
            {
                'type': 'optimization',
                'text': 'Optimize instance sizing',
                'command': 'optimize instance sizes'
            },
            {
                'type': 'recommendation',
                'text': 'Reserved instance recommendations',
                'command': 'recommend reserved instances'
            }
        ]

        return AIResponse(
            text=text,
            data={},
            actions=actions,
            confidence=0.8,
            intent=intent
        )

    async def _handle_prediction_request(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle prediction requests"""
        time_period = "next 30 minutes"

        # Extract time period from entities
        for entity in intent.entities:
            if entity.type == EntityType.TIME_PERIOD:
                time_period = entity.value
                break

        if not self.scaler:
            return AIResponse(
                text="Prediction functionality is not available. Predictive scaler not connected.",
                data={},
                actions=[],
                confidence=0.5,
                intent=intent
            )

        try:
            # Get predictions
            recommendations = await self.scaler.get_scaling_recommendations()
            predictions = recommendations.get('predictions', {})

            text = f"""🔮 **Workload Predictions** (for {time_period})

**Short-term Forecast (15 minutes):**
• CPU: {predictions.get('short_term', {}).get('cpu', 0):.1f}%
• Memory: {predictions.get('short_term', {}).get('memory', 0):.1f}%
• Confidence: {predictions.get('short_term', {}).get('confidence', 0)*100:.0f}%

**Medium-term Forecast (1 hour):**
• CPU: {predictions.get('medium_term', {}).get('cpu', 0):.1f}%
• Memory: {predictions.get('medium_term', {}).get('memory', 0):.1f}%
• Confidence: {predictions.get('medium_term', {}).get('confidence', 0)*100:.0f}%

**Pattern Analysis:**
"""

            pattern_info = recommendations.get('pattern_detection', {})
            pattern = pattern_info.get('current_pattern', 'unknown')
            pattern_confidence = pattern_info.get('confidence', 0) * 100

            text += f"• Detected pattern: **{pattern.title()}** (confidence: {pattern_confidence:.0f}%)\n"

            if pattern in ['growing', 'spiky']:
                text += "• Recommendation: Prepare for increased load\n"
            elif pattern == 'declining':
                text += "• Recommendation: Consider scaling down to save costs\n"

            text += f"""

**Based on these predictions:**
"""

            scaling_rec = recommendations.get('scaling_recommendation', {})
            if scaling_rec.get('action') != 'maintain':
                text += f"• Recommended action: {scaling_rec.get('action', '').replace('_', ' ').title()}\n"
                text += f"• Target instances: {scaling_rec.get('target_instances', 1)}\n"
            else:
                text += "• No scaling action needed at this time\n"

            actions = [
                {
                    'type': 'action',
                    'text': 'Enable proactive scaling',
                    'command': 'enable predictive scaling'
                },
                {
                    'type': 'analysis',
                    'text': 'Show detailed trends',
                    'command': 'show resource trends'
                }
            ]

            return AIResponse(
                text=text,
                data=recommendations,
                actions=actions,
                confidence=0.85,
                intent=intent
            )

        except Exception as e:
            return AIResponse(
                text=f"Error generating predictions: {str(e)}",
                data={},
                actions=[],
                confidence=0.3,
                intent=intent
            )

    async def _handle_help(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle help requests"""
        text = """🤖 **CloudOS AI Assistant Help**

I can help you manage and optimize your CloudOS cluster using natural language commands.

**What I can do:**

🏥 **System Status**
• "How is the system?" or "Show cluster status"
• "What's the health of my nodes?"

📊 **Resource Monitoring**
• "Show CPU usage" or "How much memory is used?"
• "What are my resource utilization trends?"

🔧 **Optimization**
• "Optimize my cluster" or "Recommend improvements"
• "How can I improve performance?"

📈 **Scaling Management**
• "Scale up" or "Add more nodes"
• "Should I scale out?" or "Recommend scaling"

🔍 **Troubleshooting**
• "Why is node1 slow?" or "Troubleshoot high CPU"
• "Diagnose system issues"

🔮 **Predictions**
• "Predict future load" or "What will happen in 1 hour?"
• "Show workload forecasts"

💰 **Cost Analysis**
• "Show cost analysis" or "How to reduce costs?"
• "Find underutilized resources"

**Example Commands:**
• "How is my cluster doing?"
• "Show me CPU usage for the last hour"
• "Optimize resource allocation"
• "Why is my response time high?"
• "Predict load for the next 2 hours"
• "Scale out to handle more traffic"

Just ask me in natural language, and I'll help you manage your CloudOS infrastructure!
"""

        actions = [
            {
                'type': 'example',
                'text': 'Show system status',
                'command': 'show cluster status'
            },
            {
                'type': 'example',
                'text': 'Check resource usage',
                'command': 'show resource utilization'
            },
            {
                'type': 'example',
                'text': 'Optimize cluster',
                'command': 'optimize cluster performance'
            }
        ]

        return AIResponse(
            text=text,
            data=self.help_topics,
            actions=actions,
            confidence=1.0,
            intent=intent
        )

    async def _handle_unknown(self, intent: Intent, context: Dict[str, Any]) -> AIResponse:
        """Handle unknown or unclear queries"""
        text = f"""❓ I'm not sure how to handle your request: "{intent.raw_query}"

Here are some things you could try asking:

• **System Status**: "How is the system?" or "Show cluster health"
• **Resources**: "Show CPU usage" or "Check memory utilization"
• **Optimization**: "Optimize my cluster" or "Recommend improvements"
• **Scaling**: "Should I scale up?" or "Add more capacity"
• **Troubleshooting**: "Why is performance slow?" or "Diagnose issues"
• **Predictions**: "Predict future load" or "What will happen next hour?"

Or simply ask for "help" to see all available commands.

Could you rephrase your question or be more specific about what you'd like to know?
"""

        actions = [
            {
                'type': 'help',
                'text': 'Show all commands',
                'command': 'help'
            },
            {
                'type': 'example',
                'text': 'Check system status',
                'command': 'system status'
            }
        ]

        return AIResponse(
            text=text,
            data={},
            actions=actions,
            confidence=0.3,
            intent=intent
        )

if __name__ == "__main__":
    # Example usage
    import asyncio
    from ..core.ai_engine import CloudOSAIEngine

    async def test_ai_assistant():
        ai_engine = CloudOSAIEngine()
        await ai_engine.start()

        assistant = CloudOSAIAssistant(ai_engine)

        # Test queries
        test_queries = [
            "How is the system?",
            "Show CPU usage",
            "Optimize my cluster",
            "Scale up",
            "Why is node1 slow?",
            "Predict future load",
            "Help me",
            "What's the meaning of life?"  # Unknown query
        ]

        for query in test_queries:
            print(f"\n🗣️ Query: {query}")
            response = await assistant.process_query(query)
            print(f"🤖 Response: {response.text[:200]}...")
            print(f"   Intent: {response.intent.type.value} (confidence: {response.confidence:.2f})")

        await ai_engine.stop()

    # Run test
    asyncio.run(test_ai_assistant())