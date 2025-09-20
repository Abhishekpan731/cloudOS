#!/usr/bin/env python3
"""
CloudOS Multi-Master High Availability with Leader Election
etcd-based distributed consensus and failover management
"""

import asyncio
import json
import logging
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Callable, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import threading

# etcd client imports
try:
    import etcd3
    HAS_ETCD3 = True
except ImportError:
    HAS_ETCD3 = False

# Alternative etcd async client
try:
    import aioetcd3
    HAS_AIOETCD3 = True
except ImportError:
    HAS_AIOETCD3 = False

# Consul for alternative distributed consensus
try:
    import consul
    HAS_CONSUL = True
except ImportError:
    HAS_CONSUL = False

class NodeState(Enum):
    UNKNOWN = "unknown"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"
    FAILED = "failed"
    MAINTENANCE = "maintenance"

class HAEventType(Enum):
    LEADER_ELECTED = "leader_elected"
    LEADER_LOST = "leader_lost"
    NODE_JOINED = "node_joined"
    NODE_LEFT = "node_left"
    NODE_FAILED = "node_failed"
    FAILOVER_STARTED = "failover_started"
    FAILOVER_COMPLETED = "failover_completed"
    SPLIT_BRAIN_DETECTED = "split_brain_detected"

@dataclass
class ClusterNode:
    """Cluster node information"""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    state: NodeState = NodeState.UNKNOWN
    is_leader: bool = False
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    term: int = 0
    version: str = "1.0.0"
    metadata: Dict[str, Any] = field(default_factory=dict)
    capabilities: Set[str] = field(default_factory=set)

@dataclass
class HAEvent:
    """High availability event"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: HAEventType = HAEventType.NODE_JOINED
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    node_id: str = ""
    leader_id: Optional[str] = None
    term: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

class LeaderElection:
    """
    Distributed leader election using etcd or Consul
    Implements Raft-like consensus for CloudOS master nodes
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Node configuration
        self.node_id = self.config.get('node_id', self._generate_node_id())
        self.hostname = self.config.get('hostname', socket.gethostname())
        self.ip_address = self.config.get('ip_address', self._get_local_ip())
        self.port = self.config.get('port', 8080)

        # Cluster configuration
        self.cluster_name = self.config.get('cluster_name', 'cloudos-cluster')
        self.etcd_endpoints = self.config.get('etcd_endpoints', ['localhost:2379'])
        self.lease_ttl = self.config.get('lease_ttl', 30)  # seconds
        self.election_timeout = self.config.get('election_timeout', 10)  # seconds

        # State management
        self.current_state = NodeState.FOLLOWER
        self.current_term = 0
        self.voted_for: Optional[str] = None
        self.leader_id: Optional[str] = None
        self.is_leader = False

        # Cluster state
        self.cluster_nodes: Dict[str, ClusterNode] = {}
        self.ha_events: List[HAEvent] = []

        # etcd/Consul clients
        self.etcd_client = None
        self.consul_client = None
        self.lease_id = None

        # Callbacks and handlers
        self.leader_elected_callbacks: List[Callable[[str], None]] = []
        self.leader_lost_callbacks: List[Callable[[str], None]] = []
        self.node_joined_callbacks: List[Callable[[ClusterNode], None]] = []
        self.node_failed_callbacks: List[Callable[[ClusterNode], None]] = []

        # Background tasks
        self.running = False
        self.election_task = None
        self.heartbeat_task = None
        self.monitor_task = None

        # Leadership management
        self.leadership_acquired_at: Optional[datetime] = None
        self.last_heartbeat_sent: Optional[datetime] = None
        self.followers: Set[str] = set()

        # Initialize distributed store client
        self._initialize_distributed_store()

        self.logger.info(f"Leader Election initialized for node {self.node_id}")

    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        return f"node-{uuid.uuid4().hex[:8]}"

    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def _initialize_distributed_store(self):
        """Initialize etcd or Consul client"""
        backend = self.config.get('backend', 'etcd')

        if backend == 'etcd' and HAS_ETCD3:
            try:
                self.etcd_client = etcd3.client(
                    host=self.etcd_endpoints[0].split(':')[0],
                    port=int(self.etcd_endpoints[0].split(':')[1])
                )
                self.logger.info("etcd client initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize etcd client: {e}")

        elif backend == 'consul' and HAS_CONSUL:
            try:
                consul_host = self.config.get('consul_host', 'localhost')
                consul_port = self.config.get('consul_port', 8500)
                self.consul_client = consul.Consul(host=consul_host, port=consul_port)
                self.logger.info("Consul client initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Consul client: {e}")

        else:
            self.logger.warning(f"Distributed store backend '{backend}' not available")

    async def start(self):
        """Start leader election and HA services"""
        if self.running:
            return

        self.running = True

        # Register this node in the cluster
        await self._register_node()

        # Start background tasks
        self.election_task = asyncio.create_task(self._election_loop())
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self.monitor_task = asyncio.create_task(self._monitor_loop())

        self.logger.info(f"Leader Election started for node {self.node_id}")

    async def stop(self):
        """Stop leader election and cleanup"""
        if not self.running:
            return

        self.running = False

        # Step down if leader
        if self.is_leader:
            await self._step_down()

        # Cancel background tasks
        if self.election_task:
            self.election_task.cancel()
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        if self.monitor_task:
            self.monitor_task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(
            self.election_task, self.heartbeat_task, self.monitor_task,
            return_exceptions=True
        )

        # Cleanup distributed store
        await self._unregister_node()

        self.logger.info(f"Leader Election stopped for node {self.node_id}")

    async def _register_node(self):
        """Register this node in the cluster"""
        node = ClusterNode(
            node_id=self.node_id,
            hostname=self.hostname,
            ip_address=self.ip_address,
            port=self.port,
            state=self.current_state,
            term=self.current_term,
            capabilities={'ai_engine', 'cost_optimizer', 'self_healing'}
        )

        self.cluster_nodes[self.node_id] = node

        # Register in distributed store
        if self.etcd_client:
            await self._register_node_etcd(node)
        elif self.consul_client:
            await self._register_node_consul(node)

    async def _register_node_etcd(self, node: ClusterNode):
        """Register node in etcd"""
        try:
            # Create lease for the node
            lease = self.etcd_client.lease(self.lease_ttl)
            self.lease_id = lease.id

            # Register node data
            node_key = f"/cloudos/cluster/{self.cluster_name}/nodes/{node.node_id}"
            node_data = {
                'hostname': node.hostname,
                'ip_address': node.ip_address,
                'port': node.port,
                'state': node.state.value,
                'term': node.term,
                'registered_at': datetime.now(timezone.utc).isoformat(),
                'capabilities': list(node.capabilities)
            }

            self.etcd_client.put(node_key, json.dumps(node_data), lease=lease)

            # Keep lease alive
            lease.refresh()

            self.logger.info(f"Node {node.node_id} registered in etcd")

        except Exception as e:
            self.logger.error(f"Failed to register node in etcd: {e}")

    async def _register_node_consul(self, node: ClusterNode):
        """Register node in Consul"""
        try:
            service_id = f"cloudos-master-{node.node_id}"
            self.consul_client.agent.service.register(
                name="cloudos-master",
                service_id=service_id,
                address=node.ip_address,
                port=node.port,
                tags=list(node.capabilities),
                check=consul.Check.ttl(f"{self.lease_ttl}s")
            )

            # Store additional node data in KV
            node_key = f"cloudos/cluster/{self.cluster_name}/nodes/{node.node_id}"
            node_data = {
                'hostname': node.hostname,
                'ip_address': node.ip_address,
                'port': node.port,
                'state': node.state.value,
                'term': node.term,
                'registered_at': datetime.now(timezone.utc).isoformat()
            }

            self.consul_client.kv.put(node_key, json.dumps(node_data))

            self.logger.info(f"Node {node.node_id} registered in Consul")

        except Exception as e:
            self.logger.error(f"Failed to register node in Consul: {e}")

    async def _unregister_node(self):
        """Unregister this node from the cluster"""
        if self.etcd_client and self.lease_id:
            try:
                # Revoke lease to remove node data
                self.etcd_client.lease.revoke(self.lease_id)
                self.logger.info(f"Node {self.node_id} unregistered from etcd")
            except Exception as e:
                self.logger.error(f"Failed to unregister from etcd: {e}")

        elif self.consul_client:
            try:
                service_id = f"cloudos-master-{self.node_id}"
                self.consul_client.agent.service.deregister(service_id)
                self.logger.info(f"Node {self.node_id} unregistered from Consul")
            except Exception as e:
                self.logger.error(f"Failed to unregister from Consul: {e}")

    async def _election_loop(self):
        """Main leader election loop"""
        while self.running:
            try:
                if self.current_state == NodeState.FOLLOWER:
                    await self._follower_behavior()
                elif self.current_state == NodeState.CANDIDATE:
                    await self._candidate_behavior()
                elif self.current_state == NodeState.LEADER:
                    await self._leader_behavior()

                await asyncio.sleep(1)  # Election loop interval

            except Exception as e:
                self.logger.error(f"Election loop error: {e}")
                await asyncio.sleep(5)

    async def _follower_behavior(self):
        """Behavior when node is a follower"""
        # Check if leader is still alive
        if self.leader_id:
            leader_alive = await self._check_leader_alive()
            if not leader_alive:
                self.logger.info(f"Leader {self.leader_id} appears to be down")
                await self._start_election()
        else:
            # No leader known, start election after timeout
            await asyncio.sleep(self.election_timeout)
            if not self.leader_id:  # Still no leader
                await self._start_election()

    async def _candidate_behavior(self):
        """Behavior when node is a candidate"""
        # Request votes from other nodes
        votes_received = await self._request_votes()

        # Check if we have majority
        total_nodes = len(self.cluster_nodes)
        required_votes = (total_nodes // 2) + 1

        if votes_received >= required_votes:
            await self._become_leader()
        else:
            # Election failed, return to follower
            await self._become_follower()

    async def _leader_behavior(self):
        """Behavior when node is the leader"""
        # Send heartbeats to followers
        await self._send_heartbeats()

        # Check cluster health
        await self._check_cluster_health()

        # Handle any pending leadership tasks
        await self._handle_leadership_tasks()

    async def _start_election(self):
        """Start a new election"""
        self.current_state = NodeState.CANDIDATE
        self.current_term += 1
        self.voted_for = self.node_id  # Vote for self

        event = HAEvent(
            event_type=HAEventType.LEADER_ELECTED,
            node_id=self.node_id,
            term=self.current_term,
            details={'started_election': True}
        )
        self.ha_events.append(event)

        self.logger.info(f"Starting election for term {self.current_term}")

    async def _request_votes(self) -> int:
        """Request votes from other nodes"""
        votes = 1  # Vote for self

        # In a real implementation, this would send vote requests to other nodes
        # For now, we'll simulate based on cluster state
        for node_id, node in self.cluster_nodes.items():
            if node_id != self.node_id and node.state != NodeState.FAILED:
                # Simulate vote request
                if await self._send_vote_request(node):
                    votes += 1

        return votes

    async def _send_vote_request(self, node: ClusterNode) -> bool:
        """Send vote request to a node"""
        try:
            # In a real implementation, this would make an HTTP/gRPC call
            # For simulation, we'll use simple logic

            # Node votes for us if:
            # 1. Our term is higher
            # 2. Node hasn't voted in this term
            # 3. We're up to date

            if self.current_term > node.term:
                # Update node's term and vote
                node.term = self.current_term
                self.logger.debug(f"Received vote from {node.node_id}")
                return True

        except Exception as e:
            self.logger.error(f"Failed to request vote from {node.node_id}: {e}")

        return False

    async def _become_leader(self):
        """Become the cluster leader"""
        self.current_state = NodeState.LEADER
        self.is_leader = True
        self.leader_id = self.node_id
        self.leadership_acquired_at = datetime.now(timezone.utc)
        self.followers = set(node_id for node_id in self.cluster_nodes.keys() if node_id != self.node_id)

        # Update in distributed store
        await self._update_leader_info()

        # Create leadership event
        event = HAEvent(
            event_type=HAEventType.LEADER_ELECTED,
            node_id=self.node_id,
            leader_id=self.node_id,
            term=self.current_term,
            details={'leadership_acquired': True}
        )
        self.ha_events.append(event)

        # Notify callbacks
        for callback in self.leader_elected_callbacks:
            try:
                callback(self.node_id)
            except Exception as e:
                self.logger.error(f"Leader elected callback error: {e}")

        self.logger.info(f"Became leader for term {self.current_term}")

    async def _become_follower(self, leader_id: str = None):
        """Become a follower"""
        was_leader = self.is_leader

        self.current_state = NodeState.FOLLOWER
        self.is_leader = False
        self.voted_for = None

        if leader_id:
            self.leader_id = leader_id

        if was_leader:
            # Notify callbacks about leadership loss
            for callback in self.leader_lost_callbacks:
                try:
                    callback(self.node_id)
                except Exception as e:
                    self.logger.error(f"Leader lost callback error: {e}")

            # Create leadership lost event
            event = HAEvent(
                event_type=HAEventType.LEADER_LOST,
                node_id=self.node_id,
                leader_id=self.leader_id,
                term=self.current_term,
                details={'stepped_down': True}
            )
            self.ha_events.append(event)

            self.logger.info(f"Stepped down from leadership in term {self.current_term}")

    async def _step_down(self):
        """Step down from leadership"""
        if self.is_leader:
            await self._become_follower()

    async def _update_leader_info(self):
        """Update leader information in distributed store"""
        if self.etcd_client:
            try:
                leader_key = f"/cloudos/cluster/{self.cluster_name}/leader"
                leader_data = {
                    'node_id': self.node_id,
                    'hostname': self.hostname,
                    'ip_address': self.ip_address,
                    'port': self.port,
                    'term': self.current_term,
                    'elected_at': datetime.now(timezone.utc).isoformat()
                }

                self.etcd_client.put(leader_key, json.dumps(leader_data), lease=self.lease_id)

            except Exception as e:
                self.logger.error(f"Failed to update leader info in etcd: {e}")

        elif self.consul_client:
            try:
                leader_key = f"cloudos/cluster/{self.cluster_name}/leader"
                leader_data = {
                    'node_id': self.node_id,
                    'hostname': self.hostname,
                    'ip_address': self.ip_address,
                    'port': self.port,
                    'term': self.current_term,
                    'elected_at': datetime.now(timezone.utc).isoformat()
                }

                self.consul_client.kv.put(leader_key, json.dumps(leader_data))

            except Exception as e:
                self.logger.error(f"Failed to update leader info in Consul: {e}")

    async def _check_leader_alive(self) -> bool:
        """Check if current leader is still alive"""
        if not self.leader_id:
            return False

        try:
            if self.etcd_client:
                leader_key = f"/cloudos/cluster/{self.cluster_name}/leader"
                result = self.etcd_client.get(leader_key)
                if result[0] is None:
                    return False

                leader_data = json.loads(result[0].decode())
                return leader_data.get('node_id') == self.leader_id

            elif self.consul_client:
                leader_key = f"cloudos/cluster/{self.cluster_name}/leader"
                _, data = self.consul_client.kv.get(leader_key)
                if not data:
                    return False

                leader_data = json.loads(data['Value'].decode())
                return leader_data.get('node_id') == self.leader_id

        except Exception as e:
            self.logger.error(f"Failed to check leader status: {e}")

        return False

    async def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while self.running:
            try:
                if self.is_leader:
                    await self._send_heartbeats()
                else:
                    await self._update_heartbeat()

                await asyncio.sleep(self.lease_ttl // 3)  # Send heartbeat every 1/3 of lease TTL

            except Exception as e:
                self.logger.error(f"Heartbeat loop error: {e}")
                await asyncio.sleep(5)

    async def _send_heartbeats(self):
        """Send heartbeats to all followers"""
        if not self.is_leader:
            return

        self.last_heartbeat_sent = datetime.now(timezone.utc)

        # Update leader heartbeat in distributed store
        await self._update_leader_heartbeat()

        # In a real implementation, this would send heartbeats to all followers
        self.logger.debug(f"Sent heartbeats to {len(self.followers)} followers")

    async def _update_heartbeat(self):
        """Update this node's heartbeat"""
        if self.etcd_client and self.lease_id:
            try:
                # Refresh lease to maintain presence
                self.etcd_client.lease.refresh(self.lease_id)
            except Exception as e:
                self.logger.error(f"Failed to refresh etcd lease: {e}")

        elif self.consul_client:
            try:
                # Update TTL check
                service_id = f"cloudos-master-{self.node_id}"
                self.consul_client.agent.check.ttl_pass(f"service:{service_id}")
            except Exception as e:
                self.logger.error(f"Failed to update Consul TTL: {e}")

    async def _update_leader_heartbeat(self):
        """Update leader heartbeat timestamp"""
        if self.etcd_client:
            try:
                heartbeat_key = f"/cloudos/cluster/{self.cluster_name}/leader/heartbeat"
                heartbeat_data = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'term': self.current_term
                }
                self.etcd_client.put(heartbeat_key, json.dumps(heartbeat_data))
            except Exception as e:
                self.logger.error(f"Failed to update leader heartbeat: {e}")

    async def _monitor_loop(self):
        """Monitor cluster health and detect failures"""
        while self.running:
            try:
                await self._discover_nodes()
                await self._check_node_health()
                await self._detect_split_brain()

                await asyncio.sleep(10)  # Monitor every 10 seconds

            except Exception as e:
                self.logger.error(f"Monitor loop error: {e}")
                await asyncio.sleep(10)

    async def _discover_nodes(self):
        """Discover other nodes in the cluster"""
        if self.etcd_client:
            await self._discover_nodes_etcd()
        elif self.consul_client:
            await self._discover_nodes_consul()

    async def _discover_nodes_etcd(self):
        """Discover nodes using etcd"""
        try:
            nodes_prefix = f"/cloudos/cluster/{self.cluster_name}/nodes/"
            result = self.etcd_client.get_prefix(nodes_prefix)

            current_nodes = set()
            for value, metadata in result:
                try:
                    node_data = json.loads(value.decode())
                    node_id = metadata.key.decode().split('/')[-1]
                    current_nodes.add(node_id)

                    if node_id not in self.cluster_nodes:
                        # New node discovered
                        node = ClusterNode(
                            node_id=node_id,
                            hostname=node_data.get('hostname', ''),
                            ip_address=node_data.get('ip_address', ''),
                            port=node_data.get('port', 0),
                            state=NodeState(node_data.get('state', 'unknown')),
                            term=node_data.get('term', 0),
                            capabilities=set(node_data.get('capabilities', []))
                        )
                        self.cluster_nodes[node_id] = node

                        # Notify callbacks
                        for callback in self.node_joined_callbacks:
                            try:
                                callback(node)
                            except Exception as e:
                                self.logger.error(f"Node joined callback error: {e}")

                        self.logger.info(f"Discovered new node: {node_id}")

                except Exception as e:
                    self.logger.error(f"Failed to parse node data: {e}")

            # Check for removed nodes
            removed_nodes = set(self.cluster_nodes.keys()) - current_nodes - {self.node_id}
            for node_id in removed_nodes:
                node = self.cluster_nodes.pop(node_id, None)
                if node:
                    # Mark as failed and notify
                    node.state = NodeState.FAILED
                    for callback in self.node_failed_callbacks:
                        try:
                            callback(node)
                        except Exception as e:
                            self.logger.error(f"Node failed callback error: {e}")

                    self.logger.warning(f"Node {node_id} left the cluster")

        except Exception as e:
            self.logger.error(f"Failed to discover nodes from etcd: {e}")

    async def _discover_nodes_consul(self):
        """Discover nodes using Consul"""
        try:
            # Get all services with name 'cloudos-master'
            _, services = self.consul_client.health.service('cloudos-master', passing=True)

            current_nodes = set()
            for service in services:
                service_info = service['Service']
                node_id = service_info['ID'].replace('cloudos-master-', '')
                current_nodes.add(node_id)

                if node_id not in self.cluster_nodes:
                    # New node discovered
                    node = ClusterNode(
                        node_id=node_id,
                        hostname=service['Node']['Node'],
                        ip_address=service_info['Address'],
                        port=service_info['Port'],
                        capabilities=set(service_info.get('Tags', []))
                    )
                    self.cluster_nodes[node_id] = node

                    # Notify callbacks
                    for callback in self.node_joined_callbacks:
                        try:
                            callback(node)
                        except Exception as e:
                            self.logger.error(f"Node joined callback error: {e}")

                    self.logger.info(f"Discovered new node: {node_id}")

            # Check for removed nodes
            removed_nodes = set(self.cluster_nodes.keys()) - current_nodes - {self.node_id}
            for node_id in removed_nodes:
                node = self.cluster_nodes.pop(node_id, None)
                if node:
                    node.state = NodeState.FAILED
                    for callback in self.node_failed_callbacks:
                        try:
                            callback(node)
                        except Exception as e:
                            self.logger.error(f"Node failed callback error: {e}")

                    self.logger.warning(f"Node {node_id} left the cluster")

        except Exception as e:
            self.logger.error(f"Failed to discover nodes from Consul: {e}")

    async def _check_node_health(self):
        """Check health of all cluster nodes"""
        for node_id, node in self.cluster_nodes.items():
            if node_id == self.node_id:
                continue

            # Check if node heartbeat is stale
            stale_threshold = datetime.now(timezone.utc) - timedelta(seconds=self.lease_ttl * 2)
            if node.last_heartbeat < stale_threshold and node.state != NodeState.FAILED:
                node.state = NodeState.FAILED
                self.logger.warning(f"Node {node_id} marked as failed (stale heartbeat)")

    async def _detect_split_brain(self):
        """Detect split-brain scenarios"""
        if not self.is_leader:
            return

        # Check if there are other leaders
        other_leaders = []
        for node_id, node in self.cluster_nodes.items():
            if node_id != self.node_id and node.is_leader:
                other_leaders.append(node_id)

        if other_leaders:
            # Split-brain detected
            event = HAEvent(
                event_type=HAEventType.SPLIT_BRAIN_DETECTED,
                node_id=self.node_id,
                leader_id=self.leader_id,
                term=self.current_term,
                details={'other_leaders': other_leaders}
            )
            self.ha_events.append(event)

            self.logger.critical(f"Split-brain detected! Other leaders: {other_leaders}")

            # Resolve by stepping down if we have lower term
            max_term = max(self.cluster_nodes[leader].term for leader in other_leaders)
            if self.current_term <= max_term:
                await self._step_down()

    async def _check_cluster_health(self):
        """Check overall cluster health"""
        if not self.is_leader:
            return

        total_nodes = len(self.cluster_nodes)
        healthy_nodes = len([n for n in self.cluster_nodes.values() if n.state not in [NodeState.FAILED]])
        failed_nodes = total_nodes - healthy_nodes

        # Log cluster health status
        if failed_nodes > 0:
            self.logger.warning(f"Cluster health: {healthy_nodes}/{total_nodes} nodes healthy")

    async def _handle_leadership_tasks(self):
        """Handle tasks that only the leader should perform"""
        if not self.is_leader:
            return

        # Leader-specific tasks like:
        # - Coordinating cluster-wide operations
        # - Managing global state
        # - Handling client requests
        # - Orchestrating failovers

        pass

    # Public API Methods

    def add_leader_elected_callback(self, callback: Callable[[str], None]):
        """Add callback for leader election events"""
        self.leader_elected_callbacks.append(callback)

    def add_leader_lost_callback(self, callback: Callable[[str], None]):
        """Add callback for leader lost events"""
        self.leader_lost_callbacks.append(callback)

    def add_node_joined_callback(self, callback: Callable[[ClusterNode], None]):
        """Add callback for node joined events"""
        self.node_joined_callbacks.append(callback)

    def add_node_failed_callback(self, callback: Callable[[ClusterNode], None]):
        """Add callback for node failed events"""
        self.node_failed_callbacks.append(callback)

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get current cluster status"""
        return {
            'cluster_name': self.cluster_name,
            'node_id': self.node_id,
            'state': self.current_state.value,
            'is_leader': self.is_leader,
            'leader_id': self.leader_id,
            'current_term': self.current_term,
            'cluster_size': len(self.cluster_nodes),
            'healthy_nodes': len([n for n in self.cluster_nodes.values() if n.state not in [NodeState.FAILED]]),
            'leadership_acquired_at': self.leadership_acquired_at.isoformat() if self.leadership_acquired_at else None,
            'last_heartbeat_sent': self.last_heartbeat_sent.isoformat() if self.last_heartbeat_sent else None,
            'nodes': {
                node_id: {
                    'hostname': node.hostname,
                    'ip_address': node.ip_address,
                    'port': node.port,
                    'state': node.state.value,
                    'is_leader': node.is_leader,
                    'term': node.term,
                    'last_heartbeat': node.last_heartbeat.isoformat(),
                    'capabilities': list(node.capabilities)
                }
                for node_id, node in self.cluster_nodes.items()
            }
        }

    def get_ha_events(self, limit: int = 100) -> List[HAEvent]:
        """Get recent HA events"""
        return sorted(self.ha_events, key=lambda x: x.timestamp, reverse=True)[:limit]

# Example usage
if __name__ == "__main__":
    async def test_leader_election():
        # Configure leader election
        config = {
            'node_id': 'test-node-1',
            'cluster_name': 'test-cluster',
            'etcd_endpoints': ['localhost:2379'],
            'lease_ttl': 10
        }

        election = LeaderElection(config)

        # Add event callbacks
        def on_leader_elected(leader_id):
            print(f"Leader elected: {leader_id}")

        def on_leader_lost(former_leader_id):
            print(f"Leader lost: {former_leader_id}")

        def on_node_joined(node):
            print(f"Node joined: {node.node_id}")

        def on_node_failed(node):
            print(f"Node failed: {node.node_id}")

        election.add_leader_elected_callback(on_leader_elected)
        election.add_leader_lost_callback(on_leader_lost)
        election.add_node_joined_callback(on_node_joined)
        election.add_node_failed_callback(on_node_failed)

        # Start leader election
        await election.start()

        # Run for 60 seconds
        await asyncio.sleep(60)

        # Get cluster status
        status = election.get_cluster_status()
        print(f"Cluster status: {json.dumps(status, indent=2, default=str)}")

        # Stop election
        await election.stop()

    asyncio.run(test_leader_election())