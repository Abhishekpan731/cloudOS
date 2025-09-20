#!/usr/bin/env python3
"""
CloudOS Native Container Runtime Engine
High-performance container runtime with advanced resource isolation and orchestration
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
import threading

# Container management imports
try:
    import docker
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

# cgroups management
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Network namespace management
try:
    import pyroute2
    from pyroute2 import IPRoute, netns, NetNS
    HAS_PYROUTE2 = True
except ImportError:
    HAS_PYROUTE2 = False

class ContainerState(Enum):
    CREATED = "created"
    RUNNING = "running"
    STOPPED = "stopped"
    PAUSED = "paused"
    RESTARTING = "restarting"
    REMOVING = "removing"
    EXITED = "exited"
    DEAD = "dead"

class ContainerStatus(Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    UNKNOWN = "unknown"

class NetworkMode(Enum):
    BRIDGE = "bridge"
    HOST = "host"
    NONE = "none"
    CONTAINER = "container"
    CUSTOM = "custom"

class RestartPolicy(Enum):
    NO = "no"
    ALWAYS = "always"
    ON_FAILURE = "on-failure"
    UNLESS_STOPPED = "unless-stopped"

@dataclass
class ResourceLimits:
    """Container resource limits"""
    cpu_cores: Optional[float] = None
    cpu_shares: Optional[int] = None
    memory_bytes: Optional[int] = None
    memory_swap_bytes: Optional[int] = None
    pids_limit: Optional[int] = None
    disk_io_bps: Optional[int] = None
    network_bandwidth_bps: Optional[int] = None

@dataclass
class ContainerImage:
    """Container image metadata"""
    image_id: str
    repository: str
    tag: str
    digest: str
    size_bytes: int
    created_at: datetime
    layers: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    env_vars: Dict[str, str] = field(default_factory=dict)
    exposed_ports: Set[int] = field(default_factory=set)

@dataclass
class ContainerConfig:
    """Container configuration"""
    name: str
    image: str
    command: List[str] = field(default_factory=list)
    entrypoint: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    working_dir: str = "/"
    user: str = "root"
    hostname: str = ""
    network_mode: NetworkMode = NetworkMode.BRIDGE
    port_mappings: Dict[int, int] = field(default_factory=dict)  # container_port: host_port
    volumes: Dict[str, str] = field(default_factory=dict)  # host_path: container_path
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    restart_policy: RestartPolicy = RestartPolicy.NO
    restart_max_retries: int = 3
    health_check: Optional[Dict[str, Any]] = None
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)

@dataclass
class Container:
    """Container instance"""
    container_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    config: ContainerConfig = field(default_factory=ContainerConfig)
    state: ContainerState = ContainerState.CREATED
    status: ContainerStatus = ContainerStatus.UNKNOWN
    pid: Optional[int] = None
    exit_code: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    restart_count: int = 0
    ip_address: Optional[str] = None
    network_namespace: Optional[str] = None
    cgroup_path: Optional[str] = None
    root_fs_path: Optional[str] = None
    log_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ContainerStats:
    """Container runtime statistics"""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cpu_usage_percent: float = 0.0
    memory_usage_bytes: int = 0
    memory_limit_bytes: int = 0
    network_rx_bytes: int = 0
    network_tx_bytes: int = 0
    disk_read_bytes: int = 0
    disk_write_bytes: int = 0
    pids_current: int = 0
    pids_limit: int = 0

class CloudOSContainerRuntime:
    """
    Native container runtime for CloudOS
    Implements OCI-compatible container runtime with advanced features
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Runtime configuration
        self.runtime_root = Path(self.config.get('runtime_root', '/var/lib/cloudos/containers'))
        self.image_root = Path(self.config.get('image_root', '/var/lib/cloudos/images'))
        self.log_root = Path(self.config.get('log_root', '/var/log/cloudos/containers'))

        # Create directories
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.image_root.mkdir(parents=True, exist_ok=True)
        self.log_root.mkdir(parents=True, exist_ok=True)

        # Container and image storage
        self.containers: Dict[str, Container] = {}
        self.images: Dict[str, ContainerImage] = {}

        # Resource management
        self.cgroup_root = Path('/sys/fs/cgroup/cloudos')
        self.network_manager = None

        # Monitoring and statistics
        self.container_stats: Dict[str, List[ContainerStats]] = {}
        self.stats_retention_hours = self.config.get('stats_retention_hours', 24)

        # Background tasks
        self.running = False
        self.monitor_task = None
        self.stats_task = None
        self.cleanup_task = None

        # Initialize runtime components
        self._initialize_cgroups()
        self._initialize_networking()
        self._load_existing_containers()

        self.logger.info("CloudOS Container Runtime initialized")

    def _initialize_cgroups(self):
        """Initialize cgroups for container resource management"""
        try:
            if not self.cgroup_root.exists():
                self.cgroup_root.mkdir(parents=True, exist_ok=True)

            # Create cgroup hierarchies
            for controller in ['cpu', 'memory', 'pids', 'blkio']:
                controller_path = self.cgroup_root / controller
                controller_path.mkdir(exist_ok=True)

            self.logger.info("cgroups initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize cgroups: {e}")

    def _initialize_networking(self):
        """Initialize container networking"""
        try:
            if HAS_PYROUTE2:
                self.network_manager = ContainerNetworkManager()
                self.logger.info("Container networking initialized")
            else:
                self.logger.warning("pyroute2 not available - limited networking support")

        except Exception as e:
            self.logger.error(f"Failed to initialize networking: {e}")

    def _load_existing_containers(self):
        """Load existing containers from storage"""
        try:
            container_files = list(self.runtime_root.glob('*/config.json'))
            for config_file in container_files:
                try:
                    with open(config_file, 'r') as f:
                        container_data = json.load(f)

                    container = self._deserialize_container(container_data)
                    self.containers[container.container_id] = container

                except Exception as e:
                    self.logger.error(f"Failed to load container from {config_file}: {e}")

            self.logger.info(f"Loaded {len(self.containers)} existing containers")

        except Exception as e:
            self.logger.error(f"Failed to load existing containers: {e}")

    async def start(self):
        """Start the container runtime"""
        if self.running:
            return

        self.running = True

        # Start background tasks
        self.monitor_task = asyncio.create_task(self._monitor_containers())
        self.stats_task = asyncio.create_task(self._collect_stats())
        self.cleanup_task = asyncio.create_task(self._cleanup_task())

        self.logger.info("Container Runtime started")

    async def stop(self):
        """Stop the container runtime"""
        if not self.running:
            return

        self.running = False

        # Stop all running containers
        running_containers = [c for c in self.containers.values() if c.state == ContainerState.RUNNING]
        for container in running_containers:
            try:
                await self.stop_container(container.container_id)
            except Exception as e:
                self.logger.error(f"Failed to stop container {container.container_id}: {e}")

        # Cancel background tasks
        if self.monitor_task:
            self.monitor_task.cancel()
        if self.stats_task:
            self.stats_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()

        # Wait for tasks to complete
        await asyncio.gather(
            self.monitor_task, self.stats_task, self.cleanup_task,
            return_exceptions=True
        )

        self.logger.info("Container Runtime stopped")

    # Container Management

    async def create_container(self, config: ContainerConfig) -> str:
        """Create a new container"""
        try:
            # Validate configuration
            await self._validate_container_config(config)

            # Create container instance
            container = Container(
                name=config.name,
                config=config,
                state=ContainerState.CREATED
            )

            # Set up container environment
            await self._setup_container_environment(container)

            # Store container
            self.containers[container.container_id] = container
            await self._persist_container(container)

            self.logger.info(f"Created container {container.container_id} ({config.name})")
            return container.container_id

        except Exception as e:
            self.logger.error(f"Failed to create container: {e}")
            raise

    async def start_container(self, container_id: str) -> bool:
        """Start a container"""
        try:
            container = self.containers.get(container_id)
            if not container:
                raise ValueError(f"Container {container_id} not found")

            if container.state == ContainerState.RUNNING:
                self.logger.warning(f"Container {container_id} is already running")
                return True

            # Prepare container for execution
            await self._prepare_container_execution(container)

            # Start the container process
            await self._start_container_process(container)

            # Update container state
            container.state = ContainerState.RUNNING
            container.status = ContainerStatus.STARTING
            container.started_at = datetime.now(timezone.utc)

            await self._persist_container(container)

            self.logger.info(f"Started container {container_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start container {container_id}: {e}")
            # Update container state to reflect failure
            if container_id in self.containers:
                self.containers[container_id].state = ContainerState.EXITED
                self.containers[container_id].exit_code = 1
            return False

    async def stop_container(self, container_id: str, timeout: int = 10) -> bool:
        """Stop a container"""
        try:
            container = self.containers.get(container_id)
            if not container:
                raise ValueError(f"Container {container_id} not found")

            if container.state != ContainerState.RUNNING:
                self.logger.warning(f"Container {container_id} is not running")
                return True

            # Send SIGTERM to container process
            if container.pid:
                await self._stop_container_process(container, timeout)

            # Clean up container resources
            await self._cleanup_container_resources(container)

            # Update container state
            container.state = ContainerState.STOPPED
            container.finished_at = datetime.now(timezone.utc)

            await self._persist_container(container)

            self.logger.info(f"Stopped container {container_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to stop container {container_id}: {e}")
            return False

    async def remove_container(self, container_id: str, force: bool = False) -> bool:
        """Remove a container"""
        try:
            container = self.containers.get(container_id)
            if not container:
                raise ValueError(f"Container {container_id} not found")

            # Stop container if running
            if container.state == ContainerState.RUNNING:
                if not force:
                    raise ValueError(f"Container {container_id} is running. Use force=True to remove")
                await self.stop_container(container_id)

            # Clean up all container resources
            await self._cleanup_container_completely(container)

            # Remove from registry
            del self.containers[container_id]

            self.logger.info(f"Removed container {container_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to remove container {container_id}: {e}")
            return False

    async def restart_container(self, container_id: str) -> bool:
        """Restart a container"""
        try:
            container = self.containers.get(container_id)
            if not container:
                raise ValueError(f"Container {container_id} not found")

            # Stop container if running
            if container.state == ContainerState.RUNNING:
                await self.stop_container(container_id)

            # Start container
            success = await self.start_container(container_id)

            if success:
                container.restart_count += 1
                await self._persist_container(container)

            return success

        except Exception as e:
            self.logger.error(f"Failed to restart container {container_id}: {e}")
            return False

    async def pause_container(self, container_id: str) -> bool:
        """Pause a container"""
        try:
            container = self.containers.get(container_id)
            if not container:
                raise ValueError(f"Container {container_id} not found")

            if container.state != ContainerState.RUNNING:
                raise ValueError(f"Container {container_id} is not running")

            # Send SIGSTOP to container process
            if container.pid and HAS_PSUTIL:
                process = psutil.Process(container.pid)
                process.suspend()

            container.state = ContainerState.PAUSED
            await self._persist_container(container)

            self.logger.info(f"Paused container {container_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to pause container {container_id}: {e}")
            return False

    async def unpause_container(self, container_id: str) -> bool:
        """Unpause a container"""
        try:
            container = self.containers.get(container_id)
            if not container:
                raise ValueError(f"Container {container_id} not found")

            if container.state != ContainerState.PAUSED:
                raise ValueError(f"Container {container_id} is not paused")

            # Send SIGCONT to container process
            if container.pid and HAS_PSUTIL:
                process = psutil.Process(container.pid)
                process.resume()

            container.state = ContainerState.RUNNING
            await self._persist_container(container)

            self.logger.info(f"Unpaused container {container_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to unpause container {container_id}: {e}")
            return False

    # Container Environment Setup

    async def _validate_container_config(self, config: ContainerConfig):
        """Validate container configuration"""
        if not config.name:
            raise ValueError("Container name is required")

        if not config.image:
            raise ValueError("Container image is required")

        # Check for name conflicts
        for container in self.containers.values():
            if container.name == config.name and container.state != ContainerState.EXITED:
                raise ValueError(f"Container with name '{config.name}' already exists")

        # Validate resource limits
        if config.resource_limits.memory_bytes and config.resource_limits.memory_bytes < 1024 * 1024:  # 1MB minimum
            raise ValueError("Memory limit must be at least 1MB")

        if config.resource_limits.cpu_cores and config.resource_limits.cpu_cores <= 0:
            raise ValueError("CPU cores must be positive")

    async def _setup_container_environment(self, container: Container):
        """Set up container runtime environment"""
        # Create container directory
        container_dir = self.runtime_root / container.container_id
        container_dir.mkdir(exist_ok=True)

        # Set up root filesystem
        container.root_fs_path = str(container_dir / "rootfs")
        await self._setup_container_rootfs(container)

        # Set up networking
        if self.network_manager:
            container.network_namespace = await self.network_manager.create_network_namespace(container)

        # Set up cgroups
        container.cgroup_path = await self._setup_container_cgroups(container)

        # Set up logging
        container.log_path = str(self.log_root / f"{container.container_id}.log")

    async def _setup_container_rootfs(self, container: Container):
        """Set up container root filesystem"""
        rootfs_path = Path(container.root_fs_path)
        rootfs_path.mkdir(parents=True, exist_ok=True)

        # For now, create a minimal rootfs
        # In a full implementation, this would extract container image layers
        essential_dirs = ['bin', 'etc', 'lib', 'proc', 'sys', 'tmp', 'var', 'dev']
        for dir_name in essential_dirs:
            (rootfs_path / dir_name).mkdir(exist_ok=True)

        # Copy essential files (simplified)
        # In production, this would be handled by image layer extraction

    async def _setup_container_cgroups(self, container: Container) -> str:
        """Set up cgroups for container resource management"""
        cgroup_name = f"container-{container.container_id}"
        cgroup_path = self.cgroup_root / cgroup_name

        try:
            cgroup_path.mkdir(exist_ok=True)

            # Set resource limits
            limits = container.config.resource_limits

            if limits.memory_bytes:
                memory_limit_file = cgroup_path / "memory.limit_in_bytes"
                with open(memory_limit_file, 'w') as f:
                    f.write(str(limits.memory_bytes))

            if limits.cpu_cores:
                cpu_quota_file = cgroup_path / "cpu.cfs_quota_us"
                cpu_period_file = cgroup_path / "cpu.cfs_period_us"
                period = 100000  # 100ms
                quota = int(limits.cpu_cores * period)

                with open(cpu_period_file, 'w') as f:
                    f.write(str(period))
                with open(cpu_quota_file, 'w') as f:
                    f.write(str(quota))

            if limits.pids_limit:
                pids_limit_file = cgroup_path / "pids.max"
                with open(pids_limit_file, 'w') as f:
                    f.write(str(limits.pids_limit))

            return str(cgroup_path)

        except Exception as e:
            self.logger.error(f"Failed to setup cgroups for container {container.container_id}: {e}")
            return ""

    async def _prepare_container_execution(self, container: Container):
        """Prepare container for execution"""
        # Ensure image is available
        if container.config.image not in self.images:
            # In a full implementation, this would pull the image
            await self._ensure_image_available(container.config.image)

        # Set up volume mounts
        await self._setup_volume_mounts(container)

        # Set up port mappings
        if self.network_manager:
            await self.network_manager.setup_port_mappings(container)

    async def _ensure_image_available(self, image_name: str):
        """Ensure container image is available"""
        # For demonstration, create a minimal image entry
        if image_name not in self.images:
            image = ContainerImage(
                image_id=str(uuid.uuid4()),
                repository=image_name.split(':')[0] if ':' in image_name else image_name,
                tag=image_name.split(':')[1] if ':' in image_name else 'latest',
                digest=f"sha256:{uuid.uuid4().hex}",
                size_bytes=100 * 1024 * 1024,  # 100MB placeholder
                created_at=datetime.now(timezone.utc)
            )
            self.images[image_name] = image

    async def _setup_volume_mounts(self, container: Container):
        """Set up volume mounts for container"""
        for host_path, container_path in container.config.volumes.items():
            host_path_obj = Path(host_path)
            if not host_path_obj.exists():
                self.logger.warning(f"Host path {host_path} does not exist")
                continue

            # In a full implementation, this would set up bind mounts
            # For now, we just log the mount configuration
            self.logger.debug(f"Would mount {host_path} to {container_path}")

    # Container Process Management

    async def _start_container_process(self, container: Container):
        """Start the container process"""
        try:
            # Build command
            command = container.config.entrypoint + container.config.command
            if not command:
                command = ["/bin/sh"]  # Default shell

            # Set up environment
            env = dict(os.environ)
            env.update(container.config.environment)

            # Start process with namespace isolation
            # In a full implementation, this would use proper namespace isolation
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=container.config.working_dir,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            container.pid = process.pid

            # Add process to cgroup
            if container.cgroup_path:
                await self._add_process_to_cgroup(container.pid, container.cgroup_path)

            # Start log collection
            asyncio.create_task(self._collect_container_logs(container, process))

        except Exception as e:
            self.logger.error(f"Failed to start process for container {container.container_id}: {e}")
            raise

    async def _add_process_to_cgroup(self, pid: int, cgroup_path: str):
        """Add process to cgroup"""
        try:
            cgroup_procs_file = Path(cgroup_path) / "cgroup.procs"
            with open(cgroup_procs_file, 'w') as f:
                f.write(str(pid))
        except Exception as e:
            self.logger.error(f"Failed to add process {pid} to cgroup {cgroup_path}: {e}")

    async def _collect_container_logs(self, container: Container, process: asyncio.subprocess.Process):
        """Collect container logs"""
        try:
            with open(container.log_path, 'w') as log_file:
                async for line in process.stdout:
                    timestamp = datetime.now(timezone.utc).isoformat()
                    log_entry = f"{timestamp} {line.decode().rstrip()}\n"
                    log_file.write(log_entry)
                    log_file.flush()

            # Wait for process to complete
            exit_code = await process.wait()
            container.exit_code = exit_code
            container.state = ContainerState.EXITED
            container.finished_at = datetime.now(timezone.utc)

            # Handle restart policy
            await self._handle_container_restart_policy(container)

        except Exception as e:
            self.logger.error(f"Error collecting logs for container {container.container_id}: {e}")

    async def _stop_container_process(self, container: Container, timeout: int):
        """Stop container process"""
        if not container.pid:
            return

        try:
            if HAS_PSUTIL:
                process = psutil.Process(container.pid)

                # Send SIGTERM
                process.terminate()

                # Wait for graceful shutdown
                try:
                    process.wait(timeout=timeout)
                except psutil.TimeoutExpired:
                    # Force kill if timeout
                    process.kill()
                    process.wait(timeout=5)

            container.pid = None

        except psutil.NoSuchProcess:
            # Process already exited
            container.pid = None
        except Exception as e:
            self.logger.error(f"Failed to stop process for container {container.container_id}: {e}")

    async def _handle_container_restart_policy(self, container: Container):
        """Handle container restart policy"""
        policy = container.config.restart_policy

        if policy == RestartPolicy.NO:
            return

        if policy == RestartPolicy.ALWAYS:
            await self._schedule_container_restart(container)
        elif policy == RestartPolicy.ON_FAILURE and container.exit_code != 0:
            if container.restart_count < container.config.restart_max_retries:
                await self._schedule_container_restart(container)
        elif policy == RestartPolicy.UNLESS_STOPPED and container.state != ContainerState.STOPPED:
            await self._schedule_container_restart(container)

    async def _schedule_container_restart(self, container: Container):
        """Schedule container restart"""
        # Implement exponential backoff
        delay = min(2 ** container.restart_count, 60)  # Max 60 seconds

        async def restart_after_delay():
            await asyncio.sleep(delay)
            await self.restart_container(container.container_id)

        asyncio.create_task(restart_after_delay())

    # Resource Cleanup

    async def _cleanup_container_resources(self, container: Container):
        """Clean up container resources"""
        # Clean up cgroups
        if container.cgroup_path:
            await self._cleanup_cgroup(container.cgroup_path)

        # Clean up network namespace
        if self.network_manager and container.network_namespace:
            await self.network_manager.cleanup_network_namespace(container)

    async def _cleanup_container_completely(self, container: Container):
        """Completely clean up container"""
        await self._cleanup_container_resources(container)

        # Remove container directory
        container_dir = self.runtime_root / container.container_id
        if container_dir.exists():
            shutil.rmtree(container_dir)

        # Remove log file
        if container.log_path and Path(container.log_path).exists():
            Path(container.log_path).unlink()

        # Remove from stats
        if container.container_id in self.container_stats:
            del self.container_stats[container.container_id]

    async def _cleanup_cgroup(self, cgroup_path: str):
        """Clean up cgroup"""
        try:
            cgroup_dir = Path(cgroup_path)
            if cgroup_dir.exists():
                # Remove all processes from cgroup first
                procs_file = cgroup_dir / "cgroup.procs"
                if procs_file.exists():
                    with open(procs_file, 'w') as f:
                        pass  # Empty the file

                # Remove cgroup directory
                cgroup_dir.rmdir()

        except Exception as e:
            self.logger.error(f"Failed to cleanup cgroup {cgroup_path}: {e}")

    # Background Tasks

    async def _monitor_containers(self):
        """Monitor container health and state"""
        while self.running:
            try:
                for container in list(self.containers.values()):
                    await self._check_container_health(container)

                await asyncio.sleep(10)  # Check every 10 seconds

            except Exception as e:
                self.logger.error(f"Container monitoring error: {e}")
                await asyncio.sleep(10)

    async def _check_container_health(self, container: Container):
        """Check individual container health"""
        if container.state != ContainerState.RUNNING:
            return

        # Check if process is still alive
        if container.pid and HAS_PSUTIL:
            try:
                process = psutil.Process(container.pid)
                if not process.is_running():
                    container.state = ContainerState.EXITED
                    container.exit_code = process.returncode if hasattr(process, 'returncode') else 0
                    container.finished_at = datetime.now(timezone.utc)
                    await self._persist_container(container)
            except psutil.NoSuchProcess:
                container.state = ContainerState.EXITED
                container.exit_code = 1
                container.finished_at = datetime.now(timezone.utc)
                await self._persist_container(container)

        # Check health check command
        if container.config.health_check and container.state == ContainerState.RUNNING:
            await self._run_health_check(container)

    async def _run_health_check(self, container: Container):
        """Run container health check"""
        try:
            health_config = container.config.health_check
            command = health_config.get('test', [])
            timeout = health_config.get('timeout', 30)

            if command:
                # Execute health check command
                # In a full implementation, this would run inside the container
                # For now, we'll simulate a basic check
                container.status = ContainerStatus.HEALTHY

        except Exception as e:
            self.logger.error(f"Health check failed for container {container.container_id}: {e}")
            container.status = ContainerStatus.UNHEALTHY

    async def _collect_stats(self):
        """Collect container statistics"""
        while self.running:
            try:
                for container in self.containers.values():
                    if container.state == ContainerState.RUNNING and container.pid:
                        stats = await self._get_container_stats(container)
                        if stats:
                            if container.container_id not in self.container_stats:
                                self.container_stats[container.container_id] = []

                            self.container_stats[container.container_id].append(stats)

                            # Keep only recent stats
                            max_stats = self.stats_retention_hours * 60  # Assuming 1-minute intervals
                            if len(self.container_stats[container.container_id]) > max_stats:
                                self.container_stats[container.container_id] = \
                                    self.container_stats[container.container_id][-max_stats:]

                await asyncio.sleep(60)  # Collect stats every minute

            except Exception as e:
                self.logger.error(f"Stats collection error: {e}")
                await asyncio.sleep(60)

    async def _get_container_stats(self, container: Container) -> Optional[ContainerStats]:
        """Get current container statistics"""
        if not container.pid or not HAS_PSUTIL:
            return None

        try:
            process = psutil.Process(container.pid)

            # Get process stats
            with process.oneshot():
                cpu_percent = process.cpu_percent()
                memory_info = process.memory_info()
                io_counters = process.io_counters() if hasattr(process, 'io_counters') else None

            # Get cgroup stats if available
            memory_limit = await self._get_cgroup_memory_limit(container.cgroup_path)

            stats = ContainerStats(
                cpu_usage_percent=cpu_percent,
                memory_usage_bytes=memory_info.rss,
                memory_limit_bytes=memory_limit or 0,
                disk_read_bytes=io_counters.read_bytes if io_counters else 0,
                disk_write_bytes=io_counters.write_bytes if io_counters else 0,
                pids_current=1  # Simplified - would count all processes in container
            )

            return stats

        except Exception as e:
            self.logger.error(f"Failed to get stats for container {container.container_id}: {e}")
            return None

    async def _get_cgroup_memory_limit(self, cgroup_path: str) -> Optional[int]:
        """Get memory limit from cgroup"""
        if not cgroup_path:
            return None

        try:
            limit_file = Path(cgroup_path) / "memory.limit_in_bytes"
            if limit_file.exists():
                with open(limit_file, 'r') as f:
                    return int(f.read().strip())
        except Exception:
            pass

        return None

    async def _cleanup_task(self):
        """Clean up old data and resources"""
        while self.running:
            try:
                # Clean up exited containers older than 1 hour
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)

                containers_to_remove = []
                for container_id, container in self.containers.items():
                    if (container.state == ContainerState.EXITED and
                        container.finished_at and container.finished_at < cutoff_time):
                        containers_to_remove.append(container_id)

                for container_id in containers_to_remove:
                    await self.remove_container(container_id, force=True)

                await asyncio.sleep(3600)  # Run cleanup every hour

            except Exception as e:
                self.logger.error(f"Cleanup task error: {e}")
                await asyncio.sleep(3600)

    # Persistence

    async def _persist_container(self, container: Container):
        """Persist container state to disk"""
        try:
            container_dir = self.runtime_root / container.container_id
            container_dir.mkdir(exist_ok=True)

            config_file = container_dir / "config.json"
            with open(config_file, 'w') as f:
                json.dump(self._serialize_container(container), f, indent=2, default=str)

        except Exception as e:
            self.logger.error(f"Failed to persist container {container.container_id}: {e}")

    def _serialize_container(self, container: Container) -> Dict[str, Any]:
        """Serialize container to JSON-compatible format"""
        return {
            'container_id': container.container_id,
            'name': container.name,
            'config': {
                'name': container.config.name,
                'image': container.config.image,
                'command': container.config.command,
                'entrypoint': container.config.entrypoint,
                'environment': container.config.environment,
                'working_dir': container.config.working_dir,
                'user': container.config.user,
                'hostname': container.config.hostname,
                'network_mode': container.config.network_mode.value,
                'port_mappings': container.config.port_mappings,
                'volumes': container.config.volumes,
                'restart_policy': container.config.restart_policy.value,
                'restart_max_retries': container.config.restart_max_retries,
                'labels': container.config.labels,
                'annotations': container.config.annotations
            },
            'state': container.state.value,
            'status': container.status.value,
            'pid': container.pid,
            'exit_code': container.exit_code,
            'started_at': container.started_at.isoformat() if container.started_at else None,
            'finished_at': container.finished_at.isoformat() if container.finished_at else None,
            'restart_count': container.restart_count,
            'ip_address': container.ip_address,
            'network_namespace': container.network_namespace,
            'cgroup_path': container.cgroup_path,
            'root_fs_path': container.root_fs_path,
            'log_path': container.log_path,
            'metadata': container.metadata
        }

    def _deserialize_container(self, data: Dict[str, Any]) -> Container:
        """Deserialize container from JSON data"""
        config_data = data.get('config', {})
        config = ContainerConfig(
            name=config_data.get('name', ''),
            image=config_data.get('image', ''),
            command=config_data.get('command', []),
            entrypoint=config_data.get('entrypoint', []),
            environment=config_data.get('environment', {}),
            working_dir=config_data.get('working_dir', '/'),
            user=config_data.get('user', 'root'),
            hostname=config_data.get('hostname', ''),
            network_mode=NetworkMode(config_data.get('network_mode', 'bridge')),
            port_mappings=config_data.get('port_mappings', {}),
            volumes=config_data.get('volumes', {}),
            restart_policy=RestartPolicy(config_data.get('restart_policy', 'no')),
            restart_max_retries=config_data.get('restart_max_retries', 3),
            labels=config_data.get('labels', {}),
            annotations=config_data.get('annotations', {})
        )

        container = Container(
            container_id=data.get('container_id', ''),
            name=data.get('name', ''),
            config=config,
            state=ContainerState(data.get('state', 'created')),
            status=ContainerStatus(data.get('status', 'unknown')),
            pid=data.get('pid'),
            exit_code=data.get('exit_code'),
            restart_count=data.get('restart_count', 0),
            ip_address=data.get('ip_address'),
            network_namespace=data.get('network_namespace'),
            cgroup_path=data.get('cgroup_path'),
            root_fs_path=data.get('root_fs_path'),
            log_path=data.get('log_path'),
            metadata=data.get('metadata', {})
        )

        # Parse timestamps
        if data.get('started_at'):
            container.started_at = datetime.fromisoformat(data['started_at'])
        if data.get('finished_at'):
            container.finished_at = datetime.fromisoformat(data['finished_at'])

        return container

    # Public API

    def list_containers(self, all: bool = False) -> List[Container]:
        """List containers"""
        if all:
            return list(self.containers.values())
        else:
            return [c for c in self.containers.values() if c.state != ContainerState.EXITED]

    def get_container(self, container_id: str) -> Optional[Container]:
        """Get container by ID"""
        return self.containers.get(container_id)

    def get_container_stats(self, container_id: str) -> List[ContainerStats]:
        """Get container statistics"""
        return self.container_stats.get(container_id, [])

    def get_container_logs(self, container_id: str, tail: int = 100) -> List[str]:
        """Get container logs"""
        container = self.containers.get(container_id)
        if not container or not container.log_path:
            return []

        try:
            with open(container.log_path, 'r') as f:
                lines = f.readlines()
                return lines[-tail:] if tail > 0 else lines
        except Exception as e:
            self.logger.error(f"Failed to read logs for container {container_id}: {e}")
            return []

    def get_runtime_info(self) -> Dict[str, Any]:
        """Get runtime information"""
        running_containers = len([c for c in self.containers.values() if c.state == ContainerState.RUNNING])
        total_containers = len(self.containers)

        return {
            'runtime_version': '1.0.0',
            'runtime_root': str(self.runtime_root),
            'image_root': str(self.image_root),
            'total_containers': total_containers,
            'running_containers': running_containers,
            'total_images': len(self.images),
            'cgroup_support': self.cgroup_root.exists(),
            'network_support': self.network_manager is not None,
            'stats_retention_hours': self.stats_retention_hours
        }


class ContainerNetworkManager:
    """Container networking management"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.NetworkManager")
        self.network_namespaces: Dict[str, str] = {}

    async def create_network_namespace(self, container: Container) -> Optional[str]:
        """Create network namespace for container"""
        if not HAS_PYROUTE2:
            return None

        try:
            # Create unique namespace name
            namespace_name = f"container-{container.container_id[:12]}"

            # In a full implementation, this would create actual network namespace
            self.network_namespaces[container.container_id] = namespace_name

            self.logger.debug(f"Created network namespace {namespace_name} for container {container.container_id}")
            return namespace_name

        except Exception as e:
            self.logger.error(f"Failed to create network namespace for container {container.container_id}: {e}")
            return None

    async def setup_port_mappings(self, container: Container):
        """Set up port mappings for container"""
        for container_port, host_port in container.config.port_mappings.items():
            # In a full implementation, this would set up iptables rules
            self.logger.debug(f"Would map host port {host_port} to container port {container_port}")

    async def cleanup_network_namespace(self, container: Container):
        """Clean up network namespace"""
        namespace_name = self.network_namespaces.pop(container.container_id, None)
        if namespace_name:
            # In a full implementation, this would remove the network namespace
            self.logger.debug(f"Cleaned up network namespace {namespace_name}")


# Example usage
if __name__ == "__main__":
    async def test_container_runtime():
        runtime = CloudOSContainerRuntime()
        await runtime.start()

        # Create container configuration
        config = ContainerConfig(
            name="test-container",
            image="alpine:latest",
            command=["/bin/sh", "-c", "echo 'Hello CloudOS' && sleep 30"],
            environment={"TEST_VAR": "test_value"},
            resource_limits=ResourceLimits(
                cpu_cores=1.0,
                memory_bytes=128 * 1024 * 1024  # 128MB
            )
        )

        # Create and start container
        container_id = await runtime.create_container(config)
        print(f"Created container: {container_id}")

        success = await runtime.start_container(container_id)
        print(f"Started container: {success}")

        # Wait a bit
        await asyncio.sleep(5)

        # Get container info
        container = runtime.get_container(container_id)
        print(f"Container state: {container.state.value}")

        # Get logs
        logs = runtime.get_container_logs(container_id)
        print(f"Container logs: {logs}")

        # Stop container
        await runtime.stop_container(container_id)

        # Get runtime info
        info = runtime.get_runtime_info()
        print(f"Runtime info: {json.dumps(info, indent=2)}")

        await runtime.stop()

    asyncio.run(test_container_runtime())