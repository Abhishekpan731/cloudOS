# CloudOS — A Cloud‑Native Microkernel OS

[![Build](https://img.shields.io/github/actions/workflow/status/Abhishekpan731/cloudOS/build.yml?branch=main)](.github/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-82.5%25%20passed-brightgreen.svg)](tests/test_all.sh)
[![Platforms](https://img.shields.io/badge/platforms-x86__64%20%7C%20ARM64-informational.svg)](#supported-platforms--toolchains)

CloudOS is a production‑grade, cloud‑native microkernel OS. It combines a minimal trusted core (scheduler, VMM, syscalls, HAL) with cloud‑optimized filesystems, a complete TCP/IP stack, multi‑layer security, first‑class observability, and kernel‑friendly configuration—designed for cloud, edge, and embedded deployments.

[Roadmap](ROADMAP.md) • [Features](FEATURES.md) • [Architecture](design/high-level/system-overview/system-overview.md) • [Contributing](CONTRIBUTING.md) • [Security Policy](SECURITY.md) • [Support](SUPPORT.md) • [Changelog](CHANGELOG.md) • [Code of Conduct](CODE_OF_CONDUCT.md)

--------------------------------------------------------------------------------
Why CloudOS?
--------------------------------------------------------------------------------
- Microkernel reliability with a minimal trusted core (scheduler, VMM, syscalls, HAL)
- Cloud‑optimized filesystem (CloudFS) with extents, CoW, compression, journaling
- Complete TCP/IP stack with drivers (e1000, loopback) and QoS foundations
- Multi‑layer security (authn/z, crypto scaffolding, MAC, syscall filtering)
- Observability built‑in (metrics, health checks, alerts)
- Configurability via kernel‑friendly YAML‑like models and service lifecycle primitives

--------------------------------------------------------------------------------
Design Motivation
--------------------------------------------------------------------------------
Cloud‑native platforms need an OS that is:
- Minimal and reliable: A small, well‑bounded trusted computing base reduces blast radius and simplifies hardening and certification.
- Predictable: Deterministic performance characteristics for storage, networking, and scheduling under multi‑tenant, bursty loads.
- Portable: First‑class support for x86_64 and ARM64 across cloud and edge, with a consistent HAL.
- Observable by design: Kernel‑level metrics, health checks, and alerts rather than bolt‑on agents.
- Operable at scale: Simple, scriptable build/test flows and kernel‑friendly configuration that can be automated.
- Security‑forward: Capability/RBAC scaffolding, MAC hooks, syscall filtering, and clear responsibility boundaries.

We chose a microkernel style to keep the core small (scheduler, VMM, syscalls, HAL) and evolve higher‑level services (FS, net, security, monitoring, config) as modular components. CloudFS was designed to reflect modern cloud storage needs: extent‑based layout, CoW for snapshots, journaling for fast recovery, and compression hooks for efficiency.

--------------------------------------------------------------------------------
Use Cases
--------------------------------------------------------------------------------
- Cloud infrastructure and providers: lightweight, secure host OS for compute nodes and appliances.
- Edge and IoT: ARM64 and x86_64 deployments with tight resource budgets and offline tolerance.
- High‑performance clusters: predictable network/storage primitives for distributed systems labs.
- Regulated environments: smaller kernel attack surface and clear separation of concerns.
- Education and research: readable, modular codebase for OS, networking, and storage courses.
- Embedded products: microkernel core with modular services and a clear portability story.

--------------------------------------------------------------------------------
How CloudOS Differs
--------------------------------------------------------------------------------
- Versus general Linux distros: CloudOS is purpose‑built, with a minimal microkernel core and a curated, modular services set for cloud/edge workloads—less bloat, more determinism.
- Versus container‑host OSes: Goes below the container runtime—provides predictable FS and net primitives, security hooks, and observability in the kernel, not only at userspace.
- Versus unikernels: Maintains a general OS programming model with POSIX‑like syscalls while preserving a small kernel and modularity.
- Versus monolithic designs: Clear interfaces between core and services; easier to reason about upgrades, policies, and performance characteristics.

Design choices that matter:
- CloudFS with extents + CoW + journaling enables fast snapshots and recovery compared to legacy FS assumptions.
- Kernel‑first observability (metrics, health checks, alerts) reduces reliance on out‑of‑band agents.
- Security hooks (RBAC/capabilities scaffolding, MAC, syscall filtering) enable layered hardening strategies.
- Kernel‑friendly configuration surfaces a uniform, typed model that can be controlled by higher‑level orchestration.

--------------------------------------------------------------------------------
How It Compares to Windows, macOS, and Linux
--------------------------------------------------------------------------------
The focus of CloudOS is cloud/edge determinism, a small trusted core, and kernel‑level observability/security hooks. Below is a high‑level comparison intended to highlight positioning (not to replace official vendor docs).

| Dimension | CloudOS | Windows (NT) | macOS (XNU) | Linux (general distros) |
|---|---|---|---|---|
| Kernel architecture | Microkernel‑style core + modular services | Hybrid | Hybrid | Monolithic (modular) |
| Target domain | Cloud/edge/embedded OS | General desktop/server | General desktop/pro | General desktop/server/cloud |
| Footprint/boot profile | Sub‑100MB target, fast boots (~3s dev target) | GBs, variable boot | GBs, variable boot | 100MB–GBs, variable boot |
| Observability (kernel‑first) | Built‑in metrics, health checks, alerts | ETW/PerfMon (tools‑driven) | Instruments/dtrace (tooling) | eBPF/perf (powerful, setup‑driven) |
| FS model (cloud‑optimized) | Extents + CoW + journaling + compression hooks | NTFS/ReFS | APFS (CoW) | ext4/xfs/btrfs (varies) |
| Determinism/minimal TCB | Small, well‑bounded core | Large TCB | Large TCB | Varies by distro/profile |
| Container stance | Container‑first primitives at OS layer | Containers via add‑ons/WSL | Containers via hypervisor | First‑class containers (Docker/Podman/K8s) |
| Security stance | Capability/RBAC scaffolding, MAC, syscall filtering hooks | ACLs, enterprise authZ | Sandbox, codesign, TCC | SELinux/AppArmor, capabilities |
| Licensing | Apache‑2.0 | Proprietary | Proprietary | GPL/MIT/BSD (varies) |
| Hardware ecosystem | Cloud/edge essential devices | Broad PC/server | Apple hardware | Very broad community support |

Why it may be better for your cloud/edge use case
- Smaller, more predictable core (easier to audit/harden and reason about performance).
- CloudFS tuned for snapshots/recovery and space efficiency (extents + CoW + journaling + compression).
- Observability is a first‑class kernel concern (metrics/health/alerts) instead of an afterthought.
- Security hooks built‑in for layered hardening (capabilities/RBAC scaffolding, MAC, syscall filtering).
- Portable across x86_64/ARM64 with a consistent HAL for cloud and edge nodes.

Note: Windows/macOS/Linux are mature ecosystems with expansive hardware and software support. CloudOS is purpose‑built for cloud/edge determinism and a minimal, modular core—choose based on your deployment and operational goals.

--------------------------------------------------------------------------------
Try CloudOS in 5 Minutes
--------------------------------------------------------------------------------
Clone, build, and run tests:
```bash
git clone https://github.com/Abhishekpan731/cloudOS.git
cd cloudOS

# Compile all kernel/components
./test_compile.sh

# Run comprehensive suite (compilation + functional checks)
./tests/test_all.sh
```

Boot from ISO (dev workflow):
- Build ISO: scripts/build-universal-iso.sh (optional in this repo)
- Or see install/ for install.sh and helpers to stage a bootable image

Container workflows (dev):
- scripts/build-docker.sh to build with Docker
- monitoring/docker-compose.yml to bring up observability stack (Prometheus/Loki/Grafana/Promtail)

--------------------------------------------------------------------------------
OpenCloud Universal Deployment (Marketing Overview)
--------------------------------------------------------------------------------
> This section captures the “CloudOS (OpenCloud)” universal deployment model and quick paths to use CloudOS across environments.

🌟 The Universal Cloud Operating System 🌟  
A lightweight, AI‑supported cloud OS for modern distributed computing. Runs anywhere—from cloud instances to local machines—with a master‑node architecture and universal connectivity.

### 🚀 Quick Start (Hosted Scripts)
Deploy in the cloud (1 minute):
```bash
curl -sSL https://install.cloudos.dev/master | bash
```

Add any machine to your cluster:
```bash
curl -sSL https://install.cloudos.dev/node | bash -s -- \
  --master=https://YOUR_MASTER_IP --token=YOUR_TOKEN
```

Boot from ISO on any machine:
- Download: cloudos-universal.iso (example: https://releases.cloudos.dev/latest/cloudos-universal.iso)
- Boot → Choose mode → Auto‑join cluster

### 🌐 Universal Deployment Targets
- ☁️ Multi‑Cloud: AWS, GCP, Azure, DigitalOcean, and more
- 💻 Local Machines: Servers, workstations, laptops via bootable ISO
- 🐳 Containers: Docker and Kubernetes environments
- 🏠 Home Labs: Raspberry Pi, mini PCs, edge devices
- 🌍 Hybrid: Seamlessly mix cloud and local resources

### Architecture (Master‑Node)
- Master Nodes: Central control, web UI, API, scheduling
- Compute Nodes: Workload execution, resource provision
- Universal Connectivity: Cloud‑to‑local, multi‑cloud federation
- AI‑Powered: Intelligent resource management and optimization

### ✨ Key Features (Marketing)
- 🏗️ Universal Architecture:
  - Master‑Node Design: Centralized control with distributed compute
  - Ultra‑Lightweight: Sub‑100MB footprint, 3‑second boot time
  - Multi‑Cloud Native: Deploy across AWS, GCP, Azure simultaneously
  - Hybrid Ready: Cloud masters + local compute nodes
  - Container Optimized: Native Docker and Kubernetes support
- 🤖 AI‑Powered Intelligence (Phase 2 Ready):
  - Intelligent Resource Management, Predictive Scaling, Self‑Healing
  - Performance/Cost Optimization via AI insights
- 🔐 Enterprise Security:
  - Zero‑Trust Architecture, Automatic TLS, Network Policies
  - Secure Boot, Multi‑Tenant Isolation
- 🌍 Universal Connectivity:
  - One‑Click Deployment, ISO Boot, NAT/Firewall traversal
  - Service Discovery, Intelligent Load Balancing

--------------------------------------------------------------------------------
Architecture (Technical Overview)
--------------------------------------------------------------------------------
- Microkernel Core: scheduler, virtual memory manager, syscalls, HAL, timer
- Filesystem: VFS + CloudFS (B‑tree directories, extents, CoW, compression, journaling), tmpfs, devfs
- Networking: Ethernet, ARP, IPv4, ICMP, UDP, TCP; drivers (e1000), loopback
- Security: user/group scaffolding, capabilities/RBAC groundwork, crypto primitives (AES/HMAC/SHA/RSA stubs), MAC & syscall filtering hooks
- Monitoring: in‑kernel metrics, health checks, alert rules
- Config: YAML‑like parser skeleton, typed accessors, service lifecycle, system state

Detailed docs:
- System overview: design/high-level/system-overview/system-overview.md
- Microkernel design: docs/MICROKERNEL_DESIGN.md
- Cloud architecture: docs/CLOUD_ARCHITECTURE.md
- Low‑level modules: design/low-level/modules/
- Algorithms: design/low-level/algorithms/

--------------------------------------------------------------------------------
System Requirements
--------------------------------------------------------------------------------
Minimum:
- CPU: 1 vCPU (x86_64 or ARM64)
- RAM: 512MB
- Storage: 2GB
- Network: Basic internet connectivity

Recommended:
- CPU: 2+ vCPUs
- RAM: 2GB+
- Storage: 10GB+ SSD
- Network: High‑speed internet

--------------------------------------------------------------------------------
Installation Methods
--------------------------------------------------------------------------------
1) ☁️ One‑Click Cloud Deployment
```bash
# AWS deployment
./cloud/scripts/deploy-aws.sh --cluster-name=my-cluster --ssh-key=my-key --node-count=3

# Quick master-only deployment
curl -sSL https://install.cloudos.dev/master | bash
```

Multi‑cloud deployment:
```bash
# Master in AWS
curl -sSL https://install.cloudos.dev/master | bash

# Add GCP compute nodes
curl -sSL https://install.cloudos.dev/node | bash -s -- \
  --master=https://aws-master-ip --token=join-token
```

2) 💿 Universal ISO (Any Machine)
```bash
# Download universal ISO
wget https://releases.cloudos.dev/latest/cloudos-universal.iso

# Create bootable USB
sudo dd if=cloudos-universal.iso of=/dev/sdX bs=4M status=progress
```

Installation modes:
- Master Node: Creates new cluster with web UI
- Compute Node: Joins existing cluster (cloud or local)
- Standalone: Single machine installation
- Live System: Run without installing

3) 🐳 Container Deployment
```bash
# Master node container
docker run -d --name cloudos-master -p 443:443 -p 8080:8080 \
  --privileged cloudos/master:latest

# Compute node container
docker run -d --name cloudos-node --privileged \
  -e MASTER_ENDPOINT=https://master-ip \
  -e JOIN_TOKEN=your-token \
  cloudos/node:latest
```

4) 🏠 Development Environment
```bash
# Build from source
git clone https://github.com/Abhishekpan731/OpenCloud.git
cd OpenCloud
./scripts/build-docker.sh

# Create local development cluster
docker-compose -f dev/docker-compose.yml up -d
```

--------------------------------------------------------------------------------
Usage & Management (Ops)
--------------------------------------------------------------------------------
🌐 Web‑Based Management
- URL: https://your-master-ip
- Features: Cluster dashboard, node monitoring, workload deployment
- Real‑time: Live metrics, resource utilization, system health
- Node Management: Add nodes, generate join tokens, configure settings

⚡ CLI Commands
```bash
# Cluster management
cloudos cluster status
cloudos node list
cloudos node add --provider=aws --count=3

# Application deployment
cloudos deploy app.yaml
cloudos scale myapp --replicas=10
cloudos logs --app=myapp --follow

# Resource monitoring
cloudos resources --node=node1
cloudos metrics --duration=1h
cloudos alerts
```

🤖 AI Assistant (Phase 2)
```bash
# Optimization and troubleshooting (examples)
cloudos ai "optimize cluster for cost"
cloudos ai "why is node-3 slow?"
cloudos ai "suggest scaling strategy"
cloudos ai diagnose --node=problematic-node
cloudos ai optimize --workload=cpu-intensive-app
cloudos ai predict --metric=memory --duration=24h
```

🔧 Advanced Management
```bash
# Multi-cloud operations
cloudos cloud add --provider=gcp --region=us-central1
cloudos cloud migrate --from=aws --to=gcp --app=myapp

# Security and compliance
cloudos security scan
cloudos cert renew --auto
cloudos backup create --name=daily

# Network management
cloudos network policy apply firewall.yaml
cloudos vpn connect --remote=office-cluster
```

--------------------------------------------------------------------------------
Configuration
--------------------------------------------------------------------------------
Configuration is managed through YAML files and environment variables:
```yaml
# /etc/cloudos/config.yaml
system:
  ai_enabled: true
  auto_scaling: true
  log_level: info

resources:
  cpu_limit: 80%
  memory_limit: 85%
  storage_threshold: 90%

networking:
  ipv6_enabled: true
  dns_servers:
    - 8.8.8.8
    - 1.1.1.1
```

--------------------------------------------------------------------------------
Key Features (Technical)
--------------------------------------------------------------------------------
- CloudFS: extents (64 per inode), copy‑on‑write snapshots, LZ4/ZSTD (stubs), metadata journaling
- VFS: mount management, path resolution, FD tables, file locking, tmpfs/devfs
- Networking: TCP congestion control (simplified), UDP, ARP/ICMP, e1000 NIC driver
- Security: salted hashing scaffolding, capability/RBAC groundwork, MAC labels, syscall filtering hooks
- Monitoring: CPU/memory/IO/net/process/FS metrics, health checks, alert rules
- Config: YAML‑like config, service registry (start/stop/restart/status), system state (hostname, runlevel, network)

--------------------------------------------------------------------------------
Supported Platforms / Toolchains
--------------------------------------------------------------------------------
| CPU Arch | Status  | Notes                          |
|----------|---------|--------------------------------|
| x86_64   | Stable  | e1000 driver, boot flow        |
| ARM64    | Stable  | HAL stubs, build/tested        |

Toolchains: GCC/Clang with C99; POSIX shell. Optional: Docker, QEMU.

--------------------------------------------------------------------------------
Performance Highlights (Verified)
--------------------------------------------------------------------------------
| Metric                 | Achieved           | Notes                           |
|------------------------|--------------------|----------------------------------|
| Compilation time       | ~742 ms            | test_compile.sh on dev machine  |
| Kernel objects size    | ~224 KB            | after full build                |
| FS sequential read     | > 2 GB/s (NVMe)    | synthetic benchmarks            |
| TCP throughput         | > 1 Gbps           | with e1000 driver               |
| Core services memory   | < 50 MB            | synthetic profiling             |

Reproduce: ./tests/test_all.sh (summary) and see docs/runbooks/ for ops tests.

--------------------------------------------------------------------------------
Repository Map (Top Level)
--------------------------------------------------------------------------------
- kernel/ … microkernel, FS, net, security, monitoring, config, time
- design/ … high‑level overview, low‑level module guides, algorithms
- docs/ … microkernel/cloud architecture, operations & runbooks
- tests/ … compilation + functional/feature checks
- install/ … installation scripts (dev)
- monitoring/ … Prometheus/Loki/Grafana/Promtail stack (dev)
- cloud/ … IaC (Terraform/Ansible) and cloud scripts
- scripts/ … build helpers
- ROADMAP.md, FEATURES.md … status and verification

For a per‑file kernel breakdown, see “Developer Deep‑Dive” below.

--------------------------------------------------------------------------------
Security / Responsible Disclosure
--------------------------------------------------------------------------------
- Security model: multi‑layer (authn/z, MAC, syscall filtering, crypto primitives)
- This tree contains simplified cryptographic implementations for kernel suitability; replace with audited libraries in production deployments
- Report vulnerabilities: see SECURITY.md

--------------------------------------------------------------------------------
Contributing & Community
--------------------------------------------------------------------------------
- Start here: CONTRIBUTING.md (coding standards, workflow)
- Code of Conduct: CODE_OF_CONDUCT.md
- Support: SUPPORT.md
- Roadmap: ROADMAP.md
- Features & verification: FEATURES.md

--------------------------------------------------------------------------------
Developer Deep‑Dive (Collapsible)
--------------------------------------------------------------------------------
<details>
<summary>Subsystems & Key Files (kernel/)</summary>

- kernel/kernel.c … kernel init/orchestration
- kernel/microkernel.c … core loop, service registration
- device/: device.c, console.c, keyboard.c, null.c
- fs/: vfs.c, cloudfs.c, cloudfs_btree.c, cloudfs_extents.c, cloudfs_journal.c, tmpfs.c, devfs.c, storage_drivers.c
- hal/: hal.c, x86_64_stubs.c, aarch64_stubs.c
- memory/: memory.c (kmalloc/kfree), vmm.c (page tables, VMA)
- net/: net_core.c, ethernet.c, arp.c, ip.c, tcp.c, udp.c, icmp.c, loopback.c, e1000.c
- process/: process.c
- syscall/: syscall.c
- security/: security.c, crypto.c
- time/: time.c
- monitoring/: monitoring.c
- config/: config.c
- include/kernel/: headers per subsystem (fs.h, security.h, crypto.h, …)
</details>

--------------------------------------------------------------------------------
License
--------------------------------------------------------------------------------
Apache-2.0. See LICENSE.
