# CloudOS Quick Start Guide

CloudOS is designed to be deployed anywhere - from cloud instances to local machines. This guide shows you how to get started in under 5 minutes.

## 🚀 One-Click Cloud Deployment

### Deploy Master in AWS
```bash
# Deploy complete cluster with 1 master + 3 compute nodes
curl -sSL https://raw.githubusercontent.com/your-org/cloudos/main/cloud/scripts/deploy-aws.sh | bash -s -- \
  --cluster-name=my-cluster \
  --ssh-key=my-keypair \
  --region=us-west-2 \
  --node-count=3
```

### Deploy Master in Any Cloud
```bash
# Install master on any Linux machine
curl -sSL https://install.cloudos.dev/master | bash
```

### Add Compute Nodes
```bash
# Join existing cluster from any machine
curl -sSL https://install.cloudos.dev/node | bash -s -- \
  --master=https://YOUR_MASTER_IP \
  --token=YOUR_JOIN_TOKEN
```

## 💿 ISO Installation (Local Machines)

### Download and Boot
1. **Download ISO**: [cloudos-universal.iso](https://releases.cloudos.dev/latest/cloudos-universal.iso)
2. **Create Bootable USB**:
   ```bash
   # Linux/macOS
   sudo dd if=cloudos-universal.iso of=/dev/sdX bs=4M status=progress

   # Windows (use Rufus or similar tool)
   ```
3. **Boot from USB** and choose installation mode:
   - **Master Node**: Creates new cluster
   - **Compute Node**: Joins existing cluster
   - **Standalone**: Single machine installation
   - **Live System**: Run without installing

### Installation Options

**Master Node Installation (Recommended for first machine):**
- Creates new CloudOS cluster
- Provides web UI for management
- Can accept additional compute nodes
- Suitable for main server or development machine

**Compute Node Installation:**
- Joins existing cluster
- Requires master endpoint and join token
- Automatically registers and receives workloads
- Suitable for additional capacity

## 🔗 Universal Connectivity

### Local to Cloud Integration
You can seamlessly mix local and cloud machines:

1. **Deploy Master in Cloud**:
   ```bash
   # AWS Master
   curl -sSL https://install.cloudos.dev/master | bash
   # Note the master IP: https://1.2.3.4
   ```

2. **Connect Local Machine via ISO**:
   - Boot local machine with CloudOS ISO
   - Choose "Join Existing Cluster"
   - Enter master endpoint: `https://1.2.3.4`
   - Enter join token (get from master web UI)
   - Local machine joins cloud cluster automatically

### Docker Container Nodes
```bash
# Run CloudOS node in Docker
docker run -d --name cloudos-node --privileged \
  -e MASTER_ENDPOINT=https://YOUR_MASTER_IP \
  -e JOIN_TOKEN=YOUR_TOKEN \
  cloudos/node:latest
```

## 🌐 Multi-Cloud Deployment

### Hybrid AWS + GCP
```bash
# Master in AWS
./cloud/scripts/deploy-aws.sh --cluster-name=hybrid-cluster --ssh-key=my-key

# Compute nodes in GCP
./cloud/scripts/deploy-gcp.sh --master=https://aws-master-ip --join-cluster
```

### Edge Computing
```bash
# Master in central cloud
curl -sSL https://install.cloudos.dev/master | bash

# Edge nodes (Raspberry Pi, etc.)
curl -sSL https://install.cloudos.dev/node | bash -s -- \
  --master=https://central-master \
  --token=edge-token
```

## 📊 Management & Monitoring

### Web Interface
- **URL**: `https://your-master-ip`
- **Features**:
  - Cluster overview and node status
  - Resource utilization monitoring
  - Workload deployment and scaling
  - Node management and configuration
  - AI-powered optimization insights

### CLI Management
```bash
# Check cluster status
cloudos cluster status

# List all nodes
cloudos node list

# Deploy application
cloudos deploy app.yaml

# Scale workload
cloudos scale myapp --replicas=5

# View logs
cloudos logs --node=node1 --follow
```

### API Access
```bash
# Cluster status
curl -k https://master-ip/api/v1/status

# Node information
curl -k https://master-ip/api/v1/nodes

# Register new node
curl -k -X POST https://master-ip/api/v1/nodes/register \
  -H "Content-Type: application/json" \
  -d '{"node_type": "compute"}'
```

## 🔐 Security Features

### Automatic Security
- **TLS encryption** for all communication
- **Automatic certificate generation** for HTTPS
- **Node authentication** via join tokens
- **Network policies** for service isolation
- **Regular security updates** via auto-update

### Manual Security Configuration
```bash
# Custom SSL certificates
cloudos cert install --cert=custom.crt --key=custom.key

# Network policies
cloudos network policy apply firewall-rules.yaml

# User management
cloudos user add admin --role=cluster-admin
cloudos user add developer --role=developer
```

## 📈 Scaling Examples

### Start Small, Scale Large
```bash
# Day 1: Single machine
curl -sSL https://install.cloudos.dev/master | bash

# Week 2: Add cloud capacity
curl -sSL https://install.cloudos.dev/node | bash -s -- \
  --master=https://local-master \
  --token=scale-token

# Month 3: Multi-cloud expansion
./cloud/scripts/deploy-aws.sh --join-cluster=https://local-master
./cloud/scripts/deploy-gcp.sh --join-cluster=https://local-master
```

### Auto-Scaling
```yaml
# cloudos-autoscale.yaml
apiVersion: cloudos.dev/v1
kind: AutoScaler
metadata:
  name: web-app-scaler
spec:
  target: web-app
  minReplicas: 2
  maxReplicas: 50
  metrics:
    - type: CPU
      targetUtilization: 70%
    - type: Memory
      targetUtilization: 80%
  cloudProviders:
    - aws
    - gcp
    - azure
```

```bash
cloudos apply -f cloudos-autoscale.yaml
```

## 🤖 AI-Powered Features

### Intelligent Workload Placement
- **Automatic optimization** of resource allocation
- **Predictive scaling** based on usage patterns
- **Cost optimization** across cloud providers
- **Performance tuning** recommendations

### AI Assistant
```bash
# Ask AI for optimization suggestions
cloudos ai "optimize my cluster for cost"
cloudos ai "why is node-3 running slowly?"
cloudos ai "suggest scaling strategy for peak traffic"

# AI-powered troubleshooting
cloudos ai diagnose --node=problematic-node
cloudos ai optimize --workload=high-cpu-app
```

## 🛠️ Development & Testing

### Local Development Cluster
```bash
# Quick development setup
docker-compose -f dev/docker-compose.yml up -d
# Creates master + 2 nodes locally for testing
```

### CI/CD Integration
```yaml
# .github/workflows/cloudos-deploy.yml
name: Deploy to CloudOS
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy to CloudOS
        run: |
          curl -sSL https://install.cloudos.dev/cli | bash
          cloudos deploy --cluster=${{ secrets.CLOUDOS_CLUSTER }} \
                         --token=${{ secrets.CLOUDOS_TOKEN }} \
                         deployment.yaml
```

## 📚 Next Steps

1. **Try the Quick Start**: Deploy your first cluster in under 5 minutes
2. **Explore the Web UI**: Manage your cluster through the intuitive interface
3. **Deploy Applications**: Use the built-in container orchestration
4. **Scale Globally**: Add nodes from different cloud providers
5. **Enable AI Features**: Let CloudOS optimize your infrastructure automatically

## 💡 Use Cases

### Development Teams
- **Local development** with cloud deployment
- **Testing environments** that match production
- **CI/CD pipelines** with automatic scaling

### Startups
- **Start local**, expand to cloud as you grow
- **Cost optimization** with multi-cloud flexibility
- **Easy scaling** without vendor lock-in

### Enterprises
- **Hybrid cloud** integration
- **Edge computing** for distributed applications
- **AI-powered operations** for large-scale infrastructure

### Home Labs
- **Self-hosted services** with professional-grade orchestration
- **Learning platform** for cloud-native technologies
- **IoT integration** for smart home applications

## 🆘 Getting Help

- **Documentation**: https://docs.cloudos.dev
- **Community Forum**: https://community.cloudos.dev
- **GitHub Issues**: https://github.com/your-org/cloudos/issues
- **Discord**: https://discord.gg/cloudos

**Ready to get started?** Choose your deployment method above and have CloudOS running in minutes!