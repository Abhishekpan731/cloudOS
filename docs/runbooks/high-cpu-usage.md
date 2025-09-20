# High CPU Usage Runbook

## Overview
This runbook provides procedures for diagnosing and resolving high CPU usage issues in CloudOS systems. High CPU usage can impact system performance, user experience, and lead to system instability.

## Symptoms
- CPU usage consistently above 90% for more than 5 minutes
- System responsiveness degraded
- Applications timing out or responding slowly
- High load average (> number of CPU cores)
- Prometheus alert: `HighCPUUsage` or `CriticalCPUUsage`

## Immediate Response (< 5 minutes)

### 1. Confirm the Issue
```bash
# Check current CPU usage
top -bn1 | head -20

# Check load average
uptime

# Check CloudOS metrics
curl -s http://localhost:9200/metrics | grep cpu_usage_percent
```

### 2. Identify Top Consumers
```bash
# Find processes using most CPU
ps aux --sort=-%cpu | head -10

# Check container CPU usage
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.Name}}"

# Check for specific CloudOS processes
ps aux | grep -E "(cloudos|ai-engine|container)" | sort -k3 -nr
```

### 3. Quick Mitigation
```bash
# If a runaway process is identified
sudo kill -TERM <PID>

# For containers using excessive CPU
docker restart <container_id>

# Check if CloudOS AI engine can be temporarily throttled
# (if AI workloads are causing high CPU)
curl -X POST http://localhost:8000/api/v1/throttle -d '{"rate_limit": 0.5}'
```

## Detailed Diagnosis (< 15 minutes)

### 1. System Analysis
```bash
# Detailed CPU information
lscpu
cat /proc/cpuinfo | grep "model name" | head -1

# CPU usage by core
mpstat -P ALL 1 5

# Check CPU frequency and throttling
cat /proc/cpuinfo | grep MHz
dmesg | grep -i "thermal\|throttl"
```

### 2. Process Analysis
```bash
# Detailed process tree with CPU usage
ps auxf --sort=-%cpu

# Check for zombie processes
ps aux | awk '$8 ~ /^Z/ { print $2, $11 }'

# Monitor CPU usage in real-time
htop -s PERCENT_CPU

# Check for CPU-intensive CloudOS components
systemctl status cloudos-*
```

### 3. Container Analysis
```bash
# Get detailed container stats
docker stats --format "table {{.Container}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}"

# Check cgroup CPU limits
for container in $(docker ps --format "{{.Names}}"); do
    echo "=== $container ==="
    docker exec $container cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null || echo "N/A"
    docker exec $container cat /sys/fs/cgroup/cpu/cpu.cfs_period_us 2>/dev/null || echo "N/A"
done

# Check CloudOS container logs for errors
docker logs cloudos-ai-engine --tail 50
docker logs cloudos-exporter --tail 50
```

### 4. Kernel and System Analysis
```bash
# Check for kernel issues
dmesg | tail -50

# Look for high interrupt usage
cat /proc/interrupts

# Check for high context switches
vmstat 1 5

# Check I/O wait
iostat -x 1 5
```

## Resolution Procedures

### For General High CPU Usage

#### 1. Process Optimization
```bash
# If a specific process is consuming high CPU
# Check if it's legitimate workload or runaway process

# For legitimate high CPU usage, consider:
# - Scaling resources
# - Load balancing
# - Process prioritization

# Renice high CPU processes
sudo renice 10 <PID>

# Set CPU affinity to limit process to specific cores
taskset -c 0,1 <PID>
```

#### 2. Container Resource Management
```bash
# Limit CPU usage for problematic containers
docker update --cpus="1.0" <container_name>
docker update --cpu-shares=512 <container_name>

# For CloudOS containers specifically
docker-compose -f /path/to/cloudos/docker-compose.yml up -d --scale ai-engine=2
```

#### 3. System Tuning
```bash
# Adjust system CPU scheduling
echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Check and adjust CPU frequency scaling
sudo cpufreq-set -g performance

# Optimize kernel parameters
echo 1000 | sudo tee /proc/sys/kernel/sched_latency_ns
echo 100 | sudo tee /proc/sys/kernel/sched_min_granularity_ns
```

### For CloudOS-Specific Issues

#### 1. AI Engine High CPU
```bash
# Check AI model status
curl http://localhost:8000/api/v1/models/status

# Reduce inference concurrency
curl -X POST http://localhost:8000/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{"max_concurrent_requests": 2}'

# Check for memory swapping affecting AI workloads
free -h
swapon -s

# Restart AI engine with resource limits
docker restart cloudos-ai-engine
```

#### 2. Container Runtime Issues
```bash
# Check Docker daemon CPU usage
systemctl status docker
docker system df
docker system prune -f

# Check for container build issues
docker images --filter "dangling=true"
docker image prune -f

# Check CloudOS container runtime
docker ps | grep cloudos
docker logs cloudos-container-runtime --tail 50
```

#### 3. Monitoring System High CPU
```bash
# Check Prometheus CPU usage
docker logs cloudos-prometheus --tail 50

# Reduce scrape frequency temporarily
# Edit prometheus.yml and restart
sed -i 's/scrape_interval: 15s/scrape_interval: 30s/' /path/to/prometheus.yml
docker restart cloudos-prometheus

# Check for high cardinality metrics
curl -s http://localhost:9090/api/v1/label/__name__/values | jq '.data | length'
```

## Long-term Solutions

### 1. Resource Scaling
```bash
# Scale CloudOS cluster horizontally
./scripts/add-node.sh --master=MASTER_IP --token=TOKEN

# Scale containers vertically
docker-compose up -d --scale worker=3

# Add dedicated AI compute nodes
kubectl label nodes <node-name> workload=ai-compute
```

### 2. Performance Optimization
```bash
# Enable CPU performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Optimize CloudOS configuration
# Edit /etc/cloudos/config.yml
kernel:
  scheduler: performance
  cpu_affinity: enabled

# Tune container runtime
# Edit /etc/docker/daemon.json
{
  "default-runtime": "runc",
  "cpu-rt-runtime": 950000,
  "cpu-rt-period": 1000000
}
```

### 3. Monitoring Improvements
```bash
# Add detailed CPU monitoring
# Update Prometheus configuration to collect per-core metrics
- job_name: 'node-detailed'
  static_configs:
    - targets: ['node-exporter:9100']
  params:
    collect[]:
      - cpu_detailed

# Set up predictive alerts
# Add to alerting rules:
- alert: CPUUsageTrend
  expr: predict_linear(cloudos_system_cpu_usage_percent[1h], 3600) > 85
  for: 10m
```

## Prevention

### 1. Proactive Monitoring
- Set up gradual alerting (Warning at 80%, Critical at 90%)
- Monitor CPU usage trends over time
- Implement capacity planning based on historical data

### 2. Resource Management
- Implement CPU quotas for all containers
- Use CloudOS resource policies
- Regular performance baseline reviews

### 3. Automated Response
```bash
# Create auto-scaling policies
# Add to CloudOS configuration
autoscaling:
  cpu:
    scale_up_threshold: 80
    scale_down_threshold: 30
    cooldown_period: 300s
```

## Verification

After implementing fixes:

```bash
# Verify CPU usage has normalized
top -bn1 | head -5

# Check CloudOS metrics
curl -s http://localhost:9200/metrics | grep -E "cpu_usage|load_average"

# Verify container performance
docker stats --no-stream

# Check alert status
curl -s http://localhost:9093/api/v1/alerts | jq '.data[] | select(.labels.alertname=="HighCPUUsage")'
```

## Post-Incident

1. **Document the Root Cause**: Update incident log with findings
2. **Review Monitoring**: Ensure alerts fired appropriately
3. **Update Runbook**: Add any new procedures discovered
4. **Capacity Planning**: Review if scaling is needed

## Related Runbooks
- [Memory Issues](memory-issues.md)
- [Performance Tuning](performance-tuning.md)
- [Container Performance](container-performance.md)
- [AI Performance Optimization](ai-performance-optimization.md)

## Escalation

If CPU usage cannot be resolved within 30 minutes:
1. Contact senior engineering team
2. Consider emergency scaling of infrastructure
3. Implement temporary traffic throttling
4. Escalate to engineering management for resource approval