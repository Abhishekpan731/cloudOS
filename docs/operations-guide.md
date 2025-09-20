# CloudOS Operations Guide

This comprehensive guide covers day-to-day operations, maintenance procedures, and best practices for managing CloudOS in production environments.

## 📋 Table of Contents

1. [Daily Operations](#daily-operations)
2. [System Monitoring](#system-monitoring)
3. [Maintenance Procedures](#maintenance-procedures)
4. [Backup and Recovery](#backup-and-recovery)
5. [Performance Optimization](#performance-optimization)
6. [Security Operations](#security-operations)
7. [Troubleshooting](#troubleshooting)
8. [Emergency Procedures](#emergency-procedures)

## 🌅 Daily Operations

### Morning Health Check (10 minutes)

```bash
#!/bin/bash
# Daily CloudOS health check script

echo "🌅 CloudOS Daily Health Check - $(date)"
echo "========================================"

# 1. System Status
echo "📊 System Status:"
uptime
df -h | grep -E "(/$|/opt|/var)"

# 2. CloudOS Services
echo -e "\n🔧 CloudOS Services:"
systemctl status cloudos-* --no-pager -l

# 3. Container Health
echo -e "\n🐳 Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# 4. Cluster Status
echo -e "\n🖥️ Cluster Status:"
kubectl get nodes
kubectl get pods --all-namespaces | grep -E "(Error|CrashLoop|Pending)"

# 5. Monitoring Status
echo -e "\n📈 Monitoring Systems:"
curl -s http://localhost:9090/-/healthy && echo "✅ Prometheus: Healthy" || echo "❌ Prometheus: Down"
curl -s http://localhost:3000/api/health | jq -r '.database' && echo "✅ Grafana: Healthy" || echo "❌ Grafana: Down"
curl -s http://localhost:9093/-/healthy && echo "✅ AlertManager: Healthy" || echo "❌ AlertManager: Down"

# 6. Active Alerts
echo -e "\n🚨 Active Alerts:"
curl -s http://localhost:9093/api/v1/alerts | jq -r '.data[] | select(.status.state=="firing") | "- \(.labels.alertname): \(.annotations.summary)"' || echo "No active alerts"

# 7. Resource Usage
echo -e "\n💻 Resource Usage:"
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)% used"
echo "Memory: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
echo "Disk: $(df / | grep / | awk '{print $5}')"

# 8. AI Engine Status
echo -e "\n🤖 AI Engine Status:"
curl -s http://localhost:8000/health | jq -r '.status' || echo "AI Engine not responding"
curl -s http://localhost:8000/api/v1/models | jq -r '.loaded_models | length' | xargs echo "Loaded models:"

echo -e "\n✅ Health check complete!"
```

### Key Metrics to Monitor Daily

| Metric | Healthy Range | Action Required |
|--------|---------------|-----------------|
| **CPU Usage** | < 80% | Investigate if > 80% |
| **Memory Usage** | < 85% | Investigate if > 85% |
| **Disk Usage** | < 80% | Cleanup if > 80% |
| **Active Alerts** | 0-2 warnings | Investigate if > 2 or any critical |
| **Container Restarts** | < 5 per day | Investigate if > 5 |
| **AI Inference Error Rate** | < 5% | Investigate if > 5% |

## 📊 System Monitoring

### Grafana Dashboard Review

Daily dashboard review checklist:

1. **System Overview Dashboard**
   - Check CPU, memory, disk trends
   - Verify no unusual spikes or patterns
   - Review network I/O patterns

2. **Container Metrics Dashboard**
   - Verify all containers running
   - Check resource utilization
   - Review restart patterns

3. **AI Engine Dashboard**
   - Monitor inference rates and latency
   - Check model loading status
   - Review error rates and patterns

4. **Security Dashboard**
   - Review authentication patterns
   - Check for security events
   - Monitor access patterns

### Alert Management

```bash
# Check current alerts
curl -s http://localhost:9093/api/v1/alerts | jq '.data[] | select(.status.state=="firing")'

# Silence non-critical alerts during maintenance
curl -X POST http://localhost:9093/api/v1/silences \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [{"name": "alertname", "value": "HighCPUUsage"}],
    "startsAt": "'$(date -Iseconds)'",
    "endsAt": "'$(date -d '+2 hours' -Iseconds)'",
    "createdBy": "ops-team",
    "comment": "Maintenance window - expected high CPU"
  }'

# Clear resolved alerts
curl -X DELETE http://localhost:9093/api/v1/alerts
```

## 🔧 Maintenance Procedures

### Weekly Maintenance (30 minutes)

```bash
#!/bin/bash
# Weekly CloudOS maintenance script

echo "🔧 CloudOS Weekly Maintenance - $(date)"
echo "======================================"

# 1. System Updates
echo "📦 Checking for system updates..."
apt list --upgradable 2>/dev/null | grep -v "WARNING" | wc -l | xargs echo "Available updates:"

# 2. Log Rotation and Cleanup
echo -e "\n🗑️ Cleaning up logs..."
sudo logrotate -f /etc/logrotate.conf
docker system prune -f
journalctl --vacuum-time=7d

# 3. Container Image Updates
echo -e "\n🐳 Checking for container updates..."
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}" | grep cloudos

# 4. Backup Verification
echo -e "\n💾 Verifying backups..."
ls -la /backup/cloudos/ | tail -5

# 5. Certificate Expiry Check
echo -e "\n🔒 Checking certificate expiry..."
openssl x509 -in /etc/ssl/certs/cloudos.crt -text -noout | grep "Not After" || echo "No SSL certificate found"

# 6. Database Cleanup (if applicable)
echo -e "\n🗄️ Database maintenance..."
# Add database-specific maintenance commands

# 7. Performance Metrics Review
echo -e "\n📈 Performance trends (last 7 days):"
# Add performance analysis commands

echo -e "\n✅ Weekly maintenance complete!"
```

### Monthly Maintenance (1 hour)

- **Security Updates**: Apply all security patches
- **Capacity Planning**: Review resource usage trends
- **Backup Testing**: Test backup restoration procedures
- **Documentation Update**: Update runbooks and procedures
- **Performance Tuning**: Optimize system performance
- **Security Audit**: Review security configurations

### Quarterly Maintenance (2 hours)

- **Version Updates**: Upgrade CloudOS to latest stable version
- **Hardware Review**: Check hardware health and performance
- **Disaster Recovery Test**: Full DR procedure testing
- **Security Assessment**: Comprehensive security review
- **Process Improvement**: Review and update operational procedures

## 💾 Backup and Recovery

### Backup Strategy

#### Daily Backups
```bash
#!/bin/bash
# Daily backup script

BACKUP_DIR="/backup/cloudos/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# 1. Configuration backup
echo "📁 Backing up configuration..."
tar -czf "$BACKUP_DIR/config-$(date +%H%M).tar.gz" /etc/cloudos/ /opt/cloudos/config/

# 2. Database backup (if applicable)
echo "🗄️ Backing up databases..."
# Add database backup commands

# 3. Container volumes backup
echo "📦 Backing up container volumes..."
docker run --rm -v prometheus_data:/data -v "$BACKUP_DIR":/backup alpine tar czf /backup/prometheus-data-$(date +%H%M).tar.gz -C /data .

# 4. System state backup
echo "⚙️ Backing up system state..."
systemctl list-units --state=enabled > "$BACKUP_DIR/enabled-services.txt"
crontab -l > "$BACKUP_DIR/crontab.txt"

# 5. Cleanup old backups (keep 30 days)
find /backup/cloudos/ -type d -mtime +30 -exec rm -rf {} \;

echo "✅ Backup complete: $BACKUP_DIR"
```

#### Recovery Procedures
```bash
#!/bin/bash
# Disaster recovery script

RESTORE_DATE="$1"
BACKUP_DIR="/backup/cloudos/$RESTORE_DATE"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "❌ Backup directory not found: $BACKUP_DIR"
    exit 1
fi

echo "🚨 Starting CloudOS disaster recovery..."
echo "Restoring from: $BACKUP_DIR"

# 1. Stop all services
echo "⏹️ Stopping CloudOS services..."
systemctl stop cloudos-*
docker-compose down

# 2. Restore configuration
echo "📁 Restoring configuration..."
tar -xzf "$BACKUP_DIR"/config-*.tar.gz -C /

# 3. Restore data volumes
echo "📦 Restoring data volumes..."
docker volume create prometheus_data
docker run --rm -v prometheus_data:/data -v "$BACKUP_DIR":/backup alpine tar xzf /backup/prometheus-data-*.tar.gz -C /data

# 4. Start services
echo "▶️ Starting CloudOS services..."
systemctl start cloudos-*
docker-compose up -d

# 5. Verify recovery
echo "✅ Verifying recovery..."
sleep 30
curl -f http://localhost:9090/-/healthy || echo "❌ Prometheus not healthy"
curl -f http://localhost:3000/api/health || echo "❌ Grafana not healthy"

echo "✅ Disaster recovery complete!"
```

## ⚡ Performance Optimization

### System Performance Tuning

```bash
#!/bin/bash
# Performance optimization script

echo "⚡ CloudOS Performance Optimization"
echo "=================================="

# 1. CPU Performance
echo "🖥️ CPU Optimization..."
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost

# 2. Memory Optimization
echo -e "\n💾 Memory Optimization..."
echo 1 | sudo tee /proc/sys/vm/swappiness
echo 10 | sudo tee /proc/sys/vm/vfs_cache_pressure
echo 50 | sudo tee /proc/sys/vm/dirty_ratio

# 3. Network Optimization
echo -e "\n🌐 Network Optimization..."
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 16777216' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 4. Disk I/O Optimization
echo -e "\n💿 Disk Optimization..."
echo deadline | sudo tee /sys/block/*/queue/scheduler
echo 4096 | sudo tee /sys/block/*/queue/read_ahead_kb

# 5. Container Optimization
echo -e "\n🐳 Container Optimization..."
# Optimize Docker daemon
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "default-ulimits": {
    "nofile": {
      "name": "nofile",
      "hard": 64000,
      "soft": 64000
    }
  }
}
EOF

sudo systemctl restart docker

echo "✅ Performance optimization complete!"
```

### Application Performance Tuning

```bash
# AI Engine Performance Tuning
curl -X POST http://localhost:8000/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{
    "inference": {
      "batch_size": 8,
      "max_workers": 4,
      "cache_size": "1GB"
    },
    "memory": {
      "model_cache_size": "2GB",
      "optimization_level": "high"
    }
  }'

# Prometheus Performance Tuning
# Edit prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

# Add to command line args
--storage.tsdb.retention.time=15d
--storage.tsdb.retention.size=10GB
--query.max-concurrency=20
--query.timeout=2m
```

## 🔐 Security Operations

### Daily Security Checks

```bash
#!/bin/bash
# Daily security check script

echo "🔐 CloudOS Daily Security Check - $(date)"
echo "======================================="

# 1. Failed Authentication Attempts
echo "🚫 Failed Authentication Attempts (last 24h):"
sudo grep "Failed password" /var/log/auth.log | grep "$(date +%b' '%d)" | wc -l | xargs echo "Failed attempts:"

# 2. Suspicious Network Connections
echo -e "\n🌐 Suspicious Network Connections:"
sudo netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -5

# 3. Recently Modified Files
echo -e "\n📝 Recently Modified System Files (last 24h):"
sudo find /etc /opt/cloudos -type f -mtime -1 -ls | wc -l | xargs echo "Modified files:"

# 4. Active Security Alerts
echo -e "\n🚨 Active Security Alerts:"
curl -s http://localhost:9093/api/v1/alerts | jq -r '.data[] | select(.labels.team=="security" and .status.state=="firing") | "- \(.labels.alertname): \(.annotations.summary)"' || echo "No security alerts"

# 5. Container Security
echo -e "\n🐳 Container Security Status:"
docker ps --format "table {{.Names}}\t{{.RunningFor}}\t{{.Status}}" | grep -v "healthy" | grep -v "NAMES" || echo "All containers healthy"

# 6. SSL Certificate Status
echo -e "\n🔒 SSL Certificate Status:"
openssl x509 -in /etc/ssl/certs/cloudos.crt -text -noout | grep "Not After" || echo "No SSL certificate configured"

echo -e "\n✅ Security check complete!"
```

### Security Hardening Checklist

- [ ] All default passwords changed
- [ ] SSH key-based authentication enabled
- [ ] Firewall configured and enabled
- [ ] Regular security updates applied
- [ ] Log monitoring configured
- [ ] Intrusion detection system active
- [ ] Regular backup verification
- [ ] Access control policies enforced

## 🔍 Troubleshooting

### Common Issues and Solutions

#### CloudOS Services Not Starting
```bash
# Check service status
systemctl status cloudos-*

# Check logs
journalctl -u cloudos-ai-engine -f

# Check configuration
sudo cloudos config validate

# Restart services
sudo systemctl restart cloudos-*
```

#### High Resource Usage
```bash
# Identify resource consumers
top -o %CPU
htop
docker stats

# Check for memory leaks
ps aux --sort=-%mem | head -10

# Monitor I/O usage
iotop
iostat -x 1
```

#### Network Connectivity Issues
```bash
# Check network configuration
ip addr show
ip route show

# Test connectivity
ping 8.8.8.8
nslookup google.com

# Check listening ports
ss -tulpn
netstat -tulpn
```

### Log Analysis

```bash
# CloudOS application logs
sudo tail -f /var/log/cloudos/*.log

# System logs
sudo journalctl -f

# Container logs
docker logs -f cloudos-ai-engine

# Audit logs
sudo ausearch -ts today -m avc
```

## 🚨 Emergency Procedures

### Service Outage Response

1. **Immediate Assessment** (< 2 minutes)
   ```bash
   # Quick health check
   systemctl status cloudos-*
   docker ps
   curl http://localhost:8000/health
   ```

2. **Service Recovery** (< 5 minutes)
   ```bash
   # Restart failed services
   sudo systemctl restart cloudos-*
   docker-compose restart

   # Check for quick fixes
   sudo cloudos repair --auto
   ```

3. **Escalation** (if not resolved in 10 minutes)
   - Contact on-call engineer
   - Activate incident response team
   - Implement communication plan

### Data Corruption Response

1. **Stop all write operations**
2. **Assess corruption scope**
3. **Initiate recovery from backup**
4. **Verify data integrity**
5. **Resume operations**

### Security Breach Response

1. **Immediate containment**
2. **Evidence preservation**
3. **Threat assessment**
4. **System recovery**
5. **Post-incident review**

## 📞 Emergency Contacts

### Internal Team
- **On-Call Engineer**: +1-XXX-XXX-XXXX
- **Engineering Manager**: +1-XXX-XXX-XXXX
- **Security Team**: security@cloudos.dev

### External Support
- **Cloud Provider Support**: [Provider-specific contact]
- **Vendor Support**: [Vendor contact information]
- **Legal/Compliance**: legal@cloudos.dev

## 📚 Additional Resources

- [CloudOS Documentation](../README.md)
- [Runbooks Directory](runbooks/)
- [Monitoring Guide](monitoring/README.md)
- [Security Guide](security-guide.md)
- [API Documentation](api-documentation.md)

---

This operations guide should be reviewed and updated monthly to ensure it remains current with system changes and operational learnings.