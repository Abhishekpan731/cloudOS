# Security Incident Response Runbook

## Overview
This runbook provides comprehensive procedures for responding to security incidents in CloudOS environments. Follow these procedures for authentication failures, potential breaches, or security alerts.

## 🚨 Incident Severity Levels

### **CRITICAL** (Immediate Response Required)
- Active security breach
- Unauthorized root/admin access
- Data exfiltration in progress
- Ransomware/malware detected
- Multiple authentication failures from single source

### **HIGH** (Response within 15 minutes)
- Suspicious authentication patterns
- Privilege escalation attempts
- Unusual network traffic
- Security tool failures

### **MEDIUM** (Response within 1 hour)
- Policy violations
- Failed compliance checks
- Suspicious user behavior

## Immediate Response (< 5 minutes)

### 1. Assess the Situation
```bash
# Check current security alerts
curl -s http://localhost:9093/api/v1/alerts | jq '.data[] | select(.labels.team=="security")'

# Check authentication failures
curl -s http://localhost:9200/metrics | grep auth_attempts_total

# Check active sessions
curl -s http://localhost:9200/metrics | grep active_sessions

# Review recent security events
curl -s http://localhost:9200/metrics | grep security_events_total
```

### 2. Immediate Containment
```bash
# For CRITICAL incidents - isolate affected systems
# Block suspicious IP addresses
sudo iptables -A INPUT -s <SUSPICIOUS_IP> -j DROP

# Disable compromised user accounts
sudo usermod -L <username>  # Lock account
sudo passwd -l <username>   # Lock password

# Stop suspicious processes
sudo pkill -f <suspicious_process>

# Isolate containers if compromised
docker stop <container_id>
docker network disconnect bridge <container_id>
```

### 3. Alert the Team
```bash
# Send immediate notification
curl -X POST https://hooks.slack.com/YOUR_WEBHOOK \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "🚨 SECURITY INCIDENT - Level: CRITICAL",
    "attachments": [{
      "color": "danger",
      "fields": [{
        "title": "Incident Type",
        "value": "Authentication Breach",
        "short": true
      }, {
        "title": "Affected System",
        "value": "CloudOS Production",
        "short": true
      }]
    }]
  }'
```

## Detailed Investigation (< 30 minutes)

### 1. Evidence Collection
```bash
# Collect system logs
sudo journalctl -u cloudos-* --since "1 hour ago" > /tmp/incident-logs.txt

# Collect authentication logs
sudo cat /var/log/auth.log | tail -1000 > /tmp/auth-logs.txt

# Collect network connections
ss -tulpn > /tmp/network-connections.txt
netstat -tulpn > /tmp/netstat-output.txt

# Collect process information
ps auxf > /tmp/process-tree.txt
top -bn1 > /tmp/process-usage.txt

# Container forensics
docker ps -a > /tmp/containers.txt
docker logs cloudos-ai-engine --since 1h > /tmp/ai-engine-logs.txt
docker logs cloudos-exporter --since 1h > /tmp/exporter-logs.txt
```

### 2. Timeline Reconstruction
```bash
# Check when incident started
# Look for first suspicious activity
grep -n "FAIL" /var/log/auth.log | tail -20

# Check CloudOS audit logs
sudo find /var/log/cloudos -name "audit*.log" -exec grep -l "$(date +%Y-%m-%d)" {} \;

# Check file system changes
sudo find /etc /opt/cloudos -type f -mtime -1 -ls

# Check user login history
last -n 50
w
who
```

### 3. Scope Assessment
```bash
# Check affected systems
# Query all CloudOS nodes for similar indicators
for node in $(kubectl get nodes -o name); do
  echo "=== $node ==="
  kubectl exec -n kube-system $node -- ss -tulpn | grep :22
done

# Check container integrity
docker exec cloudos-ai-engine find /opt/cloudos -type f -name "*.py" -exec sha256sum {} \; > /tmp/file-hashes.txt

# Verify system binaries
sudo debsums -c
rpm -Va  # For RHEL/CentOS systems
```

## Investigation Procedures

### Authentication Incidents
```bash
# Analyze failed login attempts
sudo grep "Failed password" /var/log/auth.log | awk '{print $1, $2, $3, $11}' | sort | uniq -c | sort -nr

# Check for successful logins after failures
sudo grep -A5 -B5 "Accepted password" /var/log/auth.log

# Verify SSH key usage
sudo grep "publickey" /var/log/auth.log | tail -20

# Check CloudOS authentication
curl -s http://localhost:8000/api/v1/auth/audit | jq '.recent_events'

# Check for privilege escalation
sudo grep "sudo:" /var/log/auth.log | tail -20
```

### Network Security Analysis
```bash
# Check for unusual outbound connections
sudo netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr

# Check for suspicious listening ports
sudo ss -tulpn | grep -v -E ':(22|80|443|9090|9093|3000|8080)'

# Analyze network traffic patterns
sudo tcpdump -i any -c 1000 -w /tmp/network-capture.pcap &
sleep 30
sudo pkill tcpdump

# Check CloudOS network metrics
curl -s http://localhost:9200/metrics | grep network_bytes_total
```

### File System Integrity
```bash
# Check for unauthorized changes
sudo find /opt/cloudos -type f -mtime -1 -ls

# Verify CloudOS binaries
sha256sum /opt/cloudos/bin/* > /tmp/binary-hashes.txt
# Compare with known good hashes

# Check for backdoors
sudo find / -name ".*" -type f -executable 2>/dev/null | head -20
sudo find /tmp /var/tmp -type f -executable -mtime -1

# Check crontabs
sudo cat /etc/crontab
sudo ls -la /etc/cron.*
```

### Container Security Analysis
```bash
# Check container integrity
docker diff cloudos-ai-engine
docker diff cloudos-exporter

# Verify container images
docker images --digests | grep cloudos

# Check for privilege escalation in containers
docker exec cloudos-ai-engine ps aux | grep root

# Analyze container logs for anomalies
docker logs cloudos-ai-engine 2>&1 | grep -i -E "(error|fail|unauthorized|denied)"
```

## Containment Procedures

### 1. Network Isolation
```bash
# Create isolation network rules
sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP
sudo iptables -A OUTPUT -d <SUSPICIOUS_DEST> -j DROP

# Isolate specific containers
docker network create isolated
docker network connect isolated <container_id>
docker network disconnect bridge <container_id>

# Block at CloudOS cluster level
kubectl create networkpolicy deny-all --namespace=default
```

### 2. Account Security
```bash
# Force password reset for all users
sudo chage -d 0 <username>

# Revoke all active sessions
# For CloudOS sessions
curl -X DELETE http://localhost:8000/api/v1/auth/sessions/all

# Rotate API keys and tokens
kubectl delete secret cloudos-api-keys
kubectl create secret generic cloudos-api-keys --from-literal=key="$(openssl rand -hex 32)"

# Update service account tokens
kubectl get secrets | grep "token" | xargs kubectl delete secret
```

### 3. System Hardening
```bash
# Disable unnecessary services
sudo systemctl disable --now <service>

# Update security policies
# Strengthen CloudOS configuration
sudo tee -a /etc/cloudos/security.yml << EOF
security:
  authentication:
    max_attempts: 3
    lockout_duration: 3600
  session:
    timeout: 900
    concurrent_limit: 1
EOF

# Restart CloudOS services with new security config
sudo systemctl restart cloudos-*
```

## Eradication

### 1. Remove Threats
```bash
# Remove malicious files
sudo rm -f /path/to/malicious/file

# Clean compromised containers
docker stop <compromised_container>
docker rm <compromised_container>
docker rmi <compromised_image>

# Rebuild from clean images
docker pull cloudos/ai-engine:latest
docker-compose up -d --force-recreate ai-engine

# Remove malicious users/accounts
sudo userdel -r <malicious_user>
```

### 2. Patch Vulnerabilities
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y
# or
sudo yum update -y

# Update CloudOS components
curl -sSL https://install.cloudos.dev/update | bash

# Apply security patches
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 3. Strengthen Security
```bash
# Implement additional monitoring
# Add new Prometheus alert rules
cat >> /etc/prometheus/alerts/security.yml << EOF
- alert: SuspiciousNetworkActivity
  expr: rate(cloudos_system_network_bytes_total[5m]) > 100 * 1024 * 1024
  for: 2m
  labels:
    severity: warning
    team: security
EOF

# Enable additional security logging
echo "auth,authpriv.*          /var/log/auth.log" >> /etc/rsyslog.conf
sudo systemctl restart rsyslog

# Configure fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

## Recovery

### 1. System Restoration
```bash
# Restore from clean backups if necessary
sudo systemctl stop cloudos-*
sudo rsync -av /backup/cloudos/ /opt/cloudos/
sudo systemctl start cloudos-*

# Verify system integrity
sudo debsums -c
sha256sum /opt/cloudos/bin/* | diff - /opt/cloudos/checksums.txt

# Test all CloudOS services
curl http://localhost:8000/health
curl http://localhost:9200/health
```

### 2. Service Restoration
```bash
# Restart all CloudOS services
sudo systemctl restart cloudos-*
docker-compose restart

# Verify cluster connectivity
kubectl get nodes
kubectl get pods --all-namespaces

# Test AI engine functionality
curl -X POST http://localhost:8000/api/v1/inference \
  -H "Content-Type: application/json" \
  -d '{"model": "test", "input": "test"}'
```

### 3. Monitoring Restoration
```bash
# Verify monitoring is working
curl http://localhost:9090/api/v1/query?query=up

# Check alert manager
curl http://localhost:9093/api/v1/alerts

# Test alerting
# Trigger a test alert to verify notification channels
```

## Post-Incident Activities

### 1. Documentation
```bash
# Create incident report
cat > /tmp/incident-report-$(date +%Y%m%d).md << EOF
# Security Incident Report - $(date)

## Timeline
- $(date -d '1 hour ago'): First detection
- $(date -d '45 minutes ago'): Containment
- $(date -d '30 minutes ago'): Investigation
- $(date): Resolution

## Root Cause
[Description of what caused the incident]

## Impact
[Systems affected, data exposure, downtime]

## Actions Taken
[List of remediation steps]

## Lessons Learned
[Improvements needed]
EOF
```

### 2. Forensic Analysis
```bash
# Preserve evidence
sudo mkdir -p /var/log/incidents/$(date +%Y%m%d)
sudo cp /tmp/incident-logs.txt /var/log/incidents/$(date +%Y%m%d)/
sudo cp /tmp/auth-logs.txt /var/log/incidents/$(date +%Y%m%d)/
sudo cp /tmp/network-connections.txt /var/log/incidents/$(date +%Y%m%d)/

# Create system image for analysis
sudo dd if=/dev/sda of=/backup/forensic-image-$(date +%Y%m%d).img bs=4M

# Generate checksums
sudo find /var/log/incidents/$(date +%Y%m%d)/ -type f -exec sha256sum {} \; > /var/log/incidents/$(date +%Y%m%d)/checksums.txt
```

### 3. Security Improvements
```bash
# Update security baseline
# Review and update security policies
# Implement additional monitoring
# Schedule security audit

# Update incident response procedures
# Add new indicators to monitoring
# Improve detection capabilities
```

## Prevention Measures

### 1. Enhanced Monitoring
- Implement behavioral analysis
- Set up threat intelligence feeds
- Enable real-time anomaly detection
- Regular security scans

### 2. Access Controls
- Implement zero-trust architecture
- Enable multi-factor authentication
- Regular access reviews
- Principle of least privilege

### 3. Security Training
- Regular security awareness training
- Incident response drills
- Security best practices
- Threat landscape updates

## Legal and Compliance

### Data Breach Notification
- Determine if personal data was involved
- Notify data protection authorities within 72 hours
- Notify affected users
- Document all breach response activities

### Evidence Preservation
- Maintain chain of custody for forensic evidence
- Preserve logs and system images
- Document all investigative activities
- Coordinate with legal team

## Contact Information

### Internal Contacts
- **Security Team**: security@cloudos.dev
- **On-Call Engineer**: +1-XXX-XXX-XXXX
- **Legal Team**: legal@cloudos.dev
- **PR Team**: pr@cloudos.dev

### External Contacts
- **Law Enforcement**: [Local cybercrime unit]
- **Incident Response Partner**: [External IR firm]
- **Legal Counsel**: [External legal counsel]

## Tools and Resources

### Required Tools
- **tcpdump/wireshark** - Network analysis
- **fail2ban** - Intrusion prevention
- **chkrootkit/rkhunter** - Rootkit detection
- **aide** - File integrity monitoring
- **osquery** - Security investigation

### Useful Commands Reference
```bash
# Quick security check
sudo ss -tulpn | grep -v -E ':(22|80|443|9090|9093|3000|8080)'
sudo last -n 20
sudo grep "Failed password" /var/log/auth.log | tail -10
sudo find /tmp -type f -executable -mtime -1
```

This runbook should be reviewed and updated quarterly or after each security incident.