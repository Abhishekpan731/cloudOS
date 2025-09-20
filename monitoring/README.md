# CloudOS Monitoring and Observability Stack

This directory contains the complete monitoring and observability infrastructure for CloudOS, including metrics collection, alerting, dashboards, and log aggregation.

## 🏗️ Architecture Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Grafana   │◄───┤ Prometheus  │◄───┤   Targets   │
│ Dashboards  │    │   Metrics   │    │ (Exporters) │
└─────────────┘    └─────────────┘    └─────────────┘
                            │
                            ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│AlertManager │◄───┤   Rules     │    │    Loki     │
│Notifications│    │ Evaluation  │    │Log Storage  │
└─────────────┘    └─────────────┘    └─────────────┘
                                               ▲
                                               │
                                      ┌─────────────┐
                                      │  Promtail   │
                                      │Log Collection│
                                      └─────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- At least 4GB RAM available
- 10GB disk space for metrics storage

### Start the Stack

```bash
# Start all monitoring services
./scripts/start-monitoring.sh

# Check service health
./scripts/start-monitoring.sh health

# View logs
./scripts/start-monitoring.sh logs grafana
```

### Stop the Stack

```bash
./scripts/start-monitoring.sh stop
```

## 📊 Components

### Core Services

| Service | Port | Description |
|---------|------|-------------|
| **Prometheus** | 9090 | Metrics collection and storage |
| **Grafana** | 3000 | Visualization and dashboards |
| **AlertManager** | 9093 | Alert routing and notifications |
| **Loki** | 3100 | Log aggregation and storage |
| **Jaeger** | 16686 | Distributed tracing |

### Monitoring Agents

| Service | Port | Purpose |
|---------|------|---------|
| **Node Exporter** | 9100 | Host system metrics |
| **cAdvisor** | 8080 | Container metrics |
| **Promtail** | 9080 | Log collection agent |
| **CloudOS Exporter** | 9200 | Custom CloudOS metrics |
| **Pushgateway** | 9091 | Batch job metrics |

## 🎯 Default Dashboards

### System Overview
- CPU, Memory, Disk usage
- Network I/O statistics
- System load and processes

### Container Metrics
- Container count by state
- Resource usage per container
- Restart and health statistics

### AI Engine Performance
- Inference request rates
- Model loading statistics
- Latency and error rates

### Security Monitoring
- Authentication events
- Security incident detection
- Access patterns and anomalies

### Cluster Health
- Node status and availability
- Leader election events
- Distributed system metrics

## 🔔 Alerting

### Alert Severities

- **Critical**: Immediate attention required
- **Warning**: Attention needed soon
- **Info**: Informational notifications

### Notification Channels

- **Email**: Critical alerts and summaries
- **Slack**: Real-time notifications
- **Webhooks**: Custom integrations

### Key Alert Rules

| Alert | Threshold | Action |
|-------|-----------|--------|
| High CPU Usage | >90% for 5min | Warning notification |
| Critical Memory | >95% for 2min | Critical alert |
| Disk Space Low | <15% free | Warning alert |
| Container Restarts | >5 in 1hour | Investigation needed |
| AI Inference Failures | >10% error rate | AI team notification |
| Authentication Failures | >10 in 5min | Security alert |

## 📝 Log Collection

### Log Sources

- **System Logs**: syslog, auth.log, daemon logs
- **Application Logs**: CloudOS components
- **Container Logs**: Docker container output
- **Security Logs**: Authentication and authorization
- **Audit Logs**: System and user actions

### Log Retention

- **Default**: 7 days (configurable)
- **Long-term**: Configure remote storage for longer retention
- **Compression**: Automatic log compression and rotation

## ⚙️ Configuration

### Prometheus Configuration

Edit `prometheus/prometheus.yml` to:
- Add new scrape targets
- Modify scrape intervals
- Configure remote storage

### Grafana Configuration

- **Admin credentials**: admin/cloudos123
- **Datasources**: Pre-configured for Prometheus, Loki, Jaeger
- **Dashboards**: Auto-provisioned from `/grafana/dashboards/`

### AlertManager Configuration

Edit `alertmanager/alertmanager.yml` to:
- Configure notification channels
- Set up routing rules
- Add webhook integrations

## 🔧 Customization

### Adding Custom Metrics

1. **Kernel Metrics**: Expose metrics from CloudOS kernel
```c
// In kernel code
prometheus_counter_inc(request_count);
prometheus_gauge_set(memory_usage, current_usage);
```

2. **Application Metrics**: Use the CloudOS metrics library
```python
from monitoring.observability.prometheus_integration import ObservabilityStack

stack = ObservabilityStack()
stack.record_ai_inference_metric("model_id", duration, success)
```

3. **Custom Exporters**: Create new exporters for specific components

### Creating Custom Dashboards

1. Create JSON files in `grafana/dashboards/`
2. Use the dashboard provisioning system
3. Access via Grafana UI at http://localhost:3000

### Adding Alert Rules

1. Edit `prometheus/alerts/cloudos_alerts.yml`
2. Define new alert rules with PromQL expressions
3. Restart Prometheus to reload rules

## 🐳 Docker Configuration

### Environment Variables

- `CLOUDOS_METRICS_PORT`: Custom metrics port (default: 9200)
- `CLOUDOS_LOG_LEVEL`: Logging level (INFO, DEBUG, ERROR)
- `CLOUDOS_PUSHGATEWAY_URL`: Pushgateway endpoint

### Volume Mounts

- `prometheus_data`: Metrics storage
- `grafana_data`: Dashboard and configuration storage
- `loki_data`: Log storage
- `alertmanager_data`: Alert state storage

## 🔍 Troubleshooting

### Common Issues

1. **Services not starting**
   ```bash
   # Check logs
   docker-compose logs -f [service]

   # Check available resources
   docker system df
   ```

2. **Metrics not appearing**
   ```bash
   # Check Prometheus targets
   curl http://localhost:9090/api/v1/targets

   # Verify exporter endpoints
   curl http://localhost:9200/metrics
   ```

3. **Alerts not firing**
   ```bash
   # Check alert rules
   curl http://localhost:9090/api/v1/rules

   # Verify AlertManager configuration
   curl http://localhost:9093/api/v1/status
   ```

4. **Dashboard not loading**
   - Check Grafana datasource configuration
   - Verify Prometheus connectivity
   - Check browser console for errors

### Performance Tuning

1. **Metrics Retention**: Adjust `--storage.tsdb.retention.time`
2. **Scrape Intervals**: Increase intervals for high-cardinality metrics
3. **Memory Limits**: Set appropriate container memory limits
4. **Disk Space**: Monitor disk usage and configure cleanup policies

## 📈 Scaling

### Horizontal Scaling

- **Prometheus**: Use federation for multiple Prometheus instances
- **Grafana**: Deploy multiple Grafana instances with shared storage
- **AlertManager**: Cluster AlertManager for high availability

### Vertical Scaling

- Increase memory allocation for Prometheus
- Add more CPU cores for Grafana
- Optimize queries and dashboard refresh rates

## 🔐 Security

### Access Control

- Change default Grafana admin password
- Configure LDAP/OAuth for user authentication
- Use TLS for external connections

### Data Protection

- Enable encryption at rest for sensitive metrics
- Configure network segmentation
- Regular backup of configuration and data

## 🧪 Testing

### Health Checks

```bash
# Test all endpoints
./scripts/start-monitoring.sh health

# Manual endpoint tests
curl http://localhost:9090/-/healthy  # Prometheus
curl http://localhost:3000/api/health # Grafana
curl http://localhost:9093/-/healthy  # AlertManager
```

### Load Testing

```bash
# Generate test metrics
for i in {1..1000}; do
  echo "test_metric $i" | curl -X POST --data-binary @- http://localhost:9091/metrics/job/test
done
```

## 📚 Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [AlertManager Documentation](https://prometheus.io/docs/alerting/latest/alertmanager/)
- [Loki Documentation](https://grafana.com/docs/loki/)
- [CloudOS Metrics API](../docs/metrics-api.md)

## 🤝 Contributing

1. Test changes locally with the development stack
2. Update documentation for new metrics or dashboards
3. Follow the CloudOS monitoring standards
4. Submit pull requests with proper testing

---

For questions or issues, please check the [CloudOS documentation](../docs/) or create an issue in the repository.