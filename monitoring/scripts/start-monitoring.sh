#!/bin/bash
# CloudOS Monitoring Stack Startup Script
# Starts the complete observability stack with proper dependency ordering

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITORING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is required but not installed"
        exit 1
    fi

    log_success "Dependencies satisfied"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."

    cd "$MONITORING_DIR"

    # Create volume mount directories
    mkdir -p {prometheus,grafana,alertmanager,loki,promtail}/data
    mkdir -p grafana/dashboards/{system,applications,ai,security,cluster}
    mkdir -p config

    # Set permissions
    chmod -R 755 .

    log_success "Directories created"
}

# Validate configuration files
validate_configs() {
    log_info "Validating configuration files..."

    local configs=(
        "prometheus/prometheus.yml"
        "alertmanager/alertmanager.yml"
        "grafana/provisioning/datasources/prometheus.yml"
        "grafana/provisioning/dashboards/dashboard.yml"
        "loki/loki.yml"
        "promtail/promtail.yml"
    )

    for config in "${configs[@]}"; do
        if [[ ! -f "$MONITORING_DIR/$config" ]]; then
            log_error "Configuration file missing: $config"
            exit 1
        fi
    done

    log_success "Configuration files validated"
}

# Build custom exporter image
build_exporter() {
    log_info "Building CloudOS metrics exporter..."

    cd "$MONITORING_DIR"

    if docker build -f Dockerfile.exporter -t cloudos-metrics-exporter:latest .; then
        log_success "CloudOS metrics exporter built successfully"
    else
        log_error "Failed to build CloudOS metrics exporter"
        exit 1
    fi
}

# Start monitoring stack
start_stack() {
    log_info "Starting CloudOS monitoring stack..."

    cd "$MONITORING_DIR"

    # Start core infrastructure first
    log_info "Starting core infrastructure (Prometheus, Loki, AlertManager)..."
    docker-compose up -d prometheus loki alertmanager pushgateway

    # Wait for core services to be ready
    log_info "Waiting for core services to be ready..."
    sleep 15

    # Start monitoring agents
    log_info "Starting monitoring agents (Node Exporter, cAdvisor, Promtail)..."
    docker-compose up -d node-exporter cadvisor promtail

    # Wait for agents to start
    sleep 10

    # Start visualization and tracing
    log_info "Starting visualization and tracing (Grafana, Jaeger)..."
    docker-compose up -d grafana jaeger

    # Wait for Grafana
    sleep 15

    # Start custom CloudOS exporter
    log_info "Starting CloudOS custom metrics exporter..."
    docker-compose up -d cloudos-exporter

    log_success "CloudOS monitoring stack started successfully"
}

# Health check services
health_check() {
    log_info "Performing health checks..."

    local services=(
        "prometheus:9090/api/v1/query?query=up"
        "grafana:3000/api/health"
        "alertmanager:9093/api/v1/status"
        "loki:3100/ready"
        "jaeger:16686/api/services"
    )

    local healthy=true

    for service in "${services[@]}"; do
        local name="${service%%:*}"
        local endpoint="http://localhost:${service#*:}"

        log_info "Checking $name..."

        if curl -sf "$endpoint" >/dev/null 2>&1; then
            log_success "$name is healthy"
        else
            log_warning "$name is not responding"
            healthy=false
        fi
    done

    if $healthy; then
        log_success "All services are healthy"
    else
        log_warning "Some services are not responding (may still be starting up)"
    fi
}

# Show access information
show_access_info() {
    cat << EOF

${GREEN}🚀 CloudOS Monitoring Stack is running!${NC}

${BLUE}📊 Access URLs:${NC}
  • Grafana:        http://localhost:3000 (admin/cloudos123)
  • Prometheus:     http://localhost:9090
  • AlertManager:   http://localhost:9093
  • Jaeger:         http://localhost:16686
  • Loki:           http://localhost:3100
  • Node Exporter:  http://localhost:9100
  • cAdvisor:       http://localhost:8080
  • Pushgateway:    http://localhost:9091
  • CloudOS Exporter: http://localhost:9200

${BLUE}📈 Pre-configured Dashboards:${NC}
  • CloudOS System Overview
  • Container Metrics
  • AI Engine Performance
  • Security Monitoring
  • Cluster Health

${BLUE}🔔 Alert Channels:${NC}
  • Critical alerts: Email + Slack
  • Warnings: Slack notifications
  • Security events: Immediate notifications

${BLUE}📝 Log Sources:${NC}
  • System logs via Promtail
  • Container logs via Docker
  • CloudOS application logs
  • Security and audit logs

${YELLOW}⚙️  Management Commands:${NC}
  • Stop stack:    docker-compose down
  • View logs:     docker-compose logs -f [service]
  • Restart:       docker-compose restart [service]
  • Scale:         docker-compose up -d --scale [service]=N

EOF
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    cd "$MONITORING_DIR"
    docker-compose down
    log_success "Monitoring stack stopped"
}

# Main function
main() {
    log_info "Starting CloudOS Monitoring Stack Setup..."

    # Set up signal handlers
    trap cleanup EXIT INT TERM

    check_dependencies
    create_directories
    validate_configs
    build_exporter
    start_stack

    # Give services time to fully start
    log_info "Waiting for all services to be ready..."
    sleep 30

    health_check
    show_access_info

    log_success "CloudOS Monitoring Stack setup complete!"
}

# Handle command line arguments
case "${1:-start}" in
    start)
        main
        ;;
    stop)
        cleanup
        ;;
    health)
        health_check
        ;;
    rebuild)
        cd "$MONITORING_DIR"
        docker-compose down
        build_exporter
        start_stack
        ;;
    logs)
        cd "$MONITORING_DIR"
        docker-compose logs -f "${2:-}"
        ;;
    *)
        echo "Usage: $0 {start|stop|health|rebuild|logs [service]}"
        exit 1
        ;;
esac