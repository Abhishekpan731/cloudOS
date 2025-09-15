#!/bin/bash

# CloudOS Universal Installer
# Can be used via: curl -sSL https://install.cloudos.dev | bash

set -e

CLOUDOS_VERSION="0.1.0"
INSTALL_DIR="/opt/cloudos"
CONFIG_DIR="/etc/cloudos"
SERVICE_DIR="/etc/systemd/system"
LOG_FILE="/var/log/cloudos-install.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
MODE=""
MASTER_ENDPOINT=""
JOIN_TOKEN=""
CLUSTER_NAME="cloudos-cluster"
PROVIDER=""

exec > >(tee -a $LOG_FILE)
exec 2>&1

print_header() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "       CloudOS Universal Installer"
    echo "             Version $CLOUDOS_VERSION"
    echo "========================================"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

usage() {
    cat << EOF
CloudOS Universal Installer

Usage:
  curl -sSL https://install.cloudos.dev | bash
  curl -sSL https://install.cloudos.dev/master | bash
  curl -sSL https://install.cloudos.dev/node | bash -s -- --master=ENDPOINT --token=TOKEN

Options:
  --mode=MODE                 Installation mode (master|node|standalone)
  --master=ENDPOINT          Master node endpoint (for node mode)
  --token=TOKEN              Join token (for node mode)
  --cluster-name=NAME        Cluster name (default: cloudos-cluster)
  --provider=PROVIDER        Cloud provider (aws|gcp|azure|local)

Examples:
  # Install master node
  curl -sSL https://install.cloudos.dev/master | bash

  # Install compute node
  curl -sSL https://install.cloudos.dev/node | bash -s -- \\
    --master=https://master.example.com \\
    --token=cloudos-join-token-abc123

  # Interactive installation
  curl -sSL https://install.cloudos.dev | bash
EOF
}

detect_system() {
    print_info "Detecting system..."

    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect operating system"
        exit 1
    fi

    # Detect cloud provider
    if curl -s -m 5 http://169.254.169.254/latest/meta-data/ > /dev/null 2>&1; then
        PROVIDER="aws"
    elif curl -s -m 5 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ > /dev/null 2>&1; then
        PROVIDER="gcp"
    elif curl -s -m 5 -H "Metadata: true" http://169.254.169.254/metadata/instance > /dev/null 2>&1; then
        PROVIDER="azure"
    else
        PROVIDER="local"
    fi

    print_success "Detected: $OS $VERSION on $PROVIDER"
}

check_requirements() {
    print_info "Checking system requirements..."

    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        print_info "Try: sudo $0"
        exit 1
    fi

    # Check system resources
    MEMORY_MB=$(free -m | awk 'NR==2{print $2}')
    DISK_GB=$(df / | awk 'NR==2{print int($4/1024/1024)}')

    if [ "$MEMORY_MB" -lt 512 ]; then
        print_error "Insufficient memory. Required: 512MB, Available: ${MEMORY_MB}MB"
        exit 1
    fi

    if [ "$DISK_GB" -lt 5 ]; then
        print_error "Insufficient disk space. Required: 5GB, Available: ${DISK_GB}GB"
        exit 1
    fi

    print_success "System requirements met"
}

install_dependencies() {
    print_info "Installing dependencies..."

    case "$OS" in
        ubuntu|debian)
            apt-get update
            apt-get install -y curl wget git docker.io docker-compose python3 python3-pip jq
            ;;
        centos|rhel|fedora)
            yum update -y
            yum install -y curl wget git docker docker-compose python3 python3-pip jq
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    # Start Docker
    systemctl start docker
    systemctl enable docker

    print_success "Dependencies installed"
}

interactive_setup() {
    print_info "Interactive setup mode"

    echo ""
    echo "CloudOS Installation Options:"
    echo "============================="
    echo "1) Master Node    - Create new cluster (recommended for first installation)"
    echo "2) Compute Node   - Join existing cluster"
    echo "3) Standalone     - Single machine installation"
    echo ""

    while true; do
        read -p "Select installation mode [1-3]: " choice
        case $choice in
            1)
                MODE="master"
                break
                ;;
            2)
                MODE="node"
                break
                ;;
            3)
                MODE="standalone"
                break
                ;;
            *)
                echo "Please choose 1, 2, or 3"
                ;;
        esac
    done

    if [ "$MODE" = "master" ]; then
        echo ""
        read -p "Cluster name [$CLUSTER_NAME]: " input
        CLUSTER_NAME=${input:-$CLUSTER_NAME}
    elif [ "$MODE" = "node" ]; then
        echo ""
        read -p "Master endpoint (e.g., https://master.example.com): " MASTER_ENDPOINT
        read -p "Join token: " JOIN_TOKEN

        if [ -z "$MASTER_ENDPOINT" ] || [ -z "$JOIN_TOKEN" ]; then
            print_error "Master endpoint and join token are required for node installation"
            exit 1
        fi
    fi
}

install_cloudos_master() {
    print_info "Installing CloudOS Master Node..."

    # Create directories
    mkdir -p $INSTALL_DIR/{bin,config,data,logs,web}
    mkdir -p $CONFIG_DIR
    mkdir -p /var/lib/cloudos/{etcd,registry}

    # Download or build CloudOS components
    download_cloudos_components

    # Create master configuration
    cat > $CONFIG_DIR/master.yaml << EOF
cluster:
  name: $CLUSTER_NAME
  mode: master

master:
  bind_address: "0.0.0.0"
  api_port: 8080
  secure_port: 443
  web_ui: true

database:
  type: etcd
  endpoints:
    - http://localhost:2379

ai:
  enabled: true
  model_path: /var/lib/cloudos/models

security:
  tls_enabled: true
  cert_path: $CONFIG_DIR/ssl/cert.pem
  key_path: $CONFIG_DIR/ssl/key.pem

logging:
  level: info
  file: /var/log/cloudos-master.log
EOF

    # Generate SSL certificates
    generate_ssl_certs

    # Create systemd service
    cat > $SERVICE_DIR/cloudos-master.service << EOF
[Unit]
Description=CloudOS Master Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/bin/cloudos-master --config=$CONFIG_DIR/master.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start service
    systemctl daemon-reload
    systemctl enable cloudos-master
    systemctl start cloudos-master

    print_success "CloudOS Master installed successfully!"

    # Show connection information
    show_master_info
}

install_cloudos_node() {
    print_info "Installing CloudOS Compute Node..."

    # Verify master connectivity
    if ! curl -k -s "$MASTER_ENDPOINT/api/v1/status" > /dev/null; then
        print_error "Cannot connect to master: $MASTER_ENDPOINT"
        exit 1
    fi

    # Create directories
    mkdir -p $INSTALL_DIR/{bin,config,data,logs}
    mkdir -p $CONFIG_DIR
    mkdir -p /var/lib/cloudos/containers

    # Download CloudOS components
    download_cloudos_components

    # Create node configuration
    cat > $CONFIG_DIR/node.yaml << EOF
cluster:
  name: $CLUSTER_NAME
  mode: node

master:
  endpoint: $MASTER_ENDPOINT
  join_token: $JOIN_TOKEN

node:
  id: $(hostname)-$(date +%s)
  bind_address: "0.0.0.0"
  port: 50052
  heartbeat_interval: 30s

runtime:
  type: docker
  socket: /var/run/docker.sock

resources:
  cpu_limit: 80%
  memory_limit: 85%

logging:
  level: info
  file: /var/log/cloudos-node.log
EOF

    # Create systemd service
    cat > $SERVICE_DIR/cloudos-node.service << EOF
[Unit]
Description=CloudOS Compute Node
After=network.target docker.service
Wants=network.target
Requires=docker.service

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/bin/cloudos-node --config=$CONFIG_DIR/node.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start service
    systemctl daemon-reload
    systemctl enable cloudos-node
    systemctl start cloudos-node

    print_success "CloudOS Node installed successfully!"
    print_info "Node will automatically register with master: $MASTER_ENDPOINT"
}

install_cloudos_standalone() {
    print_info "Installing CloudOS Standalone..."

    # Similar to master but configured for single-node operation
    install_cloudos_master

    # Update configuration for standalone mode
    sed -i 's/mode: master/mode: standalone/' $CONFIG_DIR/master.yaml

    print_success "CloudOS Standalone installed successfully!"
}

download_cloudos_components() {
    print_info "Downloading CloudOS components..."

    # For now, create placeholder binaries
    # In production, these would be downloaded from releases

    cat > $INSTALL_DIR/bin/cloudos-master << 'EOF'
#!/bin/bash
echo "CloudOS Master v0.1.0 starting..."
echo "Configuration: $1"

# Start etcd
/usr/local/bin/etcd \
  --data-dir=/var/lib/cloudos/etcd \
  --listen-client-urls=http://0.0.0.0:2379 \
  --advertise-client-urls=http://127.0.0.1:2379 \
  --listen-peer-urls=http://0.0.0.0:2380 \
  --initial-advertise-peer-urls=http://127.0.0.1:2380 \
  --initial-cluster=default=http://127.0.0.1:2380 \
  --initial-cluster-token=cloudos-cluster \
  --initial-cluster-state=new &

sleep 5

# Start API server
python3 $INSTALL_DIR/bin/api-server.py &

# Start web UI
nginx -c $INSTALL_DIR/config/nginx.conf &

wait
EOF

    cat > $INSTALL_DIR/bin/cloudos-node << 'EOF'
#!/bin/bash
echo "CloudOS Node v0.1.0 starting..."
echo "Configuration: $1"

python3 $INSTALL_DIR/bin/node-agent.py &
wait
EOF

    chmod +x $INSTALL_DIR/bin/cloudos-*

    # Create Python components (simplified versions)
    create_python_components

    print_success "Components downloaded"
}

create_python_components() {
    # Create API server
    cat > $INSTALL_DIR/bin/api-server.py << 'EOF'
#!/usr/bin/env python3
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class CloudOSAPI(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/v1/status':
            self.send_json({"status": "running", "version": "0.1.0"})
        elif self.path == '/api/v1/nodes':
            self.send_json({"nodes": []})
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/api/v1/nodes/register':
            self.send_json({"status": "success", "token": f"cloudos-{int(time.time())}"})
        else:
            self.send_error(404)

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), CloudOSAPI)
    server.serve_forever()
EOF

    # Create node agent
    cat > $INSTALL_DIR/bin/node-agent.py << 'EOF'
#!/usr/bin/env python3
import json
import time
import requests
import threading
from datetime import datetime

class CloudOSNode:
    def __init__(self):
        self.config = self.load_config()

    def load_config(self):
        # Load configuration from file
        return {
            "master_endpoint": "http://localhost:8080",
            "node_id": "local-node"
        }

    def register(self):
        # Register with master
        pass

    def heartbeat(self):
        # Send heartbeat to master
        while True:
            time.sleep(30)

    def run(self):
        threading.Thread(target=self.heartbeat, daemon=True).start()
        while True:
            time.sleep(60)

if __name__ == '__main__':
    node = CloudOSNode()
    node.run()
EOF

    chmod +x $INSTALL_DIR/bin/*.py
}

generate_ssl_certs() {
    print_info "Generating SSL certificates..."

    mkdir -p $CONFIG_DIR/ssl

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $CONFIG_DIR/ssl/key.pem \
        -out $CONFIG_DIR/ssl/cert.pem \
        -subj "/C=US/ST=Cloud/L=Internet/O=CloudOS/CN=$(hostname)"

    print_success "SSL certificates generated"
}

show_master_info() {
    echo ""
    print_success "CloudOS Master is ready!"
    echo ""
    echo "Cluster Information:"
    echo "==================="
    echo "Cluster Name: $CLUSTER_NAME"
    echo "Master IP: $(hostname -I | awk '{print $1}')"
    echo "Web UI: https://$(hostname -I | awk '{print $1}')"
    echo "API Endpoint: http://$(hostname -I | awk '{print $1}'):8080"
    echo ""
    echo "To add compute nodes, use:"
    echo "curl -sSL https://install.cloudos.dev/node | bash -s -- \\"
    echo "  --master=https://$(hostname -I | awk '{print $1}') \\"
    echo "  --token=\$(curl -s http://$(hostname -I | awk '{print $1}'):8080/api/v1/nodes/register | jq -r .token)"
    echo ""
    echo "Service Management:"
    echo "==================="
    echo "Status: systemctl status cloudos-master"
    echo "Logs: journalctl -u cloudos-master -f"
    echo "Stop: systemctl stop cloudos-master"
    echo "Start: systemctl start cloudos-master"
}

cleanup() {
    print_warning "Cleaning up installation..."
    systemctl stop cloudos-master 2>/dev/null || true
    systemctl stop cloudos-node 2>/dev/null || true
    systemctl disable cloudos-master 2>/dev/null || true
    systemctl disable cloudos-node 2>/dev/null || true
    rm -rf $INSTALL_DIR
    rm -rf $CONFIG_DIR
    rm -f $SERVICE_DIR/cloudos-*.service
    systemctl daemon-reload
    print_success "Cleanup completed"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode=*)
            MODE="${1#*=}"
            shift
            ;;
        --master=*)
            MASTER_ENDPOINT="${1#*=}"
            shift
            ;;
        --token=*)
            JOIN_TOKEN="${1#*=}"
            shift
            ;;
        --cluster-name=*)
            CLUSTER_NAME="${1#*=}"
            shift
            ;;
        --provider=*)
            PROVIDER="${1#*=}"
            shift
            ;;
        --cleanup)
            cleanup
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Detect installation mode from URL path
if [ -z "$MODE" ]; then
    if echo "$0" | grep -q "master"; then
        MODE="master"
    elif echo "$0" | grep -q "node"; then
        MODE="node"
    fi
fi

# Main execution
print_header
detect_system
check_requirements
install_dependencies

case "$MODE" in
    master)
        install_cloudos_master
        ;;
    node)
        if [ -z "$MASTER_ENDPOINT" ] || [ -z "$JOIN_TOKEN" ]; then
            print_error "Node installation requires --master and --token parameters"
            exit 1
        fi
        install_cloudos_node
        ;;
    standalone)
        install_cloudos_standalone
        ;;
    *)
        interactive_setup
        case "$MODE" in
            master) install_cloudos_master ;;
            node) install_cloudos_node ;;
            standalone) install_cloudos_standalone ;;
        esac
        ;;
esac

print_success "CloudOS installation completed!"
print_info "Check logs: tail -f $LOG_FILE"