#!/bin/bash
set -e

# CloudOS Compute Node Initialization Script

CLUSTER_NAME="${cluster_name}"
MASTER_IP="${master_ip}"
NODE_INDEX="${node_index}"
CLOUDOS_VERSION="0.1.0"
LOG_FILE="/var/log/cloudos-node-init.log"

exec > >(tee -a $LOG_FILE)
exec 2>&1

echo "Starting CloudOS Compute Node initialization..."
echo "Cluster Name: $CLUSTER_NAME"
echo "Master IP: $MASTER_IP"
echo "Node Index: $NODE_INDEX"
echo "CloudOS Version: $CLOUDOS_VERSION"
echo "Timestamp: $(date)"

# Update system
echo "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
echo "Installing system dependencies..."
apt-get install -y \
    curl \
    wget \
    git \
    docker.io \
    docker-compose \
    python3 \
    python3-pip \
    jq \
    unzip \
    htop \
    iotop \
    nethogs

# Start and enable services
systemctl start docker
systemctl enable docker

# Add ubuntu user to docker group
usermod -aG docker ubuntu

# Create CloudOS directories
mkdir -p /opt/cloudos/{bin,config,data,logs}
mkdir -p /var/lib/cloudos/containers

# Get node IP addresses
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# Create CloudOS node agent
cat > /opt/cloudos/bin/cloudos-node << 'EOF'
#!/bin/bash
echo "CloudOS Compute Node v$CLOUDOS_VERSION"
echo "Node Index: $NODE_INDEX"
echo "Connecting to master: $MASTER_IP"

# Start node agent
python3 /opt/cloudos/bin/node-agent.py &

# Start container runtime
dockerd &

echo "CloudOS Node is running!"
echo "Private IP: $PRIVATE_IP"
echo "Public IP: $PUBLIC_IP"

# Keep running
wait
EOF

chmod +x /opt/cloudos/bin/cloudos-node

# Create node agent
cat > /opt/cloudos/bin/node-agent.py << 'EOF'
#!/usr/bin/env python3
import json
import time
import requests
import subprocess
import psutil
from datetime import datetime
import threading

class CloudOSNodeAgent:
    def __init__(self):
        self.master_ip = "${master_ip}"
        self.node_id = f"node-${node_index}"
        self.cluster_name = "${cluster_name}"
        self.private_ip = "${private_ip}"
        self.public_ip = "${public_ip}"
        self.registered = False

    def get_system_info(self):
        """Get system resource information"""
        cpu_count = psutil.cpu_count()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            "cpu": {
                "count": cpu_count,
                "usage": psutil.cpu_percent(interval=1)
            },
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percentage": memory.percent
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percentage": (disk.used / disk.total) * 100
            },
            "network": {
                "private_ip": self.private_ip,
                "public_ip": self.public_ip
            }
        }

    def register_with_master(self):
        """Register this node with the master"""
        try:
            registration_data = {
                "node_id": self.node_id,
                "node_type": "compute",
                "cluster_name": self.cluster_name,
                "private_ip": self.private_ip,
                "public_ip": self.public_ip,
                "system_info": self.get_system_info(),
                "timestamp": datetime.now().isoformat()
            }

            response = requests.post(
                f"http://{self.master_ip}:8080/api/v1/nodes/register",
                json=registration_data,
                timeout=30
            )

            if response.status_code == 200:
                self.registered = True
                print(f"Successfully registered with master at {self.master_ip}")
                return True
            else:
                print(f"Failed to register: HTTP {response.status_code}")
                return False

        except Exception as e:
            print(f"Error registering with master: {e}")
            return False

    def send_heartbeat(self):
        """Send periodic heartbeat to master"""
        while True:
            if self.registered:
                try:
                    heartbeat_data = {
                        "node_id": self.node_id,
                        "status": "running",
                        "system_info": self.get_system_info(),
                        "timestamp": datetime.now().isoformat()
                    }

                    response = requests.post(
                        f"http://{self.master_ip}:8080/api/v1/nodes/heartbeat",
                        json=heartbeat_data,
                        timeout=10
                    )

                    if response.status_code == 200:
                        print(f"Heartbeat sent successfully at {datetime.now()}")
                    else:
                        print(f"Heartbeat failed: HTTP {response.status_code}")

                except Exception as e:
                    print(f"Error sending heartbeat: {e}")

            time.sleep(30)  # Send heartbeat every 30 seconds

    def run(self):
        """Main node agent loop"""
        print(f"Starting CloudOS Node Agent for {self.node_id}")

        # Try to register with master
        retry_count = 0
        while not self.registered and retry_count < 10:
            print(f"Attempting to register with master (attempt {retry_count + 1})")
            if self.register_with_master():
                break
            retry_count += 1
            time.sleep(10)

        if not self.registered:
            print("Failed to register with master after 10 attempts")
            return

        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.send_heartbeat, daemon=True)
        heartbeat_thread.start()

        # Main loop
        print("Node agent is running...")
        while True:
            # Handle any incoming work requests from master
            # This is where workload scheduling would be implemented
            time.sleep(60)

if __name__ == '__main__':
    agent = CloudOSNodeAgent()
    agent.run()
EOF

# Update the node-agent.py with actual IP addresses
sed -i "s/\${private_ip}/$PRIVATE_IP/g" /opt/cloudos/bin/node-agent.py
sed -i "s/\${public_ip}/$PUBLIC_IP/g" /opt/cloudos/bin/node-agent.py

chmod +x /opt/cloudos/bin/node-agent.py

# Install Python dependencies
pip3 install requests psutil

# Create systemd service
cat > /etc/systemd/system/cloudos-node.service << 'EOF'
[Unit]
Description=CloudOS Compute Node
After=network.target docker.service
Requires=docker.service

[Service]
Type=forking
User=root
ExecStart=/opt/cloudos/bin/cloudos-node
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start CloudOS node service
systemctl daemon-reload
systemctl enable cloudos-node
systemctl start cloudos-node

# Wait a bit for the node to register
sleep 30

# Create node status script
cat > /opt/cloudos/bin/node-status << 'EOF'
#!/bin/bash
echo "CloudOS Node Status"
echo "=================="
echo "Node ID: $NODE_INDEX"
echo "Cluster: $CLUSTER_NAME"
echo "Master: $MASTER_IP"
echo "Private IP: $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)"
echo "Public IP: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo ""
echo "System Resources:"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')"
echo "Memory Usage: $(free | grep Mem | awk '{printf("%.1f%% (%s/%s)\n", ($3/$2) * 100.0, $3, $2)}')"
echo "Disk Usage: $(df -h / | awk 'NR==2{printf "%s (%s)\n", $5, $4}')"
echo ""
echo "Docker Containers:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
EOF

chmod +x /opt/cloudos/bin/node-status

echo "CloudOS Compute Node initialization complete!"
echo "Node ID: node-$NODE_INDEX"
echo "Master: $MASTER_IP"
echo "Status: $(systemctl is-active cloudos-node)"
echo ""
echo "To check node status, run: /opt/cloudos/bin/node-status"