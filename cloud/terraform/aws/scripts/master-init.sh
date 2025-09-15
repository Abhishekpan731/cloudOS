#!/bin/bash
set -e

# CloudOS Master Node Initialization Script

CLUSTER_NAME="${cluster_name}"
CLOUDOS_VERSION="0.1.0"
LOG_FILE="/var/log/cloudos-init.log"

exec > >(tee -a $LOG_FILE)
exec 2>&1

echo "Starting CloudOS Master Node initialization..."
echo "Cluster Name: $CLUSTER_NAME"
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
    nginx \
    certbot \
    python3 \
    python3-pip \
    jq \
    unzip \
    build-essential \
    postgresql \
    redis-server

# Start and enable services
systemctl start docker
systemctl enable docker
systemctl start postgresql
systemctl enable postgresql
systemctl start redis-server
systemctl enable redis-server

# Add ubuntu user to docker group
usermod -aG docker ubuntu

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
mv kubectl /usr/local/bin/

# Install etcd
ETCD_VERSION="v3.5.9"
wget https://github.com/etcd-io/etcd/releases/download/$ETCD_VERSION/etcd-$ETCD_VERSION-linux-amd64.tar.gz
tar xzf etcd-$ETCD_VERSION-linux-amd64.tar.gz
mv etcd-$ETCD_VERSION-linux-amd64/etcd* /usr/local/bin/
rm -rf etcd-$ETCD_VERSION-linux-amd64*

# Create CloudOS directories
mkdir -p /opt/cloudos/{bin,config,data,logs}
mkdir -p /var/lib/cloudos/{etcd,docker-registry}

# Download CloudOS binaries (placeholder - will be replaced with actual releases)
echo "Downloading CloudOS master components..."
cat > /opt/cloudos/bin/cloudos-master << 'EOF'
#!/bin/bash
echo "CloudOS Master Node v$CLOUDOS_VERSION"
echo "Starting master services..."

# Start etcd
/usr/local/bin/etcd \
  --name=cloudos-master \
  --data-dir=/var/lib/cloudos/etcd \
  --initial-cluster=cloudos-master=http://localhost:2380 \
  --initial-cluster-state=new \
  --initial-cluster-token=cloudos-cluster \
  --initial-advertise-peer-urls=http://localhost:2380 \
  --listen-peer-urls=http://localhost:2380 \
  --listen-client-urls=http://localhost:2379,http://127.0.0.1:2379 \
  --advertise-client-urls=http://localhost:2379 &

sleep 5

# Start master API server
python3 /opt/cloudos/bin/master-api.py &

# Start web UI
nginx -c /opt/cloudos/config/nginx.conf

echo "CloudOS Master is running!"
echo "Web UI: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo "API: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8080"

# Keep running
wait
EOF

chmod +x /opt/cloudos/bin/cloudos-master

# Create master API server
cat > /opt/cloudos/bin/master-api.py << 'EOF'
#!/usr/bin/env python3
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class CloudOSMasterAPI(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/v1/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            status = {
                "cluster_name": "${cluster_name}",
                "version": "0.1.0",
                "status": "running",
                "timestamp": datetime.now().isoformat(),
                "nodes": 1,
                "master_ip": self.server.server_address[0]
            }
            self.wfile.write(json.dumps(status).encode())
        elif self.path == '/api/v1/nodes':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            nodes = {
                "nodes": [
                    {
                        "id": "master",
                        "type": "master",
                        "status": "ready",
                        "resources": {
                            "cpu": "2",
                            "memory": "4Gi",
                            "storage": "50Gi"
                        }
                    }
                ]
            }
            self.wfile.write(json.dumps(nodes).encode())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/api/v1/nodes/register':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            response = {
                "status": "success",
                "message": "Node registered successfully",
                "token": "cloudos-join-token-" + str(int(time.time()))
            }
            self.wfile.write(json.dumps(response).encode())

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), CloudOSMasterAPI)
    print(f"CloudOS Master API listening on port 8080")
    server.serve_forever()
EOF

chmod +x /opt/cloudos/bin/master-api.py

# Create nginx configuration
cat > /opt/cloudos/config/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    server {
        listen 80;
        server_name _;

        # Redirect HTTP to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl default_server;
        server_name _;

        # Self-signed certificate (replace with proper cert in production)
        ssl_certificate /opt/cloudos/config/ssl/cert.pem;
        ssl_certificate_key /opt/cloudos/config/ssl/key.pem;

        root /opt/cloudos/web;
        index index.html;

        # API proxy
        location /api/ {
            proxy_pass http://localhost:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location / {
            try_files $uri $uri/ /index.html;
        }
    }
}
EOF

# Create SSL certificate directory and self-signed cert
mkdir -p /opt/cloudos/config/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /opt/cloudos/config/ssl/key.pem \
    -out /opt/cloudos/config/ssl/cert.pem \
    -subj "/C=US/ST=Cloud/L=Internet/O=CloudOS/OU=Master/CN=cloudos-master"

# Create web UI
mkdir -p /opt/cloudos/web
cat > /opt/cloudos/web/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudOS Master</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .status { background: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #28a745; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .info-card { background: #f8f9fa; padding: 20px; border-radius: 5px; border-left: 4px solid #007bff; }
        .command { background: #2c3e50; color: white; padding: 15px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
        .btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CloudOS Master Node</h1>

        <div class="status">
            <strong>🟢 Status:</strong> Master node is running and ready to accept compute nodes
        </div>

        <div class="info-grid">
            <div class="info-card">
                <h3>Cluster Information</h3>
                <p><strong>Cluster Name:</strong> ${cluster_name}</p>
                <p><strong>Version:</strong> CloudOS v0.1.0</p>
                <p><strong>Nodes:</strong> <span id="node-count">1</span> (1 master)</p>
            </div>

            <div class="info-card">
                <h3>API Endpoints</h3>
                <p><strong>REST API:</strong> <a href="/api/v1/status" target="_blank">/api/v1/status</a></p>
                <p><strong>Node Registration:</strong> /api/v1/nodes/register</p>
                <p><strong>Cluster Status:</strong> <a href="/api/v1/nodes" target="_blank">/api/v1/nodes</a></p>
            </div>
        </div>

        <div class="info-card">
            <h3>Add Compute Nodes</h3>
            <p>To add a new compute node to this cluster:</p>

            <h4>Option 1: Cloud Instance</h4>
            <div class="command">curl -sSL https://install.cloudos.dev/node | bash -s -- --master=https://MASTER_IP --token=JOIN_TOKEN</div>

            <h4>Option 2: Local Machine (ISO)</h4>
            <ol>
                <li>Download CloudOS ISO: <a href="https://releases.cloudos.dev/latest/cloudos.iso">cloudos.iso</a></li>
                <li>Boot machine from ISO</li>
                <li>Select "Join Existing Cluster"</li>
                <li>Enter master endpoint and join token</li>
            </ol>

            <h4>Option 3: Docker Container</h4>
            <div class="command">docker run -d --name cloudos-node --privileged \<br>
  -e MASTER_ENDPOINT=https://MASTER_IP \<br>
  -e JOIN_TOKEN=JOIN_TOKEN \<br>
  cloudos/node:latest</div>

            <button class="btn" onclick="generateToken()">Generate Join Token</button>
            <div id="join-token" style="margin-top: 10px;"></div>
        </div>

        <div class="info-card">
            <h3>Management Commands</h3>
            <button class="btn" onclick="refreshStatus()">Refresh Status</button>
            <button class="btn" onclick="viewLogs()">View Logs</button>
            <button class="btn" onclick="downloadConfig()">Download Config</button>
        </div>
    </div>

    <script>
        async function refreshStatus() {
            try {
                const response = await fetch('/api/v1/nodes');
                const data = await response.json();
                document.getElementById('node-count').textContent = data.nodes.length;
            } catch (error) {
                console.error('Error fetching status:', error);
            }
        }

        async function generateToken() {
            try {
                const response = await fetch('/api/v1/nodes/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: 'generate-token' })
                });
                const data = await response.json();
                document.getElementById('join-token').innerHTML =
                    '<strong>Join Token:</strong> <code style="background: #f1f1f1; padding: 5px;">' +
                    data.token + '</code>';
            } catch (error) {
                console.error('Error generating token:', error);
            }
        }

        function viewLogs() {
            window.open('/logs', '_blank');
        }

        function downloadConfig() {
            const a = document.createElement('a');
            a.href = '/api/v1/config';
            a.download = 'cloudos-config.yaml';
            a.click();
        }

        // Auto-refresh status every 30 seconds
        setInterval(refreshStatus, 30000);

        // Initial status load
        refreshStatus();
    </script>
</body>
</html>
EOF

# Create systemd service
cat > /etc/systemd/system/cloudos-master.service << 'EOF'
[Unit]
Description=CloudOS Master Node
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=forking
User=root
ExecStart=/opt/cloudos/bin/cloudos-master
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start CloudOS master service
systemctl daemon-reload
systemctl enable cloudos-master
systemctl start cloudos-master

# Create join script for nodes
cat > /opt/cloudos/bin/generate-join-command << 'EOF'
#!/bin/bash
MASTER_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
TOKEN=$(date +%s | sha256sum | head -c 16)
echo "curl -sSL https://install.cloudos.dev/node | bash -s -- --master=https://$MASTER_IP --token=cloudos-$TOKEN"
EOF

chmod +x /opt/cloudos/bin/generate-join-command

echo "CloudOS Master Node initialization complete!"
echo "Web UI: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo "API: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8080"
echo ""
echo "To add nodes, run: /opt/cloudos/bin/generate-join-command"