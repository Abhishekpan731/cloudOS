#!/bin/bash
# CloudOS Install Endpoint Setup
# Creates the infrastructure for install.cloudos.dev

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_info "Setting up CloudOS install endpoint infrastructure..."

# Create install endpoint directory
mkdir -p "$PROJECT_ROOT/install"

# Create main install script
cat > "$PROJECT_ROOT/install/install.sh" << 'EOF'
#!/bin/bash
# CloudOS Universal Installer
# Usage: curl -sSL https://install.cloudos.dev | bash

set -euo pipefail

# Configuration
DEFAULT_VERSION="latest"
DEFAULT_INSTALL_DIR="/opt/cloudos"
GITHUB_REPO="CloudOSProject/CloudOS"
BASE_URL="https://github.com/${GITHUB_REPO}/releases"

# User-configurable variables
CLOUDOS_VERSION="${CLOUDOS_VERSION:-$DEFAULT_VERSION}"
CLOUDOS_INSTALL_DIR="${CLOUDOS_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
CLOUDOS_ARCH="${CLOUDOS_ARCH:-}"
FORCE_INSTALL="${FORCE_INSTALL:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect system information
detect_system() {
    local arch machine

    # Detect architecture
    machine=$(uname -m)
    case $machine in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l|armhf) arch="armv7" ;;
        *) log_error "Unsupported architecture: $machine"; exit 1 ;;
    esac

    # Override if user specified
    if [[ -n "$CLOUDOS_ARCH" ]]; then
        arch="$CLOUDOS_ARCH"
    fi

    echo "$arch"
}

# Get latest version from GitHub API
get_latest_version() {
    if command -v curl &> /dev/null; then
        curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | \
            grep '"tag_name":' | \
            sed -E 's/.*"tag_name": "([^"]+)".*/\1/'
    elif command -v wget &> /dev/null; then
        wget -qO- "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | \
            grep '"tag_name":' | \
            sed -E 's/.*"tag_name": "([^"]+)".*/\1/'
    else
        log_error "Neither curl nor wget found. Cannot fetch latest version."
        exit 1
    fi
}

# Download file with progress
download_file() {
    local url="$1"
    local output="$2"

    if command -v curl &> /dev/null; then
        curl -L --progress-bar -o "$output" "$url"
    elif command -v wget &> /dev/null; then
        wget --progress=bar:force -O "$output" "$url"
    else
        log_error "Neither curl nor wget found. Cannot download files."
        exit 1
    fi
}

# Verify checksum
verify_checksum() {
    local file="$1"
    local expected_hash="$2"

    if command -v sha256sum &> /dev/null; then
        local actual_hash
        actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
        if [[ "$actual_hash" != "$expected_hash" ]]; then
            log_error "Checksum verification failed for $file"
            log_error "Expected: $expected_hash"
            log_error "Actual: $actual_hash"
            return 1
        fi
    else
        log_warning "sha256sum not found, skipping checksum verification"
    fi
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."

    # Check if running as root for system-wide install
    if [[ "$CLOUDOS_INSTALL_DIR" == "/opt/cloudos" || "$CLOUDOS_INSTALL_DIR" == "/usr"* ]]; then
        if [[ $EUID -ne 0 ]]; then
            log_warning "System-wide installation requires root privileges"
            log_info "Consider running with sudo or setting CLOUDOS_INSTALL_DIR to a user directory"
            log_info "Example: CLOUDOS_INSTALL_DIR=\$HOME/.local/cloudos $0"
            exit 1
        fi
    fi

    # Check available space (at least 100MB)
    local install_parent
    install_parent=$(dirname "$CLOUDOS_INSTALL_DIR")
    local available_space
    available_space=$(df -BM "$install_parent" | awk 'NR==2 {print $4}' | sed 's/M//')

    if [[ $available_space -lt 100 ]]; then
        log_error "Insufficient disk space. At least 100MB required."
        exit 1
    fi

    log_success "System requirements satisfied"
}

# Install CloudOS
install_cloudos() {
    local arch version

    arch=$(detect_system)
    log_info "Detected architecture: $arch"

    # Get version
    if [[ "$CLOUDOS_VERSION" == "latest" ]]; then
        log_info "Fetching latest version..."
        version=$(get_latest_version)
        if [[ -z "$version" ]]; then
            log_error "Failed to fetch latest version"
            exit 1
        fi
    else
        version="$CLOUDOS_VERSION"
    fi

    log_info "Installing CloudOS $version for $arch"

    # Create temporary directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    # Download archive
    local archive_name="cloudos-${version#v}-${arch}.tar.gz"
    local download_url="${BASE_URL}/download/${version}/${archive_name}"

    log_info "Downloading $archive_name..."
    if ! download_file "$download_url" "$tmp_dir/$archive_name"; then
        # Fallback to universal archive
        log_warning "Architecture-specific package not found, trying universal package..."
        archive_name="cloudos-${version#v}-universal.zip"
        download_url="${BASE_URL}/download/${version}/${archive_name}"
        download_file "$download_url" "$tmp_dir/$archive_name"
    fi

    # Download checksums
    log_info "Downloading checksums..."
    download_file "${BASE_URL}/download/${version}/checksums.txt" "$tmp_dir/checksums.txt"

    # Verify checksum
    local expected_hash
    expected_hash=$(grep "$archive_name" "$tmp_dir/checksums.txt" | cut -d' ' -f1)
    if [[ -n "$expected_hash" ]]; then
        verify_checksum "$tmp_dir/$archive_name" "$expected_hash"
    fi

    # Create install directory
    log_info "Creating install directory: $CLOUDOS_INSTALL_DIR"
    mkdir -p "$CLOUDOS_INSTALL_DIR"

    # Extract archive
    log_info "Extracting CloudOS..."
    cd "$tmp_dir"
    if [[ "$archive_name" == *.tar.gz ]]; then
        tar -xzf "$archive_name"
    elif [[ "$archive_name" == *.zip ]]; then
        unzip -q "$archive_name"
    fi

    # Install files
    log_info "Installing files..."

    # Find kernel binary
    local kernel_bin
    if [[ -f "kernel.bin" ]]; then
        kernel_bin="kernel.bin"
    elif [[ -f "gcc/kernel.bin" ]]; then
        kernel_bin="gcc/kernel.bin"
    elif [[ -f "clang/kernel-clang.bin" ]]; then
        kernel_bin="clang/kernel-clang.bin"
    elif [[ -f "${arch}/kernel-${arch}.bin" ]]; then
        kernel_bin="${arch}/kernel-${arch}.bin"
    else
        log_error "Kernel binary not found in archive"
        exit 1
    fi

    # Copy files
    cp "$kernel_bin" "$CLOUDOS_INSTALL_DIR/cloudos-kernel"
    chmod +x "$CLOUDOS_INSTALL_DIR/cloudos-kernel"

    # Copy ISO if available
    if [[ -f "cloudos.iso" ]]; then
        cp "cloudos.iso" "$CLOUDOS_INSTALL_DIR/"
    fi

    # Create version file
    echo "$version" > "$CLOUDOS_INSTALL_DIR/VERSION"

    # Create symlink for easy access
    if [[ -w "/usr/local/bin" ]]; then
        ln -sf "$CLOUDOS_INSTALL_DIR/cloudos-kernel" "/usr/local/bin/cloudos"
    elif [[ -w "$HOME/.local/bin" ]]; then
        mkdir -p "$HOME/.local/bin"
        ln -sf "$CLOUDOS_INSTALL_DIR/cloudos-kernel" "$HOME/.local/bin/cloudos"
    fi

    log_success "CloudOS $version installed successfully!"

    # Show installation info
    echo
    echo "📦 Installation complete!"
    echo "🔧 Install location: $CLOUDOS_INSTALL_DIR"
    echo "📖 Documentation: https://docs.cloudos.dev"
    echo "🚀 CLI: cloudos --help"
    echo

    # Show next steps
    echo "Next steps:"
    echo "1. Add $CLOUDOS_INSTALL_DIR to your PATH (if not using system location)"
    echo "2. Run 'cloudos --version' to verify installation"
    echo "3. Check out the documentation for getting started"
}

# Main execution
main() {
    echo "🚀 CloudOS Universal Installer"
    echo "Version: $CLOUDOS_VERSION"
    echo "Architecture: $(detect_system)"
    echo "Install Directory: $CLOUDOS_INSTALL_DIR"
    echo

    check_requirements
    install_cloudos
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
EOF

# Create version-specific install script template
cat > "$PROJECT_ROOT/install/install-version.sh" << 'EOF'
#!/bin/bash
# CloudOS Version-Specific Installer Template
# This template is used to generate version-specific install scripts

export CLOUDOS_VERSION="{{VERSION}}"
curl -sSL https://raw.githubusercontent.com/CloudOSProject/CloudOS/main/install/install.sh | bash
EOF

# Create simple redirect script for latest
cat > "$PROJECT_ROOT/install/latest.sh" << 'EOF'
#!/bin/bash
# CloudOS Latest Installer Redirect
curl -sSL https://raw.githubusercontent.com/CloudOSProject/CloudOS/main/install/install.sh | bash
EOF

# Create a simple web server script for local testing
cat > "$PROJECT_ROOT/install/serve.py" << 'EOF'
#!/usr/bin/env python3
"""
Simple HTTP server for testing install endpoint locally
Usage: python3 serve.py [port]
"""

import http.server
import socketserver
import sys
import os
from pathlib import Path

# Change to install directory
os.chdir(Path(__file__).parent)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

class InstallHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Route root to install.sh
        if self.path == '/':
            self.path = '/install.sh'
        elif self.path == '/latest':
            self.path = '/latest.sh'

        return super().do_GET()

with socketserver.TCPServer(("", PORT), InstallHandler) as httpd:
    print(f"Serving CloudOS install endpoint at http://localhost:{PORT}")
    print(f"Test with: curl -sSL http://localhost:{PORT} | bash")
    httpd.serve_forever()
EOF

# Create GitHub Pages configuration
cat > "$PROJECT_ROOT/install/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudOS Install</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
            color: #333;
        }
        .hero {
            text-align: center;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .install-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .install-command {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Monaco', 'Menlo', monospace;
            overflow-x: auto;
        }
        .copy-btn {
            background: #4299e1;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            float: right;
            margin-top: -5px;
        }
        .copy-btn:hover {
            background: #3182ce;
        }
    </style>
</head>
<body>
    <div class="hero">
        <h1>🚀 CloudOS</h1>
        <p>AI-Powered Cloud Operating System</p>
    </div>

    <div class="install-box">
        <h2>Quick Install</h2>
        <p>Install the latest version of CloudOS with a single command:</p>
        <div class="install-command">
            <button class="copy-btn" onclick="copyToClipboard('curl -sSL https://install.cloudos.dev | bash')">Copy</button>
            curl -sSL https://install.cloudos.dev | bash
        </div>
    </div>

    <div class="install-box">
        <h2>Custom Installation</h2>
        <p>Customize your installation with environment variables:</p>
        <div class="install-command">
            <button class="copy-btn" onclick="copyToClipboard('CLOUDOS_INSTALL_DIR=$HOME/.local/cloudos CLOUDOS_VERSION=v1.0.0 curl -sSL https://install.cloudos.dev | bash')">Copy</button>
            CLOUDOS_INSTALL_DIR=$HOME/.local/cloudos \<br>
            CLOUDOS_VERSION=v1.0.0 \<br>
            curl -sSL https://install.cloudos.dev | bash
        </div>
    </div>

    <div class="install-box">
        <h2>Options</h2>
        <ul>
            <li><code>CLOUDOS_VERSION</code> - Specific version to install (default: latest)</li>
            <li><code>CLOUDOS_INSTALL_DIR</code> - Installation directory (default: /opt/cloudos)</li>
            <li><code>CLOUDOS_ARCH</code> - Force architecture (x86_64, arm64, armv7)</li>
            <li><code>FORCE_INSTALL</code> - Force reinstall (default: false)</li>
        </ul>
    </div>

    <div class="install-box">
        <h2>Manual Download</h2>
        <p>Download specific artifacts from GitHub releases:</p>
        <ul>
            <li><a href="https://github.com/CloudOSProject/CloudOS/releases">All Releases</a></li>
            <li><a href="https://github.com/CloudOSProject/CloudOS/releases/latest">Latest Release</a></li>
        </ul>
    </div>

    <div class="install-box">
        <h2>Verify Installation</h2>
        <div class="install-command">
            cloudos --version
        </div>
    </div>

    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('Copied to clipboard!');
            });
        }
    </script>
</body>
</html>
EOF

# Create README for install directory
cat > "$PROJECT_ROOT/install/README.md" << 'EOF'
# CloudOS Install Endpoint

This directory contains the installation infrastructure for CloudOS.

## Files

- `install.sh` - Universal installation script
- `latest.sh` - Redirect script for latest version
- `install-version.sh` - Template for version-specific installers
- `serve.py` - Local test server
- `index.html` - Web interface for install.cloudos.dev

## Usage

### Production Deployment

The install endpoint (install.cloudos.dev) serves the `install.sh` script directly:

```bash
curl -sSL https://install.cloudos.dev | bash
```

### Local Testing

Start local server for testing:

```bash
cd install/
python3 serve.py 8080
```

Test locally:

```bash
curl -sSL http://localhost:8080 | bash
```

### Environment Variables

- `CLOUDOS_VERSION` - Version to install (default: latest)
- `CLOUDOS_INSTALL_DIR` - Installation directory (default: /opt/cloudos)
- `CLOUDOS_ARCH` - Force architecture detection
- `FORCE_INSTALL` - Force reinstallation

### GitHub Pages Setup

1. Enable GitHub Pages for the repository
2. Set source to the `install/` directory
3. Configure custom domain: install.cloudos.dev
4. Ensure HTTPS is enabled

### CDN Configuration

For production, consider using a CDN like CloudFlare to cache and serve the install scripts globally.
EOF

chmod +x "$PROJECT_ROOT/install"/*.sh "$PROJECT_ROOT/install/serve.py"

log_success "Install endpoint setup complete!"
log_info "Files created in: $PROJECT_ROOT/install/"
log_info "Test locally with: cd install && python3 serve.py"