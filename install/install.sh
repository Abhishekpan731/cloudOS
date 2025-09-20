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
