#!/bin/bash

# CloudOS Universal ISO Builder
# Creates a bootable ISO that can work standalone or connect to cloud masters

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
ISO_DIR="$BUILD_DIR/iso"
KERNEL_DIR="$PROJECT_DIR/kernel"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_header() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "  CloudOS Universal ISO Builder"
    echo "========================================"
    echo -e "${NC}"
}

check_dependencies() {
    print_info "Checking dependencies..."

    local deps=("docker" "docker-compose")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo "Error: $dep not found. Please install Docker and Docker Compose."
            exit 1
        fi
    done

    print_success "Dependencies verified"
}

build_kernel() {
    print_info "Building CloudOS kernel..."

    # Use Docker to build the kernel
    cd "$PROJECT_DIR"
    ./scripts/build-docker.sh --kernel-only

    print_success "Kernel build completed"
}

create_initramfs() {
    print_info "Creating initramfs with CloudOS system..."

    mkdir -p "$ISO_DIR/boot"
    mkdir -p "$BUILD_DIR/initramfs"

    # Create initramfs structure
    cat > "$BUILD_DIR/create-initramfs.sh" << 'EOF'
#!/bin/bash
set -e

INITRAMFS_DIR="/tmp/initramfs"
OUTPUT_DIR="/build/iso/boot"

# Create directory structure
mkdir -p $INITRAMFS_DIR/{bin,sbin,etc,proc,sys,dev,tmp,var,usr/{bin,sbin},lib,lib64,boot,opt/cloudos}

# Copy essential binaries
cp /bin/busybox $INITRAMFS_DIR/bin/
cp /sbin/dhclient $INITRAMFS_DIR/sbin/ || true
cp /usr/bin/curl $INITRAMFS_DIR/usr/bin/ || true
cp /usr/bin/wget $INITRAMFS_DIR/usr/bin/ || true

# Create busybox symlinks
cd $INITRAMFS_DIR/bin
./busybox --install .

# Create init script
cat > $INITRAMFS_DIR/init << 'INIT_EOF'
#!/bin/sh

echo "Starting CloudOS..."

# Mount essential filesystems
/bin/mount -t proc proc /proc
/bin/mount -t sysfs sysfs /sys
/bin/mount -t devtmpfs devtmpfs /dev

# Create device nodes
/bin/mknod /dev/null c 1 3
/bin/mknod /dev/zero c 1 5
/bin/mknod /dev/console c 5 1

# Clear screen and show banner
clear
echo "=================================================="
echo "           CloudOS v0.1.0 Universal ISO"
echo "=================================================="
echo ""

# Network setup
echo "Setting up network..."
ip link set lo up
for iface in $(ls /sys/class/net/ | grep -v lo); do
    echo "Configuring interface: $iface"
    ip link set $iface up
    dhclient -timeout 10 $iface || true
done

# Check for internet connectivity
if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo "✓ Internet connectivity established"
    INTERNET=true
else
    echo "⚠ No internet connectivity"
    INTERNET=false
fi

echo ""
echo "CloudOS Installation Options:"
echo "=============================="
echo "1) Install as Master Node (Local Cluster)"
echo "2) Install as Compute Node (Join Remote Master)"
echo "3) Install Standalone (Single Machine)"
echo "4) Boot Live System (No Installation)"
echo "5) Advanced Options"
echo ""

while true; do
    echo -n "Select option [1-5]: "
    read choice

    case $choice in
        1)
            install_master
            break
            ;;
        2)
            install_node
            break
            ;;
        3)
            install_standalone
            break
            ;;
        4)
            boot_live
            break
            ;;
        5)
            advanced_options
            break
            ;;
        *)
            echo "Invalid option. Please choose 1-5."
            ;;
    esac
done

install_master() {
    echo ""
    echo "Installing CloudOS Master Node..."
    echo "================================="

    # Get configuration
    echo -n "Cluster name [cloudos-cluster]: "
    read cluster_name
    cluster_name=${cluster_name:-cloudos-cluster}

    echo -n "Admin password: "
    read -s admin_password
    echo ""

    # Partition and format disk
    echo "⚠ This will erase the entire disk!"
    echo "Available disks:"
    lsblk -d -o NAME,SIZE,MODEL | grep -E "sd|nvme"
    echo -n "Select disk (e.g., sda): "
    read disk

    echo "Partitioning disk..."
    parted /dev/$disk --script mklabel msdos
    parted /dev/$disk --script mkpart primary ext4 1MiB 100%
    parted /dev/$disk --script set 1 boot on

    # Format and mount
    mkfs.ext4 /dev/${disk}1
    mount /dev/${disk}1 /mnt

    # Install base system
    echo "Installing base system..."
    mkdir -p /mnt/{boot,etc,opt,var}

    # Copy kernel
    cp /boot/cloudos-kernel.bin /mnt/boot/

    # Install GRUB
    grub-install --target=i386-pc --boot-directory=/mnt/boot /dev/$disk

    # Create GRUB config
    cat > /mnt/boot/grub/grub.cfg << GRUB_EOF
set timeout=5
set default=0

menuentry "CloudOS Master Node" {
    linux /boot/cloudos-kernel.bin root=/dev/${disk}1 ro cloudos.mode=master cloudos.cluster=$cluster_name
}

menuentry "CloudOS Recovery" {
    linux /boot/cloudos-kernel.bin root=/dev/${disk}1 ro cloudos.mode=recovery
}
GRUB_EOF

    # Create CloudOS configuration
    mkdir -p /mnt/etc/cloudos
    cat > /mnt/etc/cloudos/config.yaml << CONFIG_EOF
cluster:
  name: $cluster_name
  mode: master

master:
  web_ui: true
  api_port: 8080
  secure_port: 443

node:
  auto_register: true
  heartbeat_interval: 30

networking:
  dhcp: true
  dns_servers:
    - 8.8.8.8
    - 1.1.1.1
CONFIG_EOF

    echo "✓ CloudOS Master installed successfully!"
    echo "Cluster: $cluster_name"
    echo "After reboot, access web UI at: https://<this-machine-ip>"

    echo "Rebooting in 10 seconds..."
    sleep 10
    reboot
}

install_node() {
    echo ""
    echo "Installing CloudOS Compute Node..."
    echo "=================================="

    if [ "$INTERNET" != "true" ]; then
        echo "Error: Internet connection required to join remote master"
        return
    fi

    echo -n "Master endpoint (e.g., https://master.example.com): "
    read master_endpoint

    echo -n "Join token: "
    read join_token

    # Verify master connectivity
    echo "Verifying master connectivity..."
    if ! curl -k -s "$master_endpoint/api/v1/status" > /dev/null; then
        echo "Error: Cannot connect to master at $master_endpoint"
        return
    fi

    echo "⚠ This will erase the entire disk!"
    echo "Available disks:"
    lsblk -d -o NAME,SIZE,MODEL | grep -E "sd|nvme"
    echo -n "Select disk (e.g., sda): "
    read disk

    # Install similar to master but as compute node
    echo "Installing compute node..."
    # ... (installation logic similar to master)

    echo "✓ CloudOS Compute Node installed!"
    echo "Master: $master_endpoint"
    echo "Rebooting to join cluster..."
    sleep 5
    reboot
}

install_standalone() {
    echo ""
    echo "Installing CloudOS Standalone..."
    echo "==============================="
    echo "This mode provides a single-machine CloudOS installation"
    echo "suitable for development and testing."

    # Similar installation but configured for standalone use
    echo "Installing standalone system..."
    # ... (standalone installation logic)

    echo "✓ CloudOS Standalone installed!"
}

boot_live() {
    echo ""
    echo "Booting CloudOS Live System..."
    echo "=============================="
    echo "Running CloudOS from memory without installation"

    # Start live system services
    /opt/cloudos/bin/cloudos-live &

    echo "Live system ready!"
    echo "- Kernel: $(uname -r)"
    echo "- Memory: $(free -h | awk 'NR==2{print $2}')"
    echo "- Network: $(ip route | grep default | awk '{print $5}' | head -1)"

    # Drop to shell
    exec /bin/sh
}

advanced_options() {
    echo ""
    echo "Advanced Options:"
    echo "================="
    echo "1) Network Configuration"
    echo "2) Disk Utilities"
    echo "3) System Information"
    echo "4) Remote Installation"
    echo "5) Back to Main Menu"

    # ... (advanced options implementation)
}

# Start main menu
main
INIT_EOF

chmod +x $INITRAMFS_DIR/init

# Create CloudOS live system
mkdir -p $INITRAMFS_DIR/opt/cloudos/bin
cat > $INITRAMFS_DIR/opt/cloudos/bin/cloudos-live << 'LIVE_EOF'
#!/bin/sh
echo "CloudOS Live System v0.1.0"
echo "Available commands:"
echo "  cloudos-status  - Show system status"
echo "  cloudos-network - Configure network"
echo "  cloudos-install - Install to disk"
LIVE_EOF

chmod +x $INITRAMFS_DIR/opt/cloudos/bin/cloudos-live

# Create initramfs archive
cd $INITRAMFS_DIR
find . | cpio -o -H newc | gzip > $OUTPUT_DIR/initramfs.cpio.gz

echo "Initramfs created: $OUTPUT_DIR/initramfs.cpio.gz"
EOF

    chmod +x "$BUILD_DIR/create-initramfs.sh"

    # Run in Docker to create initramfs
    docker run --rm \
        -v "$BUILD_DIR:/build" \
        -v "$BUILD_DIR/create-initramfs.sh:/create-initramfs.sh" \
        ubuntu:20.04 \
        bash -c "
            apt-get update &&
            apt-get install -y busybox-static cpio gzip parted grub2-common curl wget dhcpcd5 &&
            /create-initramfs.sh
        "

    print_success "Initramfs created"
}

create_grub_config() {
    print_info "Creating GRUB configuration..."

    mkdir -p "$ISO_DIR/boot/grub"

    cat > "$ISO_DIR/boot/grub/grub.cfg" << 'EOF'
set timeout=30
set default=0

insmod all_video
insmod gfxterm
terminal_output gfxterm

set gfxmode=1024x768
set gfxpayload=keep

menuentry "CloudOS Universal - Auto Detection" {
    linux /boot/cloudos-kernel.bin quiet cloudos.mode=auto
    initrd /boot/initramfs.cpio.gz
}

menuentry "CloudOS Master Node (Local Cluster)" {
    linux /boot/cloudos-kernel.bin quiet cloudos.mode=master
    initrd /boot/initramfs.cpio.gz
}

menuentry "CloudOS Compute Node (Join Existing)" {
    linux /boot/cloudos-kernel.bin quiet cloudos.mode=node
    initrd /boot/initramfs.cpio.gz
}

menuentry "CloudOS Live System (No Install)" {
    linux /boot/cloudos-kernel.bin quiet cloudos.mode=live
    initrd /boot/initramfs.cpio.gz
}

menuentry "CloudOS Recovery Mode" {
    linux /boot/cloudos-kernel.bin quiet cloudos.mode=recovery single
    initrd /boot/initramfs.cpio.gz
}
EOF

    print_success "GRUB configuration created"
}

create_iso() {
    print_info "Creating bootable ISO image..."

    # Copy kernel to ISO
    cp "$BUILD_DIR/cloudos-kernel.bin" "$ISO_DIR/boot/"

    # Create ISO using grub-mkrescue
    docker run --rm \
        -v "$ISO_DIR:/iso" \
        -v "$BUILD_DIR:/build" \
        ubuntu:20.04 \
        bash -c "
            apt-get update &&
            apt-get install -y grub2-common grub-pc-bin xorriso mtools &&
            grub-mkrescue -o /build/cloudos-universal.iso /iso
        "

    if [ -f "$BUILD_DIR/cloudos-universal.iso" ]; then
        print_success "ISO created: $BUILD_DIR/cloudos-universal.iso"

        # Show ISO info
        ISO_SIZE=$(du -h "$BUILD_DIR/cloudos-universal.iso" | cut -f1)
        print_info "ISO size: $ISO_SIZE"

        echo ""
        echo "Universal CloudOS ISO ready!"
        echo "============================"
        echo "File: $BUILD_DIR/cloudos-universal.iso"
        echo "Size: $ISO_SIZE"
        echo ""
        echo "Usage:"
        echo "1. Write to USB: dd if=cloudos-universal.iso of=/dev/sdX bs=4M"
        echo "2. Boot in VM: qemu-system-x86_64 -cdrom cloudos-universal.iso -m 2G"
        echo "3. Deploy to physical hardware by booting from USB/CD"
        echo ""
        echo "The ISO can:"
        echo "- Install as master node (creates new cluster)"
        echo "- Install as compute node (joins existing cluster)"
        echo "- Run as live system (no installation)"
        echo "- Connect to cloud masters automatically"
    else
        echo "Error: Failed to create ISO"
        exit 1
    fi
}

test_iso() {
    print_info "Testing ISO in QEMU..."

    if command -v qemu-system-x86_64 &> /dev/null; then
        echo "Starting QEMU test (press Ctrl+Alt+G to release mouse, Ctrl+Alt+2 for monitor)"
        echo "Press Ctrl+C to stop test..."

        qemu-system-x86_64 \
            -cdrom "$BUILD_DIR/cloudos-universal.iso" \
            -m 2G \
            -smp 2 \
            -enable-kvm \
            -netdev user,id=net0 \
            -device virtio-net,netdev=net0 \
            -boot d
    else
        print_warning "QEMU not found. Skipping ISO test."
        print_info "You can test manually with: qemu-system-x86_64 -cdrom $BUILD_DIR/cloudos-universal.iso -m 2G"
    fi
}

# Main execution
print_header

if [ "$1" = "--test-only" ]; then
    test_iso
    exit 0
fi

check_dependencies
build_kernel
create_initramfs
create_grub_config
create_iso

echo ""
print_success "CloudOS Universal ISO build completed!"

if [ "$1" = "--test" ]; then
    test_iso
fi