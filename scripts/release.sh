#!/bin/bash
# CloudOS Release Management Script
# Automates the release process with validation and artifact creation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
RELEASE_DIR="$PROJECT_ROOT/release"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
CloudOS Release Management Script

Usage: $0 [OPTIONS] VERSION

Options:
    -h, --help          Show this help message
    -d, --dry-run       Perform a dry run without creating actual release
    -p, --prerelease    Mark as prerelease
    -s, --skip-tests    Skip running tests before release
    -b, --build-only    Only build artifacts, don't create release
    -c, --clean         Clean build directory before starting

Arguments:
    VERSION             Release version (e.g., v1.0.0, 1.2.3)

Examples:
    $0 v1.0.0                    # Create release v1.0.0
    $0 --dry-run v1.1.0         # Test release process
    $0 --prerelease v1.0.0-rc1  # Create prerelease
    $0 --build-only v1.0.0      # Only build artifacts

EOF
}

# Parse command line arguments
DRY_RUN=false
PRERELEASE=false
SKIP_TESTS=false
BUILD_ONLY=false
CLEAN_BUILD=false
VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -p|--prerelease)
            PRERELEASE=true
            shift
            ;;
        -s|--skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        -*)
            log_error "Unknown option $1"
            show_help
            exit 1
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                log_error "Multiple versions specified"
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate version
if [[ -z "$VERSION" ]]; then
    log_error "Version is required"
    show_help
    exit 1
fi

# Normalize version (add 'v' prefix if not present)
if [[ ! "$VERSION" =~ ^v ]]; then
    VERSION="v$VERSION"
fi

# Validate version format
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[0-9]+)?)?$ ]]; then
    log_error "Invalid version format: $VERSION"
    log_error "Expected format: v1.2.3 or v1.2.3-rc1"
    exit 1
fi

log_info "Starting CloudOS release process for version $VERSION"

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    # Required tools
    local required_tools=("git" "make" "gcc" "clang" "nasm" "docker" "tar" "zip" "sha256sum")

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_deps+=("$tool")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Please install missing tools and try again"
        exit 1
    fi

    log_success "All dependencies found"
}

# Validate git state
validate_git_state() {
    log_info "Validating git state..."

    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "Not in a git repository"
        exit 1
    fi

    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        log_error "Uncommitted changes detected"
        log_error "Please commit or stash changes before creating a release"
        exit 1
    fi

    # Check if tag already exists
    if git tag -l | grep -q "^$VERSION$"; then
        log_error "Tag $VERSION already exists"
        exit 1
    fi

    # Check if we're on main or development branch
    local current_branch
    current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "main" && "$current_branch" != "abhi_dev" && "$current_branch" != "develop" ]]; then
        log_warning "Not on main/abhi_dev/develop branch (current: $current_branch)"
        if [[ "$DRY_RUN" == "false" ]]; then
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi

    log_success "Git state is clean"
}

# Run tests
run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        log_warning "Skipping tests as requested"
        return
    fi

    log_info "Running tests..."

    cd "$PROJECT_ROOT"

    # Run kernel build test
    if ! make clean && make kernel; then
        log_error "Kernel build failed"
        exit 1
    fi

    # Run AI engine tests if available
    if [[ -f "ai/requirements.txt" ]]; then
        log_info "Running AI engine tests..."
        cd ai/
        if command -v python3 &> /dev/null; then
            python3 -m pytest tests/ -v || log_warning "AI tests failed"
        fi
        cd "$PROJECT_ROOT"
    fi

    log_success "Tests completed"
}

# Clean build directory
clean_build() {
    if [[ "$CLEAN_BUILD" == "true" ]]; then
        log_info "Cleaning build directory..."
        rm -rf "$BUILD_DIR"
        rm -rf "$RELEASE_DIR"
    fi
}

# Build artifacts
build_artifacts() {
    log_info "Building release artifacts..."

    cd "$PROJECT_ROOT"

    # Create release directory
    mkdir -p "$RELEASE_DIR"

    # Build kernel with GCC
    log_info "Building kernel with GCC..."
    make clean
    make kernel VERBOSE=1
    mkdir -p "$RELEASE_DIR/gcc"
    cp build/kernel.bin "$RELEASE_DIR/gcc/"

    # Build kernel with Clang
    log_info "Building kernel with Clang..."
    make clean
    CC=clang make kernel VERBOSE=1
    mkdir -p "$RELEASE_DIR/clang"
    cp build/kernel.bin "$RELEASE_DIR/clang/kernel-clang.bin"

    # Build ISO
    log_info "Building ISO image..."
    make iso
    cp build/cloudos.iso "$RELEASE_DIR/"

    # Try to build ARM64 (cross-compile)
    log_info "Attempting ARM64 build..."
    if command -v aarch64-linux-gnu-gcc &> /dev/null; then
        make clean
        CC=aarch64-linux-gnu-gcc ARCH=arm64 make kernel || log_warning "ARM64 build failed"
        if [[ -f build/kernel.bin ]]; then
            mkdir -p "$RELEASE_DIR/arm64"
            cp build/kernel.bin "$RELEASE_DIR/arm64/kernel-arm64.bin"
        fi
    else
        log_warning "ARM64 cross-compiler not available, skipping ARM64 build"
    fi

    # Create installer script
    log_info "Creating installer script..."
    cat > "$RELEASE_DIR/install-cloudos.sh" << 'EOF'
#!/bin/bash
set -e

VERSION="${CLOUDOS_VERSION:-latest}"
INSTALL_DIR="${CLOUDOS_INSTALL_DIR:-/opt/cloudos}"
BASE_URL="https://github.com/CloudOSProject/CloudOS/releases/download"

echo "🚀 Installing CloudOS ${VERSION}"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download and install kernel
echo "📥 Downloading CloudOS kernel for $ARCH..."
if [ "$ARCH" = "x86_64" ]; then
    curl -L "$BASE_URL/${VERSION}/kernel.bin" -o /tmp/cloudos-kernel.bin
    curl -L "$BASE_URL/${VERSION}/cloudos.iso" -o /tmp/cloudos.iso
else
    curl -L "$BASE_URL/${VERSION}/kernel-${ARCH}.bin" -o /tmp/cloudos-kernel.bin
fi

# Install files
cp /tmp/cloudos-kernel.bin "$INSTALL_DIR/"
if [ -f /tmp/cloudos.iso ]; then
    cp /tmp/cloudos.iso "$INSTALL_DIR/"
fi

# Create symlinks
ln -sf "$INSTALL_DIR/cloudos-kernel.bin" /usr/local/bin/cloudos 2>/dev/null || echo "Note: Could not create symlink (run as root for system-wide install)"

# Set permissions
chmod +x "$INSTALL_DIR/cloudos-kernel.bin"

echo "✅ CloudOS ${VERSION} installed successfully!"
echo "📖 Documentation: https://docs.cloudos.dev"
echo "🔧 Install location: $INSTALL_DIR"
EOF
    chmod +x "$RELEASE_DIR/install-cloudos.sh"

    # Generate checksums
    log_info "Generating checksums..."
    cd "$RELEASE_DIR"
    find . -type f -name "*.bin" -o -name "*.iso" -o -name "*.sh" | xargs sha256sum > checksums.txt
    find . -type f -name "*.bin" -o -name "*.iso" -o -name "*.sh" | xargs sha512sum > checksums-sha512.txt

    # Create archives
    log_info "Creating release archives..."
    tar -czf "cloudos-${VERSION#v}-x86_64.tar.gz" gcc/kernel.bin cloudos.iso install-cloudos.sh checksums.txt
    tar -czf "cloudos-${VERSION#v}-clang.tar.gz" clang/kernel-clang.bin install-cloudos.sh checksums.txt

    if [[ -f "arm64/kernel-arm64.bin" ]]; then
        tar -czf "cloudos-${VERSION#v}-arm64.tar.gz" arm64/kernel-arm64.bin install-cloudos.sh checksums.txt
    fi

    zip -r "cloudos-${VERSION#v}-universal.zip" .

    cd "$PROJECT_ROOT"

    log_success "Artifacts built successfully"
}

# Create git tag and push
create_git_tag() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create git tag: $VERSION"
        return
    fi

    log_info "Creating git tag: $VERSION"

    # Create annotated tag
    git tag -a "$VERSION" -m "CloudOS Release $VERSION

This release includes:
- Optimized microkernel binary
- Bootable ISO image
- Cross-platform support (x86_64, ARM64)
- AI engine integration
- Container runtime capabilities

For installation instructions and documentation, visit:
https://docs.cloudos.dev"

    log_success "Git tag created: $VERSION"
}

# GitHub release
create_github_release() {
    if [[ "$BUILD_ONLY" == "true" ]]; then
        log_info "Build-only mode, skipping GitHub release"
        return
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create GitHub release for $VERSION"
        return
    fi

    log_info "Creating GitHub release..."

    # Check if gh CLI is available
    if ! command -v gh &> /dev/null; then
        log_warning "GitHub CLI (gh) not found. Skipping automatic release creation."
        log_info "Manual steps:"
        log_info "1. Push the tag: git push origin $VERSION"
        log_info "2. Create release on GitHub with artifacts in: $RELEASE_DIR"
        return
    fi

    # Generate release notes
    local release_notes="$RELEASE_DIR/release_notes.md"
    cat > "$release_notes" << EOF
## 🚀 CloudOS Release $VERSION

### 📦 What's Included

- **Kernel Binary**: Optimized microkernel for x86_64 and ARM64
- **Bootable ISO**: Ready-to-boot CloudOS image
- **Container Support**: AI Engine and runtime capabilities
- **Install Script**: One-command installation

### 🔧 Quick Installation

\`\`\`bash
# Quick install
curl -sSL https://install.cloudos.dev | bash

# Or download specific version
curl -sSL https://github.com/CloudOSProject/CloudOS/releases/download/$VERSION/install-cloudos.sh | bash
\`\`\`

### 🐳 Container Images

\`\`\`bash
# AI Engine
docker pull ghcr.io/cloudosproject/cloudos/ai-engine:$VERSION

# CLI Tools
docker pull ghcr.io/cloudosproject/cloudos/cli:$VERSION
\`\`\`

### 🔒 Checksums

\`\`\`
$(cat "$RELEASE_DIR/checksums.txt")
\`\`\`
EOF

    # Create release
    local prerelease_flag=""
    if [[ "$PRERELEASE" == "true" ]]; then
        prerelease_flag="--prerelease"
    fi

    gh release create "$VERSION" \
        --title "CloudOS $VERSION" \
        --notes-file "$release_notes" \
        $prerelease_flag \
        "$RELEASE_DIR"/*.tar.gz \
        "$RELEASE_DIR"/*.zip \
        "$RELEASE_DIR/install-cloudos.sh" \
        "$RELEASE_DIR/checksums.txt" \
        "$RELEASE_DIR/checksums-sha512.txt"

    log_success "GitHub release created: $VERSION"
}

# Main execution flow
main() {
    log_info "CloudOS Release Script Starting..."
    log_info "Version: $VERSION"
    log_info "Dry run: $DRY_RUN"
    log_info "Prerelease: $PRERELEASE"
    log_info "Build only: $BUILD_ONLY"

    check_dependencies
    validate_git_state
    clean_build
    run_tests
    build_artifacts
    create_git_tag
    create_github_release

    log_success "Release process completed successfully!"

    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "Release artifacts available in: $RELEASE_DIR"
        log_info "Next steps:"
        log_info "1. Verify the release on GitHub"
        log_info "2. Test the installation script"
        log_info "3. Update documentation if needed"
        log_info "4. Announce the release"
    fi
}

# Run main function
main "$@"