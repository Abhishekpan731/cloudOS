# CloudOS Release Automation

This document describes the automated release system for CloudOS, including artifact creation, hosting, and distribution.

## Overview

The CloudOS release system consists of:

1. **GitHub Actions Workflows** - Automated CI/CD pipelines
2. **Release Scripts** - Local and automated release tooling
3. **Install Endpoint** - Universal installation system
4. **Artifact Hosting** - GitHub Releases and container registry

## Release Workflows

### 1. Main CI/CD Pipeline (`.github/workflows/ci.yml`)

Runs on every push and pull request:

- **Code Quality**: Linting, formatting, security scans
- **Kernel Build**: Multi-compiler builds (GCC, Clang)
- **AI Engine Tests**: Python tests and integration
- **Container Build**: Docker images for AI engine and CLI
- **Integration Tests**: Full system testing
- **Performance Tests**: Benchmark validation
- **Security Scanning**: Vulnerability assessment
- **Deployment Tests**: Kubernetes and Helm validation

### 2. Release Pipeline (`.github/workflows/release.yml`)

Triggered by git tags or manual dispatch:

- **Artifact Building**: Cross-platform kernel binaries and ISOs
- **Container Images**: Multi-architecture container builds
- **GitHub Release**: Automated release creation with artifacts
- **Install Endpoint**: Updates install.cloudos.dev

## Release Process

### Automatic Releases

1. **Commit with `[release]` message** to main branch
2. **CI pipeline validates** all tests and builds
3. **Version tag created** automatically (v1.0.X format)
4. **Release workflow triggered** by new tag
5. **Artifacts built and published** to GitHub Releases
6. **Container images pushed** to GitHub Container Registry
7. **Install endpoint updated** with latest version

### Manual Releases

#### Using GitHub Interface

1. Go to GitHub Actions → Release Automation
2. Click "Run workflow"
3. Enter version (e.g., `v1.2.0`)
4. Check "prerelease" if needed
5. Click "Run workflow"

#### Using Local Script

```bash
# Create a standard release
./scripts/release.sh v1.2.0

# Create a prerelease
./scripts/release.sh --prerelease v1.2.0-rc1

# Dry run (test without creating release)
./scripts/release.sh --dry-run v1.2.0

# Build artifacts only
./scripts/release.sh --build-only v1.2.0
```

## Artifact Types

### Kernel Binaries

- **GCC Build**: `kernel.bin` - Standard kernel binary
- **Clang Build**: `kernel-clang.bin` - Clang-compiled binary
- **ARM64 Build**: `kernel-arm64.bin` - ARM64 cross-compiled

### Bootable Images

- **ISO Image**: `cloudos.iso` - Bootable ISO for x86_64
- **QEMU Ready**: Tested with QEMU virtualization

### Archive Packages

- **x86_64 Package**: `cloudos-X.Y.Z-x86_64.tar.gz`
- **ARM64 Package**: `cloudos-X.Y.Z-arm64.tar.gz`
- **Universal Package**: `cloudos-X.Y.Z-universal.zip`

### Container Images

- **AI Engine**: `ghcr.io/cloudosproject/cloudos/ai-engine:version`
- **CLI Tools**: `ghcr.io/cloudosproject/cloudos/cli:version`

## Installation System

### Universal Installer

The main installation method uses a universal script:

```bash
# Install latest version
curl -sSL https://install.cloudos.dev | bash

# Install specific version
CLOUDOS_VERSION=v1.2.0 curl -sSL https://install.cloudos.dev | bash

# Custom install directory
CLOUDOS_INSTALL_DIR=$HOME/.local/cloudos curl -sSL https://install.cloudos.dev | bash
```

### Environment Variables

- `CLOUDOS_VERSION` - Version to install (default: latest)
- `CLOUDOS_INSTALL_DIR` - Installation directory (default: /opt/cloudos)
- `CLOUDOS_ARCH` - Force architecture (x86_64, arm64, armv7)
- `FORCE_INSTALL` - Force reinstallation (default: false)

### Install Endpoint Architecture

```
install.cloudos.dev
├── install.sh          # Universal installer script
├── latest.sh           # Latest version redirect
├── v1.0.0/            # Version-specific installers
│   └── install.sh
└── index.html         # Web interface
```

## Security

### Checksums

All artifacts include SHA256 and SHA512 checksums:

- `checksums.txt` - SHA256 checksums
- `checksums-sha512.txt` - SHA512 checksums

The installer automatically verifies checksums when available.

### Container Signing

Container images are signed and can be verified:

```bash
# Verify container signature (requires cosign)
cosign verify ghcr.io/cloudosproject/cloudos/ai-engine:v1.0.0
```

### Code Scanning

All releases include:

- **Trivy vulnerability scanning**
- **CodeQL security analysis**
- **Bandit Python security scanning**
- **Dependency vulnerability checks**

## Release Versioning

### Version Format

CloudOS uses semantic versioning: `vMAJOR.MINOR.PATCH[-PRERELEASE]`

- **Major**: Breaking changes or major milestones
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes and minor improvements
- **Prerelease**: `-rc1`, `-beta1`, `-alpha1`

### Version Bumping

Automatic versions increment patch number based on commit count:
- `v1.0.{commit_count}`

Manual versions should follow semantic versioning guidelines.

## Monitoring and Notifications

### Release Status

Monitor release status through:

- **GitHub Actions**: Workflow status and logs
- **GitHub Releases**: Published artifacts
- **Container Registry**: Image availability
- **Install Endpoint**: Service health

### Failure Handling

If a release fails:

1. Check GitHub Actions logs for errors
2. Fix issues in code or configuration
3. Re-run workflow or create new tag
4. Manual cleanup if necessary

## Configuration

### Repository Secrets

Required secrets for automation:

- `GITHUB_TOKEN` - Automatic GitHub token (provided)
- `DOCKER_REGISTRY_TOKEN` - Container registry access (if using external registry)

### Workflow Permissions

Required GitHub Actions permissions:

- **Contents**: write (for creating releases)
- **Packages**: write (for container registry)
- **Actions**: read (for workflow access)

## Troubleshooting

### Common Issues

1. **Build Failures**
   - Check compiler dependencies
   - Verify cross-compilation setup
   - Review build logs

2. **Container Push Failures**
   - Verify registry authentication
   - Check image size limits
   - Review network connectivity

3. **Install Script Issues**
   - Test with different architectures
   - Verify download URLs
   - Check checksum validation

### Debug Commands

```bash
# Test release script locally
./scripts/release.sh --dry-run --build-only v1.0.0

# Test install endpoint locally
cd install && python3 serve.py 8080

# Validate GitHub workflows
gh workflow list
gh workflow run release.yml --ref main

# Check container images
docker pull ghcr.io/cloudosproject/cloudos/ai-engine:latest
docker run --rm ghcr.io/cloudosproject/cloudos/ai-engine:latest --version
```

## Future Enhancements

### Planned Improvements

1. **Multi-Cloud Distribution** - CDN deployment for global availability
2. **Package Managers** - APT, YUM, Homebrew integration
3. **Auto-Update System** - Built-in update mechanism
4. **Binary Signing** - GPG signing for all artifacts
5. **Metrics Collection** - Download and usage analytics

### Integration Points

- **CI/CD Enhancement**: More comprehensive testing
- **Documentation**: Auto-generated changelogs
- **Security**: Enhanced vulnerability scanning
- **Performance**: Build optimization and caching

---

For questions or issues with the release system, please check the GitHub Issues or contact the development team.