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
