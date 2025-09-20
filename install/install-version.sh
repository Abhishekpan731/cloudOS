#!/bin/bash
# CloudOS Version-Specific Installer Template
# This template is used to generate version-specific install scripts

export CLOUDOS_VERSION="{{VERSION}}"
curl -sSL https://raw.githubusercontent.com/CloudOSProject/CloudOS/main/install/install.sh | bash
