#!/bin/bash

# Build CloudOS using Docker

set -e

echo "Building CloudOS in Docker environment..."

# Build the Docker image
docker-compose build

# Run the build
docker-compose run --rm cloudos-dev make clean
docker-compose run --rm cloudos-dev make kernel

echo "Build complete! Kernel binary: build/cloudos-kernel.bin"

# Optionally create ISO
read -p "Create bootable ISO? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker-compose run --rm cloudos-dev make iso
    echo "ISO created: build/cloudos.iso"
fi

# Optionally test in QEMU
read -p "Test in QEMU? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting QEMU (press Ctrl+C to exit)..."
    docker-compose run --rm cloudos-dev make run
fi