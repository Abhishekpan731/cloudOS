#!/bin/bash

# CloudOS Development Environment Setup
# This script sets up the necessary tools for CloudOS development

set -e

echo "Setting up CloudOS development environment..."

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Error: Homebrew is not installed. Please install Homebrew first."
    echo "Visit: https://brew.sh"
    exit 1
fi

# Install required packages
echo "Installing development tools..."
brew install nasm
brew install qemu
brew install grub
brew install xorriso

# Check if cross-compiler is available
if ! command -v x86_64-elf-gcc &> /dev/null; then
    echo "Cross-compiler not found. You have two options:"
    echo ""
    echo "1. Install via Homebrew (recommended):"
    echo "   brew install x86_64-elf-gcc x86_64-elf-binutils"
    echo ""
    echo "2. Use system GCC with modifications:"
    echo "   We can modify the Makefile to use system GCC with appropriate flags"
    echo ""
    read -p "Would you like to use system GCC instead? (y/n): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Modifying Makefile to use system GCC..."
        sed -i '' 's/x86_64-elf-gcc/gcc/g' ../Makefile
        sed -i '' 's/x86_64-elf-ld/ld/g' ../Makefile
        sed -i '' 's/x86_64-elf-objcopy/objcopy/g' ../Makefile
        echo "Makefile updated to use system tools."
    else
        echo "Please install the cross-compiler manually:"
        echo "brew install x86_64-elf-gcc x86_64-elf-binutils"
        exit 1
    fi
fi

echo ""
echo "Development environment setup complete!"
echo ""
echo "Available make targets:"
echo "  make kernel  - Build the kernel"
echo "  make iso     - Create bootable ISO"
echo "  make run     - Run in QEMU emulator"
echo "  make clean   - Clean build artifacts"
echo ""
echo "To get started:"
echo "  make kernel"
echo "  make run"