# CloudOS Build System
# Phase 1: Foundation

# Detect host OS
UNAME_S := $(shell uname -s)

# Set compiler based on host OS
ifeq ($(UNAME_S),Darwin)
    # macOS with cross-compilation
    CC = clang
    AS = nasm
    LD = ld
    CFLAGS = -target x86_64-unknown-none -fno-builtin -fno-stack-protector \
             -Wall -Wextra -Werror -c -Ikernel/include -std=c11 -ffreestanding \
             -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -nostdlib
    LDFLAGS = -nostdlib -e _start -static
else
    # Linux with native compilation
    CC = gcc
    AS = nasm
    LD = ld
    CFLAGS = -m64 -nostdlib -nostdinc -fno-builtin -fno-stack-protector \
             -nostartfiles -nodefaultlibs -Wall -Wextra -Werror -c \
             -Ikernel/include -std=c11 -ffreestanding -mno-red-zone \
             -mno-mmx -mno-sse -mno-sse2 -mcmodel=kernel
    LDFLAGS = -T kernel/arch/$(TARGET_ARCH)/linker.ld -nostdlib -z max-page-size=0x1000
endif

# Architecture detection
ARCH ?= x86_64
TARGET_ARCH = $(ARCH)

ASFLAGS = -f elf64

# Directories
KERNEL_DIR = kernel
BUILD_DIR = build
ISO_DIR = $(BUILD_DIR)/iso

# Kernel source files
KERNEL_SOURCES = $(shell find $(KERNEL_DIR) -name "*.c")
KERNEL_ASM_SOURCES = $(shell find $(KERNEL_DIR) -name "*.asm")
KERNEL_OBJECTS = $(KERNEL_SOURCES:%.c=$(BUILD_DIR)/%.o) \
                 $(KERNEL_ASM_SOURCES:%.asm=$(BUILD_DIR)/%.o)

# Default target
all: kernel

# Kernel build
kernel: $(BUILD_DIR)/cloudos-kernel.bin

$(BUILD_DIR)/cloudos-kernel.bin: $(KERNEL_OBJECTS)
	@mkdir -p $(dir $@)
ifeq ($(UNAME_S),Darwin)
	clang -target x86_64-unknown-none -nostdlib $(LDFLAGS) -o $@ $^
else
	$(LD) $(LDFLAGS) -o $@ $^
endif

# C source compilation
$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $<

# Assembly source compilation
$(BUILD_DIR)/%.o: %.asm
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -o $@ $<

# ISO image creation
iso: $(BUILD_DIR)/cloudos.iso

$(BUILD_DIR)/cloudos.iso: kernel
	@mkdir -p $(ISO_DIR)/boot/grub
	cp $(BUILD_DIR)/cloudos-kernel.bin $(ISO_DIR)/boot/
	echo 'set timeout=0' > $(ISO_DIR)/boot/grub/grub.cfg
	echo 'set default=0' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo '' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo 'menuentry "CloudOS" {' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo '    multiboot2 /boot/cloudos-kernel.bin' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo '    boot' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo '}' >> $(ISO_DIR)/boot/grub/grub.cfg
	grub-mkrescue -o $@ $(ISO_DIR) 2>/dev/null || echo "Warning: grub-mkrescue not available"

# QEMU testing
run: iso
	qemu-system-x86_64 -cdrom $(BUILD_DIR)/cloudos.iso -m 512M -serial stdio

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Development tools
format:
	find $(KERNEL_DIR) -name "*.c" -o -name "*.h" | xargs clang-format -i

lint:
	cppcheck --enable=all --error-exitcode=1 $(KERNEL_DIR)

# Help
help:
	@echo "CloudOS Build System"
	@echo "Available targets:"
	@echo "  all     - Build kernel (default)"
	@echo "  kernel  - Build kernel binary"
	@echo "  iso     - Create bootable ISO image"
	@echo "  run     - Run in QEMU emulator"
	@echo "  clean   - Clean build artifacts"
	@echo "  format  - Format source code"
	@echo "  lint    - Run static analysis"
	@echo "  help    - Show this help"

.PHONY: all kernel iso run clean format lint help