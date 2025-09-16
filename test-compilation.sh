#!/bin/bash

# CloudOS Compilation Test Script
# This script tests compilation of all kernel modules individually

echo "=== CloudOS Compilation Test ==="
echo "Testing individual module compilation..."

CC="clang"
CFLAGS="-target x86_64-unknown-none -fno-builtin -fno-stack-protector -Wall -Wextra -Werror -c -Ikernel/include -std=c11 -ffreestanding -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -nostdlib"

TEST_DIR="build/test"
mkdir -p "$TEST_DIR"

# Test all C source files
MODULES=(
    "kernel/kernel.c"
    "kernel/microkernel.c"
    "kernel/memory/memory.c"
    "kernel/memory/vmm.c"
    "kernel/process/process.c"
    "kernel/syscall/syscall.c"
    "kernel/hal/hal.c"
    "kernel/hal/x86_64_stubs.c"
    "kernel/hal/aarch64_stubs.c"
    "kernel/device/device.c"
    "kernel/device/console.c"
    "kernel/device/keyboard.c"
    "kernel/device/null.c"
)

SUCCESS_COUNT=0
TOTAL_COUNT=${#MODULES[@]}

echo ""
for MODULE in "${MODULES[@]}"; do
    MODULE_NAME=$(basename "$MODULE" .c)
    OUTPUT_FILE="$TEST_DIR/${MODULE_NAME}.o"

    printf "Testing %-25s ... " "$MODULE_NAME"

    if $CC $CFLAGS -o "$OUTPUT_FILE" "$MODULE" 2>/dev/null; then
        echo "✅ PASS"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "❌ FAIL"
        echo "  Error details:"
        $CC $CFLAGS -o "$OUTPUT_FILE" "$MODULE" 2>&1 | sed 's/^/    /'
    fi
done

echo ""
echo "=== Compilation Results ==="
echo "✅ Successful: $SUCCESS_COUNT/$TOTAL_COUNT modules"
echo "❌ Failed:     $((TOTAL_COUNT - SUCCESS_COUNT))/$TOTAL_COUNT modules"

if [ $SUCCESS_COUNT -eq $TOTAL_COUNT ]; then
    echo ""
    echo "🎉 ALL MODULES COMPILED SUCCESSFULLY!"
    echo ""
    echo "Total object file size: $(du -sh $TEST_DIR 2>/dev/null | cut -f1)"
    echo "Individual module sizes:"
    ls -lah "$TEST_DIR"/*.o 2>/dev/null | awk '{print "  " $9 ": " $5}' | sed 's|'$TEST_DIR'/||g'

    echo ""
    echo "✅ Phase 1.1 Microkernel Development - All C code compiles without errors!"
    echo "Note: Final linking may require Linux environment or cross-compiler setup."
else
    echo ""
    echo "❌ Some modules failed to compile. Check errors above."
    exit 1
fi

# Clean up test directory
rm -rf "$TEST_DIR"