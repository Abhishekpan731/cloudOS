#!/bin/bash

echo "CloudOS Kernel Compilation Test"
echo "==============================="

COMPILE_FLAGS="-c -target x86_64-elf -ffreestanding -fno-stack-protector -mno-red-zone -I. -I./kernel/include -Wall -Wextra -std=c11"
SUCCESS_COUNT=0
TOTAL_COUNT=0

mkdir -p build

for file in $(find kernel -name "*.c" -type f | sort); do
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    basename_file=$(basename "$file" .c)
    echo -n "[$TOTAL_COUNT] Compiling $file... "

    if clang $COMPILE_FLAGS "$file" -o "build/${basename_file}.o" 2>/dev/null; then
        echo "✅ SUCCESS"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "❌ FAILED"
        echo "   Error details:"
        clang $COMPILE_FLAGS "$file" -o "build/${basename_file}.o" 2>&1 | head -5 | sed 's/^/   /'
    fi
done

echo ""
echo "Compilation Summary:"
echo "==================="
echo "Total files: $TOTAL_COUNT"
echo "Successful: $SUCCESS_COUNT"
echo "Failed: $((TOTAL_COUNT - SUCCESS_COUNT))"

if [ $SUCCESS_COUNT -eq $TOTAL_COUNT ]; then
    echo "✅ ALL MODULES COMPILED SUCCESSFULLY!"
else
    echo "❌ Some modules failed to compile"
fi

# Show total size of compiled objects
if [ $SUCCESS_COUNT -gt 0 ]; then
    total_size=$(du -ch build/*.o 2>/dev/null | tail -1 | cut -f1)
    echo "Total compiled size: $total_size"
fi