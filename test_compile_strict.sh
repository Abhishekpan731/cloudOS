#!/bin/bash

echo "CloudOS Kernel Strict Compilation Test"
echo "====================================="

STRICT_FLAGS="-c -target x86_64-elf -ffreestanding -fno-stack-protector -mno-red-zone -I. -I./kernel/include -Wall -Wextra -Werror -Wpedantic -Wstrict-prototypes -Wold-style-definition -std=c11"
SUCCESS_COUNT=0
TOTAL_COUNT=0
WARNINGS_COUNT=0

mkdir -p build_strict

echo "Using strict compilation flags with all warnings enabled..."
echo ""

for file in $(find kernel -name "*.c" -type f | sort); do
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    basename_file=$(basename "$file" .c)
    echo -n "[$TOTAL_COUNT] Strict compiling $file... "

    # First try with -Werror (treat warnings as errors)
    if clang $STRICT_FLAGS "$file" -o "build_strict/${basename_file}.o" 2>/dev/null; then
        echo "✅ SUCCESS"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        # Try without -Werror to see if it's just warnings
        RELAXED_FLAGS=$(echo $STRICT_FLAGS | sed 's/-Werror//')
        if clang $RELAXED_FLAGS "$file" -o "build_strict/${basename_file}_relaxed.o" 2>/dev/null; then
            echo "⚠️  WARNINGS"
            WARNINGS_COUNT=$((WARNINGS_COUNT + 1))
            echo "   Warning details:"
            clang $RELAXED_FLAGS "$file" -o "build_strict/${basename_file}_relaxed.o" 2>&1 | head -3 | sed 's/^/   /'
        else
            echo "❌ FAILED"
            echo "   Error details:"
            clang $STRICT_FLAGS "$file" -o "build_strict/${basename_file}.o" 2>&1 | head -3 | sed 's/^/   /'
        fi
    fi
done

echo ""
echo "Strict Compilation Summary:"
echo "=========================="
echo "Total files: $TOTAL_COUNT"
echo "Successful (no warnings): $SUCCESS_COUNT"
echo "With warnings: $WARNINGS_COUNT"
echo "Failed: $((TOTAL_COUNT - SUCCESS_COUNT - WARNINGS_COUNT))"

if [ $SUCCESS_COUNT -eq $TOTAL_COUNT ]; then
    echo "🎉 ALL MODULES COMPILED WITH ZERO WARNINGS!"
elif [ $((SUCCESS_COUNT + WARNINGS_COUNT)) -eq $TOTAL_COUNT ]; then
    echo "✅ All modules compiled (some with warnings)"
else
    echo "❌ Some modules failed to compile"
fi

# Show total size
if [ $SUCCESS_COUNT -gt 0 ]; then
    total_size=$(du -ch build_strict/*.o 2>/dev/null | tail -1 | cut -f1)
    echo "Total compiled size: $total_size"
fi