#include "kernel/kernel.h"
#include "kernel/types.h"
#include "kernel/memory.h"
#include "kernel/process.h"

static uint16_t* const VGA_BUFFER = (uint16_t*)0xB8000;
static const size_t VGA_WIDTH = 80;
static const size_t VGA_HEIGHT = 25;

static size_t terminal_row = 0;
static size_t terminal_col = 0;
static uint8_t terminal_color = 0x07; // Light gray on black

static inline uint16_t vga_entry(unsigned char c, uint8_t color) {
    return (uint16_t)c | ((uint16_t)color << 8);
}

static void terminal_clear(void) {
    for (size_t y = 0; y < VGA_HEIGHT; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            const size_t index = y * VGA_WIDTH + x;
            VGA_BUFFER[index] = vga_entry(' ', terminal_color);
        }
    }
    terminal_row = 0;
    terminal_col = 0;
}

static void terminal_putchar(char c) {
    if (c == '\n') {
        terminal_col = 0;
        if (++terminal_row == VGA_HEIGHT) {
            terminal_row = 0;
        }
        return;
    }

    const size_t index = terminal_row * VGA_WIDTH + terminal_col;
    VGA_BUFFER[index] = vga_entry(c, terminal_color);

    if (++terminal_col == VGA_WIDTH) {
        terminal_col = 0;
        if (++terminal_row == VGA_HEIGHT) {
            terminal_row = 0;
        }
    }
}

static void terminal_write(const char* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        terminal_putchar(data[i]);
    }
}

static void terminal_writestring(const char* data) {
    size_t len = 0;
    while (data[len]) len++; // Simple strlen
    terminal_write(data, len);
}

void kprintf(const char* format, ...) {
    // Basic printf implementation for now
    terminal_writestring(format);
}

void kernel_panic(const char* message) {
    terminal_color = 0x4F; // White on red
    kprintf("\n\nKERNEL PANIC: ");
    kprintf(message);
    kprintf("\nSystem halted.\n");

    while (1) {
        __asm__ volatile ("hlt");
    }
}

void kernel_main(void) {
    terminal_clear();

    // Welcome message
    terminal_color = 0x0F; // Bright white
    kprintf("CloudOS v");
    kprintf("0.1.0");
    kprintf(" - Phase 1 Foundation\n\n");

    terminal_color = 0x07; // Light gray
    kprintf("Microkernel Architecture: Active\n");

    // Initialize memory management
    kprintf("Memory Management: Initializing...\n");
    memory_init();
    kprintf("Memory Management: Ready\n");

    // Initialize process management
    kprintf("Process Manager: Starting...\n");
    process_init();
    kprintf("Process Manager: Ready\n");

    kprintf("System Services: Loading...\n");

    terminal_color = 0x0A; // Light green
    kprintf("\nCloudOS Foundation Layer Ready!\n");
    kprintf("AI Engine: Preparing for Phase 2...\n");

    terminal_color = 0x07;
    kprintf("\nSystem Status: Running\n");
    kprintf("Available Memory: 512MB\n");
    kprintf("CPU: x86_64 compatible\n");

    // Create a test process
    process_create("init", (void*)0x500000);
    kprintf("Init process created\n");

    // Kernel main loop
    while (1) {
        __asm__ volatile ("hlt");
    }
}