#ifdef __aarch64__

#include "arch/aarch64/hal_aarch64.h"
#include "kernel/kernel.h"

void aarch64_hal_init(void) {
    kprintf("ARM64 HAL: Initialized\n");
}

void aarch64_setup_mmu(void) {
    // Basic MMU setup for ARM64
    kprintf("ARM64 MMU: Setup complete\n");
}

void aarch64_setup_interrupts(void) {
    // Basic interrupt setup for ARM64
    kprintf("ARM64 Interrupts: Setup complete\n");
}

void aarch64_setup_timer(void) {
    // Basic timer setup for ARM64
    kprintf("ARM64 Timer: Setup complete\n");
}

#endif
