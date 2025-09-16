#include "kernel/hal.h"
#include "kernel/kernel.h"

static arch_info_t arch_info;
static memory_region_t memory_map[16];
static uint32_t memory_region_count = 0;

void hal_init(void) {
    kprintf("HAL: Initializing for %s\n", arch_info.arch_name);

    hal_cpu_init();
    hal_interrupt_init();
    hal_memory_init();
    hal_timer_init(1000); // 1kHz timer

    kprintf("HAL: Initialization complete\n");
}

arch_info_t* hal_get_arch_info(void) {
    return &arch_info;
}

memory_region_t* hal_get_memory_map(uint32_t* count) {
    *count = memory_region_count;
    return memory_map;
}

#ifdef __x86_64__

void hal_cpu_init(void) {
    arch_info.arch_name = "x86_64";
    arch_info.page_size = X86_64_PAGE_SIZE;
    arch_info.cache_line_size = X86_64_CACHE_LINE_SIZE;
    arch_info.has_mmu = true;
    arch_info.has_fpu = true;
    arch_info.cpu_count = 1; // TODO: detect SMP

    x86_64_hal_init();
    x86_64_setup_gdt();
    x86_64_setup_idt();
    x86_64_setup_syscalls();
}

void hal_interrupt_init(void) {
    // x86_64 interrupt initialization is done in x86_64_setup_idt()
}

void hal_timer_init(uint32_t frequency) {
    // Setup PIT timer
    uint32_t divisor = 1193180 / frequency;
    hal_outb(0x43, 0x36); // Command: channel 0, access mode lobyte/hibyte, mode 3
    hal_outb(0x40, divisor & 0xFF);
    hal_outb(0x40, divisor >> 8);
}

void hal_memory_init(void) {
    // Basic memory map for x86_64
    memory_map[0] = (memory_region_t){0x00000000, 0x000A0000, 1, 0}; // Low memory
    memory_map[1] = (memory_region_t){0x00100000, 0x1FF00000, 1, 0}; // High memory
    memory_region_count = 2;
}

void hal_enable_interrupts(void) {
    x86_64_sti();
}

void hal_disable_interrupts(void) {
    x86_64_cli();
}

void hal_halt(void) {
    x86_64_hlt();
}

void hal_cpu_relax(void) {
    x86_64_pause();
}

uint64_t hal_get_timestamp(void) {
    return x86_64_rdtsc();
}

void hal_delay_ms(uint32_t ms) {
    uint64_t start = hal_get_timestamp();
    uint64_t ticks_per_ms = 2000000; // Approximate for modern CPUs
    uint64_t target = start + (ms * ticks_per_ms);

    while (hal_get_timestamp() < target) {
        hal_cpu_relax();
    }
}

void hal_invalidate_page(void* addr) {
    x86_64_invlpg(addr);
}

void hal_flush_tlb(void) {
    uint64_t cr3 = x86_64_read_cr3();
    x86_64_write_cr3(cr3);
}

uint8_t hal_inb(uint16_t port) {
    uint8_t result;
    __asm__ volatile ("inb %1, %0" : "=a"(result) : "dN"(port));
    return result;
}

void hal_outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" :: "a"(value), "dN"(port));
}

uint16_t hal_inw(uint16_t port) {
    uint16_t result;
    __asm__ volatile ("inw %1, %0" : "=a"(result) : "dN"(port));
    return result;
}

void hal_outw(uint16_t port, uint16_t value) {
    __asm__ volatile ("outw %0, %1" :: "a"(value), "dN"(port));
}

uint32_t hal_inl(uint16_t port) {
    uint32_t result;
    __asm__ volatile ("inl %1, %0" : "=a"(result) : "dN"(port));
    return result;
}

void hal_outl(uint16_t port, uint32_t value) {
    __asm__ volatile ("outl %0, %1" :: "a"(value), "dN"(port));
}

void* hal_map_physical(uint64_t phys_addr, size_t size) {
    // Basic identity mapping for now
    (void)size;
    return (void*)phys_addr;
}

void hal_unmap_physical(void* virt_addr, size_t size) {
    // No-op for identity mapping
    (void)virt_addr;
    (void)size;
}

#elif defined(__aarch64__)

void hal_cpu_init(void) {
    arch_info.arch_name = "aarch64";
    arch_info.page_size = AARCH64_PAGE_SIZE;
    arch_info.cache_line_size = AARCH64_CACHE_LINE_SIZE;
    arch_info.has_mmu = true;
    arch_info.has_fpu = true;
    arch_info.cpu_count = 1; // TODO: detect SMP

    aarch64_hal_init();
    aarch64_setup_mmu();
    aarch64_setup_interrupts();
    aarch64_setup_timer();
}

void hal_interrupt_init(void) {
    // ARM64 interrupt initialization is done in aarch64_setup_interrupts()
}

void hal_timer_init(uint32_t frequency) {
    // ARM generic timer setup is done in aarch64_setup_timer()
    (void)frequency;
}

void hal_memory_init(void) {
    // Basic memory map for ARM64
    memory_map[0] = (memory_region_t){0x00000000, 0x40000000, 1, 0}; // 1GB RAM
    memory_region_count = 1;
}

void hal_enable_interrupts(void) {
    aarch64_enable_interrupts();
}

void hal_disable_interrupts(void) {
    aarch64_disable_interrupts();
}

void hal_halt(void) {
    aarch64_wfi();
}

void hal_cpu_relax(void) {
    aarch64_yield();
}

uint64_t hal_get_timestamp(void) {
    return aarch64_read_cntvct_el0();
}

void hal_delay_ms(uint32_t ms) {
    uint64_t freq = aarch64_read_cntfrq_el0();
    uint64_t start = aarch64_read_cntvct_el0();
    uint64_t target = start + (ms * freq / 1000);

    while (aarch64_read_cntvct_el0() < target) {
        hal_cpu_relax();
    }
}

void hal_invalidate_page(void* addr) {
    aarch64_tlbi_vaae1((uint64_t)addr);
}

void hal_flush_tlb(void) {
    aarch64_tlbi_vmalle1();
}

// ARM64 doesn't have port I/O - these are stubs
uint8_t hal_inb(uint16_t port) { (void)port; return 0; }
void hal_outb(uint16_t port, uint8_t value) { (void)port; (void)value; }
uint16_t hal_inw(uint16_t port) { (void)port; return 0; }
void hal_outw(uint16_t port, uint16_t value) { (void)port; (void)value; }
uint32_t hal_inl(uint16_t port) { (void)port; return 0; }
void hal_outl(uint16_t port, uint32_t value) { (void)port; (void)value; }

void* hal_map_physical(uint64_t phys_addr, size_t size) {
    // Basic identity mapping for now
    (void)size;
    return (void*)phys_addr;
}

void hal_unmap_physical(void* virt_addr, size_t size) {
    // No-op for identity mapping
    (void)virt_addr;
    (void)size;
}

#endif
