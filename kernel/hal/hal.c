#include "kernel/hal.h"
#include "kernel/kernel.h"
#include "kernel/time.h"

static arch_info_t arch_info;
static memory_region_t memory_map[16];
static uint32_t memory_region_count = 0;

void hal_init(void) {
    kprintf("HAL: Initializing for %s\n", arch_info.arch_name);

    hal_cpu_init();
    hal_interrupt_init();
    hal_memory_init();
    hal_timer_init_freq(1000); // 1kHz timer

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

void hal_timer_init_freq(uint32_t frequency) {
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

void hal_timer_init_freq(uint32_t frequency) {
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

// Common time-related HAL functions
static uint64_t boot_timestamp_ns = 0;
static uint64_t timer_frequency_hz = 1000;

uint64_t hal_get_timestamp_ns(void) {
#ifdef __x86_64__
    // Use TSC (Time Stamp Counter) for high-resolution timing
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    uint64_t tsc = ((uint64_t)hi << 32) | lo;

    // Convert TSC to nanoseconds
    // This is approximate - real implementation should calibrate TSC frequency
    return tsc / 3; // Assume ~3GHz CPU for now
#elif defined(__aarch64__)
    // Use ARM Generic Timer
    uint64_t freq = aarch64_read_cntfrq_el0();
    uint64_t count = aarch64_read_cntvct_el0();

    // Convert to nanoseconds
    return (count * 1000000000ULL) / freq;
#else
    // Fallback to millisecond precision
    return get_system_time_ms() * 1000000ULL;
#endif
}

uint64_t hal_get_cpu_cycles(void) {
#ifdef __x86_64__
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    return aarch64_read_cntvct_el0();
#else
    return 0;
#endif
}

uint64_t hal_get_cpu_frequency(void) {
#ifdef __x86_64__
    // For x86_64, we would typically calibrate this at boot
    // For now, return a reasonable default
    return 3000000000ULL; // 3 GHz
#elif defined(__aarch64__)
    return aarch64_read_cntfrq_el0();
#else
    return 1000000000ULL; // 1 GHz default
#endif
}

void hal_timer_init(void) {
    timer_frequency_hz = 1000; // 1kHz default
    boot_timestamp_ns = hal_get_timestamp_ns();

#ifdef __x86_64__
    // Initialize PIT or HPET timer
    hal_timer_init_x86();
#elif defined(__aarch64__)
    // ARM Generic Timer is usually initialized by firmware
    // We might need to configure the timer interrupt here
#endif
}

void hal_timer_set_frequency(uint32_t hz) {
    timer_frequency_hz = hz;

#ifdef __x86_64__
    // Reprogram PIT timer
    uint32_t divisor = 1193180 / hz;
    hal_outb(0x43, 0x36); // Command byte
    hal_outb(0x40, divisor & 0xFF); // Low byte
    hal_outb(0x40, (divisor >> 8) & 0xFF); // High byte
#elif defined(__aarch64__)
    // ARM Generic Timer frequency is usually fixed
    // We would configure the timer interrupt interval here
#endif
}

// Timer interrupt handler (should be called from architecture-specific interrupt handler)
void hal_timer_interrupt_handler(void) {
    timer_tick(); // Call the time subsystem
}

#ifdef __x86_64__
// x86-64 specific timer functions
void hal_timer_init_x86(void) {
    // Initialize PIT (Programmable Interval Timer)
    hal_timer_set_frequency(timer_frequency_hz);
}

// Read Real-Time Clock (CMOS)
uint8_t hal_rtc_read(uint8_t reg) {
    hal_outb(0x70, reg);
    return hal_inb(0x71);
}

void hal_rtc_write(uint8_t reg, uint8_t value) {
    hal_outb(0x70, reg);
    hal_outb(0x71, value);
}

bool rtc_available(void) {
    return true; // x86 systems typically have RTC
}

void rtc_read_time(datetime_t* dt) {
    if (!dt) return;

    // Read from CMOS RTC
    dt->second = hal_rtc_read(0x00);
    dt->minute = hal_rtc_read(0x02);
    dt->hour = hal_rtc_read(0x04);
    dt->day = hal_rtc_read(0x07);
    dt->month = hal_rtc_read(0x08);
    dt->year = hal_rtc_read(0x09) + 2000; // Assuming 21st century
    dt->nanosecond = 0;

    // Convert from BCD if necessary
    uint8_t status_b = hal_rtc_read(0x0B);
    if (!(status_b & 0x04)) {
        // BCD mode
        dt->second = (dt->second & 0x0F) + ((dt->second / 16) * 10);
        dt->minute = (dt->minute & 0x0F) + ((dt->minute / 16) * 10);
        dt->hour = (dt->hour & 0x0F) + ((dt->hour / 16) * 10);
        dt->day = (dt->day & 0x0F) + ((dt->day / 16) * 10);
        dt->month = (dt->month & 0x0F) + ((dt->month / 16) * 10);
        dt->year = (dt->year & 0x0F) + ((dt->year / 16) * 10) + 2000;
    }
}

void rtc_set_time(const datetime_t* dt) {
    if (!dt) return;

    // Convert to BCD if necessary
    uint8_t status_b = hal_rtc_read(0x0B);
    uint8_t second = dt->second;
    uint8_t minute = dt->minute;
    uint8_t hour = dt->hour;
    uint8_t day = dt->day;
    uint8_t month = dt->month;
    uint8_t year = dt->year - 2000;

    if (!(status_b & 0x04)) {
        // Convert to BCD
        second = (second % 10) + ((second / 10) * 16);
        minute = (minute % 10) + ((minute / 10) * 16);
        hour = (hour % 10) + ((hour / 10) * 16);
        day = (day % 10) + ((day / 10) * 16);
        month = (month % 10) + ((month / 10) * 16);
        year = (year % 10) + ((year / 10) * 16);
    }

    // Wait for update flag to clear
    while (hal_rtc_read(0x0A) & 0x80);

    // Write to CMOS RTC
    hal_rtc_write(0x00, second);
    hal_rtc_write(0x02, minute);
    hal_rtc_write(0x04, hour);
    hal_rtc_write(0x07, day);
    hal_rtc_write(0x08, month);
    hal_rtc_write(0x09, year);
}

#endif

#endif
