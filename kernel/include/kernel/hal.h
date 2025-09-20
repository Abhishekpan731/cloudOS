#ifndef KERNEL_HAL_H
#define KERNEL_HAL_H

#include "types.h"

#ifdef __x86_64__
    #include "arch/x86_64/hal_x86_64.h"
#elif defined(__aarch64__)
    #include "arch/aarch64/hal_aarch64.h"
#else
    #error "Unsupported architecture"
#endif

typedef struct {
    uint64_t base_addr;
    uint64_t size;
    uint32_t type;
    uint32_t flags;
} memory_region_t;

typedef struct {
    const char* arch_name;
    uint32_t page_size;
    uint32_t cache_line_size;
    bool has_mmu;
    bool has_fpu;
    uint32_t cpu_count;
} arch_info_t;

void hal_init(void);
void hal_cpu_init(void);
void hal_interrupt_init(void);
void hal_timer_init_freq(uint32_t frequency);
void hal_memory_init(void);

void hal_enable_interrupts(void);
void hal_disable_interrupts(void);
void hal_halt(void);
void hal_cpu_relax(void);

uint64_t hal_get_timestamp(void);
void hal_delay_ms(uint32_t ms);

// Time-related HAL functions
uint64_t hal_get_timestamp_ns(void);
uint64_t hal_get_cpu_cycles(void);
uint64_t hal_get_cpu_frequency(void);
void hal_timer_init(void);
void hal_timer_set_frequency(uint32_t hz);
void hal_timer_interrupt_handler(void);

void hal_invalidate_page(void* addr);
void hal_flush_tlb(void);

arch_info_t* hal_get_arch_info(void);
memory_region_t* hal_get_memory_map(uint32_t* count);

uint8_t hal_inb(uint16_t port);
void hal_outb(uint16_t port, uint8_t value);
uint16_t hal_inw(uint16_t port);
void hal_outw(uint16_t port, uint16_t value);
uint32_t hal_inl(uint16_t port);
void hal_outl(uint16_t port, uint32_t value);

void* hal_map_physical(uint64_t phys_addr, size_t size);
void hal_unmap_physical(void* virt_addr, size_t size);

#endif
