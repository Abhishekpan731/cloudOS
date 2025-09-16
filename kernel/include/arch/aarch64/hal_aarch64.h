#ifndef ARCH_AARCH64_HAL_H
#define ARCH_AARCH64_HAL_H

#include "kernel/types.h"

#define AARCH64_PAGE_SIZE       4096
#define AARCH64_CACHE_LINE_SIZE 64

#define SCTLR_EL1_M     (1 << 0)   // MMU enable
#define SCTLR_EL1_A     (1 << 1)   // Alignment check enable
#define SCTLR_EL1_C     (1 << 2)   // Data/unified cache enable
#define SCTLR_EL1_SA    (1 << 3)   // SP alignment check enable
#define SCTLR_EL1_I     (1 << 12)  // Instruction cache enable
#define SCTLR_EL1_WXN   (1 << 19)  // Write permission implies XN
#define SCTLR_EL1_EE    (1 << 25)  // Exception endianness

#define TCR_EL1_T0SZ_SHIFT  0
#define TCR_EL1_T1SZ_SHIFT  16
#define TCR_EL1_TG0_4KB     (0 << 14)
#define TCR_EL1_TG0_64KB    (1 << 14)
#define TCR_EL1_TG0_16KB    (2 << 14)
#define TCR_EL1_TG1_4KB     (0 << 30)
#define TCR_EL1_TG1_64KB    (1 << 30)
#define TCR_EL1_TG1_16KB    (2 << 30)

typedef struct {
    uint64_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint64_t x8, x9, x10, x11, x12, x13, x14, x15;
    uint64_t x16, x17, x18, x19, x20, x21, x22, x23;
    uint64_t x24, x25, x26, x27, x28, x29, x30;
    uint64_t sp, pc, pstate;
} aarch64_context_t;

static inline uint64_t aarch64_read_sctlr_el1(void) {
    uint64_t val;
    __asm__ volatile ("mrs %0, sctlr_el1" : "=r"(val));
    return val;
}

static inline void aarch64_write_sctlr_el1(uint64_t val) {
    __asm__ volatile ("msr sctlr_el1, %0" :: "r"(val));
    __asm__ volatile ("isb");
}

static inline uint64_t aarch64_read_ttbr0_el1(void) {
    uint64_t val;
    __asm__ volatile ("mrs %0, ttbr0_el1" : "=r"(val));
    return val;
}

static inline void aarch64_write_ttbr0_el1(uint64_t val) {
    __asm__ volatile ("msr ttbr0_el1, %0" :: "r"(val));
    __asm__ volatile ("isb");
}

static inline uint64_t aarch64_read_ttbr1_el1(void) {
    uint64_t val;
    __asm__ volatile ("mrs %0, ttbr1_el1" : "=r"(val));
    return val;
}

static inline void aarch64_write_ttbr1_el1(uint64_t val) {
    __asm__ volatile ("msr ttbr1_el1, %0" :: "r"(val));
    __asm__ volatile ("isb");
}

static inline uint64_t aarch64_read_tcr_el1(void) {
    uint64_t val;
    __asm__ volatile ("mrs %0, tcr_el1" : "=r"(val));
    return val;
}

static inline void aarch64_write_tcr_el1(uint64_t val) {
    __asm__ volatile ("msr tcr_el1, %0" :: "r"(val));
    __asm__ volatile ("isb");
}

static inline uint64_t aarch64_read_mair_el1(void) {
    uint64_t val;
    __asm__ volatile ("mrs %0, mair_el1" : "=r"(val));
    return val;
}

static inline void aarch64_write_mair_el1(uint64_t val) {
    __asm__ volatile ("msr mair_el1, %0" :: "r"(val));
    __asm__ volatile ("isb");
}

static inline void aarch64_tlbi_vmalle1(void) {
    __asm__ volatile ("tlbi vmalle1" ::: "memory");
    __asm__ volatile ("dsb sy");
    __asm__ volatile ("isb");
}

static inline void aarch64_tlbi_vaae1(uint64_t addr) {
    __asm__ volatile ("tlbi vaae1, %0" :: "r"(addr >> 12) : "memory");
    __asm__ volatile ("dsb sy");
    __asm__ volatile ("isb");
}

static inline void aarch64_enable_interrupts(void) {
    __asm__ volatile ("msr daifclr, #2" ::: "memory");
}

static inline void aarch64_disable_interrupts(void) {
    __asm__ volatile ("msr daifset, #2" ::: "memory");
}

static inline void aarch64_wfi(void) {
    __asm__ volatile ("wfi");
}

static inline void aarch64_yield(void) {
    __asm__ volatile ("yield");
}

static inline uint64_t aarch64_read_cntvct_el0(void) {
    uint64_t val;
    __asm__ volatile ("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

static inline uint64_t aarch64_read_cntfrq_el0(void) {
    uint64_t val;
    __asm__ volatile ("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

void aarch64_hal_init(void);
void aarch64_setup_mmu(void);
void aarch64_setup_interrupts(void);
void aarch64_setup_timer(void);

#endif
