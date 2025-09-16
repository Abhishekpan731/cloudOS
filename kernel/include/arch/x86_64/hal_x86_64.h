#ifndef ARCH_X86_64_HAL_H
#define ARCH_X86_64_HAL_H

#include "kernel/types.h"

#define X86_64_PAGE_SIZE        4096
#define X86_64_CACHE_LINE_SIZE  64

#define MSR_EFER               0xC0000080
#define MSR_STAR               0xC0000081
#define MSR_LSTAR              0xC0000082
#define MSR_CSTAR              0xC0000083
#define MSR_SFMASK             0xC0000084

#define CR0_PE                 (1 << 0)
#define CR0_MP                 (1 << 1)
#define CR0_EM                 (1 << 2)
#define CR0_TS                 (1 << 3)
#define CR0_ET                 (1 << 4)
#define CR0_NE                 (1 << 5)
#define CR0_WP                 (1 << 16)
#define CR0_AM                 (1 << 18)
#define CR0_NW                 (1 << 29)
#define CR0_CD                 (1 << 30)
#define CR0_PG                 (1U << 31)

#define CR4_VME                (1 << 0)
#define CR4_PVI                (1 << 1)
#define CR4_TSD                (1 << 2)
#define CR4_DE                 (1 << 3)
#define CR4_PSE                (1 << 4)
#define CR4_PAE                (1 << 5)
#define CR4_MCE                (1 << 6)
#define CR4_PGE                (1 << 7)
#define CR4_PCE                (1 << 8)
#define CR4_OSFXSR             (1 << 9)
#define CR4_OSXMMEXCPT         (1 << 10)
#define CR4_UMIP               (1 << 11)
#define CR4_VMXE               (1 << 13)
#define CR4_SMXE               (1 << 14)
#define CR4_FSGSBASE           (1 << 16)
#define CR4_PCIDE              (1 << 17)
#define CR4_OSXSAVE            (1 << 18)
#define CR4_SMEP               (1 << 20)
#define CR4_SMAP               (1 << 21)
#define CR4_PKE                (1 << 22)

typedef struct {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint64_t cs, ss, ds, es, fs, gs;
} x86_64_context_t;

static inline uint64_t x86_64_read_cr0(void) {
    uint64_t val;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(val));
    return val;
}

static inline void x86_64_write_cr0(uint64_t val) {
    __asm__ volatile ("mov %0, %%cr0" :: "r"(val) : "memory");
}

static inline uint64_t x86_64_read_cr3(void) {
    uint64_t val;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(val));
    return val;
}

static inline void x86_64_write_cr3(uint64_t val) {
    __asm__ volatile ("mov %0, %%cr3" :: "r"(val) : "memory");
}

static inline uint64_t x86_64_read_cr4(void) {
    uint64_t val;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(val));
    return val;
}

static inline void x86_64_write_cr4(uint64_t val) {
    __asm__ volatile ("mov %0, %%cr4" :: "r"(val) : "memory");
}

static inline uint64_t x86_64_read_msr(uint32_t msr) {
    uint32_t low, high;
    __asm__ volatile ("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline void x86_64_write_msr(uint32_t msr, uint64_t val) {
    uint32_t low = val & 0xFFFFFFFF;
    uint32_t high = val >> 32;
    __asm__ volatile ("wrmsr" :: "a"(low), "d"(high), "c"(msr));
}

static inline uint64_t x86_64_rdtsc(void) {
    uint32_t low, high;
    __asm__ volatile ("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32) | low;
}

static inline void x86_64_invlpg(void* addr) {
    __asm__ volatile ("invlpg (%0)" :: "r"(addr) : "memory");
}

static inline void x86_64_cli(void) {
    __asm__ volatile ("cli");
}

static inline void x86_64_sti(void) {
    __asm__ volatile ("sti");
}

static inline void x86_64_hlt(void) {
    __asm__ volatile ("hlt");
}

static inline void x86_64_pause(void) {
    __asm__ volatile ("pause");
}

void x86_64_hal_init(void);
void x86_64_setup_gdt(void);
void x86_64_setup_idt(void);
void x86_64_setup_syscalls(void);

#endif
