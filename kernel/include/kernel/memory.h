#ifndef KERNEL_MEMORY_H
#define KERNEL_MEMORY_H

#include "types.h"

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGES_PER_TABLE 512
#define VIRTUAL_BASE 0xFFFF800000000000UL
#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000UL

#define PTE_PRESENT     (1UL << 0)
#define PTE_WRITE       (1UL << 1)
#define PTE_USER        (1UL << 2)
#define PTE_PWT         (1UL << 3)
#define PTE_PCD         (1UL << 4)
#define PTE_ACCESSED    (1UL << 5)
#define PTE_DIRTY       (1UL << 6)
#define PTE_PAT         (1UL << 7)
#define PTE_GLOBAL      (1UL << 8)
#define PTE_NX          (1UL << 63)

#define ADDR_MASK       0x000FFFFFFFFFF000UL
#define FLAGS_MASK      0xFFF0000000000FFFUL

typedef struct page {
    struct page* next;
    uint64_t flags;
    uint32_t ref_count;
    uint64_t virt_addr;
} page_t;

typedef struct vm_area {
    uint64_t start;
    uint64_t end;
    uint64_t flags;
    struct vm_area* next;
} vm_area_t;

void memory_init(void);
void* kmalloc(size_t size);
void kfree(void* ptr);
void* page_alloc(void);
void page_free(void* page);

uint64_t* vmm_create_page_table(void);
void vmm_destroy_page_table(uint64_t* pml4);
int vmm_map_page(uint64_t* pml4, uint64_t virt, uint64_t phys, uint64_t flags);
int vmm_unmap_page(uint64_t* pml4, uint64_t virt);
uint64_t vmm_get_physical(uint64_t* pml4, uint64_t virt);
void vmm_switch_page_table(uint64_t* pml4);

vm_area_t* vmm_find_area(uint64_t addr);
int vmm_create_area(uint64_t start, uint64_t end, uint64_t flags);
int vmm_destroy_area(uint64_t start);

void* vmalloc(size_t size);
void vfree(void* ptr);

uint64_t virt_to_phys(uint64_t virt);
uint64_t phys_to_virt(uint64_t phys);

#endif
