#include "kernel/memory.h"
#include "kernel/kernel.h"
#include "kernel/hal.h"

#ifdef __x86_64__
#include "arch/x86_64/hal_x86_64.h"
#elif defined(__aarch64__)
#include "arch/aarch64/hal_aarch64.h"
#endif

uint64_t* kernel_pml4 = NULL;
static vm_area_t* vm_areas = NULL;
static uint64_t next_virtual_addr = VIRTUAL_BASE;

uint64_t* vmm_create_page_table(void) {
    uint64_t* pml4 = (uint64_t*)page_alloc();
    if (!pml4) {
        return NULL;
    }

    // Clear the page table
    for (int i = 0; i < PAGES_PER_TABLE; i++) {
        pml4[i] = 0;
    }

    // Copy kernel mappings from kernel PML4
    if (kernel_pml4) {
        // Copy higher half kernel mappings (entries 256-511)
        for (int i = 256; i < PAGES_PER_TABLE; i++) {
            pml4[i] = kernel_pml4[i];
        }
    }

    return pml4;
}

void vmm_destroy_page_table(uint64_t* pml4) {
    if (!pml4 || pml4 == kernel_pml4) {
        return;
    }

    // Free user space page tables (entries 0-255)
    for (int pml4_idx = 0; pml4_idx < 256; pml4_idx++) {
        if (pml4[pml4_idx] & PTE_PRESENT) {
            uint64_t* pdpt = (uint64_t*)(pml4[pml4_idx] & ADDR_MASK);

            for (int pdpt_idx = 0; pdpt_idx < PAGES_PER_TABLE; pdpt_idx++) {
                if (pdpt[pdpt_idx] & PTE_PRESENT) {
                    uint64_t* pd = (uint64_t*)(pdpt[pdpt_idx] & ADDR_MASK);

                    for (int pd_idx = 0; pd_idx < PAGES_PER_TABLE; pd_idx++) {
                        if (pd[pd_idx] & PTE_PRESENT) {
                            uint64_t* pt = (uint64_t*)(pd[pd_idx] & ADDR_MASK);
                            page_free(pt);
                        }
                    }
                    page_free(pd);
                }
            }
            page_free(pdpt);
        }
    }

    page_free(pml4);
}

static uint64_t* get_or_create_table(uint64_t* table, int index, uint64_t flags) {
    if (!(table[index] & PTE_PRESENT)) {
        uint64_t* new_table = (uint64_t*)page_alloc();
        if (!new_table) {
            return NULL;
        }

        // Clear new table
        for (int i = 0; i < PAGES_PER_TABLE; i++) {
            new_table[i] = 0;
        }

        table[index] = virt_to_phys((uint64_t)new_table) | flags | PTE_PRESENT;
    }

    return (uint64_t*)phys_to_virt(table[index] & ADDR_MASK);
}

int vmm_map_page(uint64_t* pml4, uint64_t virt, uint64_t phys, uint64_t flags) {
    if (!pml4) {
        return -1;
    }

    int pml4_idx = (virt >> 39) & 0x1FF;
    int pdpt_idx = (virt >> 30) & 0x1FF;
    int pd_idx = (virt >> 21) & 0x1FF;
    int pt_idx = (virt >> 12) & 0x1FF;

    // Get or create PDPT
    uint64_t* pdpt = get_or_create_table(pml4, pml4_idx, PTE_WRITE | PTE_USER);
    if (!pdpt) {
        return -1;
    }

    // Get or create PD
    uint64_t* pd = get_or_create_table(pdpt, pdpt_idx, PTE_WRITE | PTE_USER);
    if (!pd) {
        return -1;
    }

    // Get or create PT
    uint64_t* pt = get_or_create_table(pd, pd_idx, PTE_WRITE | PTE_USER);
    if (!pt) {
        return -1;
    }

    // Map the page
    pt[pt_idx] = (phys & ADDR_MASK) | flags | PTE_PRESENT;

    // Invalidate TLB entry
    hal_invalidate_page((void*)virt);

    return 0;
}

int vmm_unmap_page(uint64_t* pml4, uint64_t virt) {
    if (!pml4) {
        return -1;
    }

    int pml4_idx = (virt >> 39) & 0x1FF;
    int pdpt_idx = (virt >> 30) & 0x1FF;
    int pd_idx = (virt >> 21) & 0x1FF;
    int pt_idx = (virt >> 12) & 0x1FF;

    if (!(pml4[pml4_idx] & PTE_PRESENT)) {
        return -1;
    }

    uint64_t* pdpt = (uint64_t*)phys_to_virt(pml4[pml4_idx] & ADDR_MASK);
    if (!(pdpt[pdpt_idx] & PTE_PRESENT)) {
        return -1;
    }

    uint64_t* pd = (uint64_t*)phys_to_virt(pdpt[pdpt_idx] & ADDR_MASK);
    if (!(pd[pd_idx] & PTE_PRESENT)) {
        return -1;
    }

    uint64_t* pt = (uint64_t*)phys_to_virt(pd[pd_idx] & ADDR_MASK);
    if (!(pt[pt_idx] & PTE_PRESENT)) {
        return -1;
    }

    // Unmap the page
    pt[pt_idx] = 0;

    // Invalidate TLB entry
    hal_invalidate_page((void*)virt);

    return 0;
}

uint64_t vmm_get_physical(uint64_t* pml4, uint64_t virt) {
    if (!pml4) {
        return 0;
    }

    int pml4_idx = (virt >> 39) & 0x1FF;
    int pdpt_idx = (virt >> 30) & 0x1FF;
    int pd_idx = (virt >> 21) & 0x1FF;
    int pt_idx = (virt >> 12) & 0x1FF;

    if (!(pml4[pml4_idx] & PTE_PRESENT)) {
        return 0;
    }

    uint64_t* pdpt = (uint64_t*)phys_to_virt(pml4[pml4_idx] & ADDR_MASK);
    if (!(pdpt[pdpt_idx] & PTE_PRESENT)) {
        return 0;
    }

    uint64_t* pd = (uint64_t*)phys_to_virt(pdpt[pdpt_idx] & ADDR_MASK);
    if (!(pd[pd_idx] & PTE_PRESENT)) {
        return 0;
    }

    uint64_t* pt = (uint64_t*)phys_to_virt(pd[pd_idx] & ADDR_MASK);
    if (!(pt[pt_idx] & PTE_PRESENT)) {
        return 0;
    }

    return (pt[pt_idx] & ADDR_MASK) | (virt & 0xFFF);
}

void vmm_switch_page_table(uint64_t* pml4) {
#ifdef __x86_64__
    if (pml4) {
        x86_64_write_cr3(virt_to_phys((uint64_t)pml4));
    }
#elif defined(__aarch64__)
    if (pml4) {
        aarch64_write_ttbr0_el1(virt_to_phys((uint64_t)pml4));
    }
#endif
}

vm_area_t* vmm_find_area(uint64_t addr) {
    vm_area_t* area = vm_areas;
    while (area) {
        if (addr >= area->start && addr < area->end) {
            return area;
        }
        area = area->next;
    }
    return NULL;
}

int vmm_create_area(uint64_t start, uint64_t end, uint64_t flags) {
    vm_area_t* area = (vm_area_t*)kmalloc(sizeof(vm_area_t));
    if (!area) {
        return -1;
    }

    area->start = start;
    area->end = end;
    area->flags = flags;
    area->next = vm_areas;
    vm_areas = area;

    return 0;
}

int vmm_destroy_area(uint64_t start) {
    vm_area_t** current = &vm_areas;
    while (*current) {
        if ((*current)->start == start) {
            vm_area_t* to_free = *current;
            *current = (*current)->next;
            kfree(to_free);
            return 0;
        }
        current = &(*current)->next;
    }
    return -1;
}

void* vmalloc(size_t size) {
    size_t aligned_size = PAGE_ALIGN(size);
    uint64_t pages = aligned_size / PAGE_SIZE;

    uint64_t virt_addr = next_virtual_addr;
    next_virtual_addr += aligned_size;

    // Create VM area
    if (vmm_create_area(virt_addr, virt_addr + aligned_size, PTE_WRITE) < 0) {
        return NULL;
    }

    // Map pages
    for (uint64_t i = 0; i < pages; i++) {
        void* phys_page = page_alloc();
        if (!phys_page) {
            // Cleanup on failure
            for (uint64_t j = 0; j < i; j++) {
                vmm_unmap_page(kernel_pml4, virt_addr + j * PAGE_SIZE);
            }
            vmm_destroy_area(virt_addr);
            return NULL;
        }

        uint64_t phys_addr = virt_to_phys((uint64_t)phys_page);
        if (vmm_map_page(kernel_pml4, virt_addr + i * PAGE_SIZE, phys_addr, PTE_WRITE) < 0) {
            page_free(phys_page);
            // Cleanup on failure
            for (uint64_t j = 0; j < i; j++) {
                vmm_unmap_page(kernel_pml4, virt_addr + j * PAGE_SIZE);
            }
            vmm_destroy_area(virt_addr);
            return NULL;
        }
    }

    return (void*)virt_addr;
}

void vfree(void* ptr) {
    if (!ptr) {
        return;
    }

    uint64_t addr = (uint64_t)ptr;
    vm_area_t* area = vmm_find_area(addr);
    if (!area) {
        return;
    }

    // Unmap all pages in the area
    for (uint64_t virt = area->start; virt < area->end; virt += PAGE_SIZE) {
        uint64_t phys = vmm_get_physical(kernel_pml4, virt);
        if (phys) {
            page_free((void*)phys_to_virt(phys));
            vmm_unmap_page(kernel_pml4, virt);
        }
    }

    // Destroy the area
    vmm_destroy_area(area->start);
}

uint64_t virt_to_phys(uint64_t virt) {
    // For now, use identity mapping for kernel space
    if (virt >= KERNEL_VIRTUAL_BASE) {
        return virt - KERNEL_VIRTUAL_BASE;
    }
    return virt;
}

uint64_t phys_to_virt(uint64_t phys) {
    // For now, use identity mapping for kernel space
    return phys + KERNEL_VIRTUAL_BASE;
}
