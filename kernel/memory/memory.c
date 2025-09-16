#include "kernel/memory.h"
#include "kernel/kernel.h"

extern uint64_t* kernel_pml4;

static uint8_t* heap_start;
static uint8_t* heap_end;
static uint8_t* heap_current;
static const size_t HEAP_SIZE = 0x100000; // 1MB initial heap

typedef struct alloc_header {
    size_t size;
    bool free;
    struct alloc_header* next;
} alloc_header_t;

static alloc_header_t* free_list = NULL;

void memory_init(void) {
    // Simple heap allocator - starts after kernel
    heap_start = (uint8_t*)0x400000; // 4MB mark
    heap_end = heap_start + HEAP_SIZE;
    heap_current = heap_start;

    // Initialize free list
    free_list = (alloc_header_t*)heap_start;
    free_list->size = HEAP_SIZE - sizeof(alloc_header_t);
    free_list->free = true;
    free_list->next = NULL;

    // Initialize virtual memory manager
    kernel_pml4 = vmm_create_page_table();
    if (kernel_pml4) {
        // Set up initial kernel mappings
        for (uint64_t addr = 0; addr < 0x1000000; addr += PAGE_SIZE) {
            vmm_map_page(kernel_pml4, KERNEL_VIRTUAL_BASE + addr, addr,
                        PTE_WRITE | PTE_GLOBAL);
        }
        vmm_switch_page_table(kernel_pml4);
    }
}

void* kmalloc(size_t size) {
    if (size == 0) return NULL;

    // Align to 8 bytes
    size = (size + 7) & ~7;

    alloc_header_t* current = free_list;

    while (current) {
        if (current->free && current->size >= size) {
            // Split block if necessary
            if (current->size > size + sizeof(alloc_header_t) + 8) {
                alloc_header_t* new_block = (alloc_header_t*)((uint8_t*)current + sizeof(alloc_header_t) + size);
                new_block->size = current->size - size - sizeof(alloc_header_t);
                new_block->free = true;
                new_block->next = current->next;

                current->size = size;
                current->next = new_block;
            }

            current->free = false;
            return (uint8_t*)current + sizeof(alloc_header_t);
        }

        current = current->next;
    }

    return NULL; // Out of memory
}

void kfree(void* ptr) {
    if (!ptr) return;

    alloc_header_t* header = (alloc_header_t*)((uint8_t*)ptr - sizeof(alloc_header_t));
    header->free = true;

    // Coalesce adjacent free blocks
    alloc_header_t* current = free_list;
    while (current && current->next) {
        if (current->free && current->next->free &&
            (uint8_t*)current + sizeof(alloc_header_t) + current->size == (uint8_t*)current->next) {
            current->size += sizeof(alloc_header_t) + current->next->size;
            current->next = current->next->next;
        } else {
            current = current->next;
        }
    }
}

void* page_alloc(void) {
    // Simple page allocation - just advance heap
    if (heap_current + PAGE_SIZE > heap_end) {
        return NULL;
    }

    void* page = heap_current;
    heap_current += PAGE_SIZE;

    // Clear the page
    for (int i = 0; i < PAGE_SIZE; i++) {
        ((uint8_t*)page)[i] = 0;
    }

    return page;
}

void page_free(void* page) {
    // Simple implementation - in real system would track free pages
    (void)page; // Unused for now
}
