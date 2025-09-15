#ifndef KERNEL_MEMORY_H
#define KERNEL_MEMORY_H

#include "types.h"

#define PAGE_SIZE 4096
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

typedef struct page {
    struct page* next;
    uint64_t flags;
    uint32_t ref_count;
} page_t;

void memory_init(void);
void* kmalloc(size_t size);
void kfree(void* ptr);
void* page_alloc(void);
void page_free(void* page);

#endif