# Memory Management Algorithms - Low-Level Design

## Overview

CloudOS implements a sophisticated memory management system with buddy allocation, slab caching, virtual memory management, and NUMA awareness. The algorithms are optimized for cloud workloads with emphasis on performance, scalability, and memory efficiency.

## Physical Memory Allocation

### Buddy System Algorithm

#### Core Buddy Allocator
```c
// Buddy system implementation for physical page allocation
typedef struct buddy_block {
    struct buddy_block* next;
    uint32_t order;           // log2(block_size_in_pages)
    bool allocated;
    uint32_t magic;          // Corruption detection
} buddy_block_t;

// Buddy allocation algorithm
page_t* buddy_alloc_pages(uint32_t order) {
    // Find smallest available block >= requested order
    for (uint32_t current_order = order; current_order <= MAX_ORDER; current_order++) {
        if (free_lists[current_order]) {
            buddy_block_t* block = free_lists[current_order];

            // Remove block from free list
            free_lists[current_order] = block->next;

            // Split block if necessary
            while (current_order > order) {
                current_order--;
                buddy_block_t* buddy = split_block(block, current_order);
                add_to_free_list(buddy, current_order);
            }

            block->allocated = true;
            return (page_t*)block;
        }
    }

    return NULL; // Out of memory
}

// Buddy deallocation with coalescing
void buddy_free_pages(page_t* page, uint32_t order) {
    buddy_block_t* block = (buddy_block_t*)page;

    // Mark as free
    block->allocated = false;
    block->order = order;

    // Coalesce with buddy blocks
    while (order < MAX_ORDER) {
        buddy_block_t* buddy = find_buddy(block, order);

        if (!buddy || buddy->allocated || buddy->order != order) {
            break; // Cannot coalesce
        }

        // Remove buddy from free list
        remove_from_free_list(buddy, order);

        // Merge blocks (ensure lower address comes first)
        if (buddy < block) {
            block = buddy;
        }

        order++;
        block->order = order;
    }

    // Add coalesced block to appropriate free list
    add_to_free_list(block, order);
}
```

#### Buddy System Optimization
```c
// Fast buddy finding using XOR arithmetic
buddy_block_t* find_buddy(buddy_block_t* block, uint32_t order) {
    uintptr_t block_addr = (uintptr_t)block;
    uintptr_t page_size = PAGE_SIZE;
    uintptr_t block_size = page_size << order;

    // Buddy address = block_addr XOR block_size
    uintptr_t buddy_addr = block_addr ^ block_size;

    return (buddy_block_t*)buddy_addr;
}

// Block splitting algorithm
buddy_block_t* split_block(buddy_block_t* block, uint32_t new_order) {
    uintptr_t block_addr = (uintptr_t)block;
    uintptr_t split_size = PAGE_SIZE << new_order;

    // Second half becomes the buddy
    buddy_block_t* buddy = (buddy_block_t*)(block_addr + split_size);
    buddy->order = new_order;
    buddy->allocated = false;
    buddy->next = NULL;
    buddy->magic = BUDDY_MAGIC;

    block->order = new_order;

    return buddy;
}
```

### Slab Allocator Algorithm

```c
// Slab allocator for kernel objects
typedef struct slab_cache {
    char name[32];
    size_t object_size;
    size_t align;
    uint32_t objects_per_slab;
    struct slab* partial_slabs;
    struct slab* full_slabs;
    struct slab* free_slabs;
    slab_constructor_t constructor;
    slab_destructor_t destructor;
    uint32_t total_slabs;
    uint32_t active_objects;
} slab_cache_t;

typedef struct slab {
    struct slab* next;
    void* objects;              // Start of object area
    uint32_t free_objects;      // Number of free objects
    uint32_t next_free;         // Index of next free object
    uint8_t* free_bitmap;       // Bitmap of free objects
} slab_t;

// Slab allocation algorithm
void* slab_alloc(slab_cache_t* cache) {
    slab_t* slab = cache->partial_slabs;

    // No partial slabs, try to get one from free list
    if (!slab) {
        slab = cache->free_slabs;
        if (slab) {
            // Move from free to partial list
            cache->free_slabs = slab->next;
            slab->next = cache->partial_slabs;
            cache->partial_slabs = slab;
        } else {
            // Allocate new slab
            slab = allocate_new_slab(cache);
            if (!slab) return NULL;
        }
    }

    // Find free object in slab
    uint32_t obj_idx = find_free_object(slab);
    if (obj_idx == INVALID_INDEX) {
        return NULL; // Slab corruption
    }

    // Mark object as allocated
    set_object_allocated(slab, obj_idx);
    slab->free_objects--;

    // Move to full list if no free objects remain
    if (slab->free_objects == 0) {
        remove_from_partial_list(cache, slab);
        add_to_full_list(cache, slab);
    }

    void* object = get_object_ptr(slab, obj_idx, cache->object_size);

    // Call constructor if present
    if (cache->constructor) {
        cache->constructor(object, cache->object_size);
    }

    cache->active_objects++;
    return object;
}

// Fast free object finding using bitmaps
uint32_t find_free_object(slab_t* slab) {
    uint8_t* bitmap = slab->free_bitmap;
    uint32_t bitmap_size = (slab->objects_per_slab + 7) / 8;

    // Use CPU bit scan instructions for fast search
    for (uint32_t i = 0; i < bitmap_size; i++) {
        if (bitmap[i] != 0xFF) { // Not all bits set
            // Find first zero bit
            uint32_t bit_pos = __builtin_ctz(~bitmap[i]);
            return i * 8 + bit_pos;
        }
    }

    return INVALID_INDEX;
}
```

## Virtual Memory Management

### Page Table Management

```c
// 4-level page table walking algorithm
uint64_t* walk_page_table(uint64_t* pml4, uint64_t vaddr, bool create) {
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx   = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx   = (vaddr >> 12) & 0x1FF;

    // Walk PML4 -> PDPT
    uint64_t* pdpt = walk_page_table_level(pml4, pml4_idx, create);
    if (!pdpt) return NULL;

    // Walk PDPT -> PD
    uint64_t* pd = walk_page_table_level(pdpt, pdpt_idx, create);
    if (!pd) return NULL;

    // Walk PD -> PT
    uint64_t* pt = walk_page_table_level(pd, pd_idx, create);
    if (!pt) return NULL;

    // Return pointer to PTE
    return &pt[pt_idx];
}

// Generic page table level walking
uint64_t* walk_page_table_level(uint64_t* table, uint32_t index, bool create) {
    uint64_t entry = table[index];

    if (!(entry & PTE_PRESENT)) {
        if (!create) return NULL;

        // Allocate new page table
        uint64_t* new_table = (uint64_t*)page_alloc();
        if (!new_table) return NULL;

        // Clear new table
        memset(new_table, 0, PAGE_SIZE);

        // Install entry
        uint64_t phys_addr = virt_to_phys((uint64_t)new_table);
        table[index] = phys_addr | PTE_PRESENT | PTE_WRITE;

        return new_table;
    }

    // Extract physical address and convert to virtual
    uint64_t phys_addr = entry & ADDR_MASK;
    return (uint64_t*)phys_to_virt(phys_addr);
}
```

### Demand Paging Algorithm

```c
// Page fault handler algorithm
void handle_page_fault(uint64_t fault_addr, uint32_t error_code) {
    vm_area_t* vma = find_vma(current_process, fault_addr);
    if (!vma) {
        // Invalid memory access
        send_signal(current_process, SIGSEGV);
        return;
    }

    // Check access permissions
    if (!check_vma_permissions(vma, error_code)) {
        send_signal(current_process, SIGSEGV);
        return;
    }

    uint64_t page_addr = fault_addr & PAGE_MASK;

    if (vma->flags & VMA_FILE_BACKED) {
        // File-backed mapping - read from file
        handle_file_fault(vma, page_addr);
    } else if (vma->flags & VMA_ANONYMOUS) {
        // Anonymous mapping - allocate zero page
        handle_anonymous_fault(vma, page_addr);
    } else if (vma->flags & VMA_SHARED) {
        // Shared memory mapping
        handle_shared_fault(vma, page_addr);
    }
}

// Copy-on-write implementation
void handle_cow_fault(vm_area_t* vma, uint64_t page_addr) {
    uint64_t* pte = walk_page_table(current_process->page_table, page_addr, false);
    if (!pte || !(*pte & PTE_PRESENT)) {
        handle_page_fault(page_addr, PF_WRITE);
        return;
    }

    uint64_t old_phys = *pte & ADDR_MASK;
    page_t* old_page = phys_to_page(old_phys);

    // Check if page is shared
    if (atomic_read(&old_page->ref_count) == 1) {
        // Only reference - just make writable
        *pte |= PTE_WRITE;
        flush_tlb_single(page_addr);
        return;
    }

    // Allocate new page for copy
    page_t* new_page = page_alloc();
    if (!new_page) {
        // Out of memory - terminate process
        send_signal(current_process, SIGKILL);
        return;
    }

    // Copy page contents
    void* old_vaddr = phys_to_virt(old_phys);
    void* new_vaddr = phys_to_virt(page_to_phys(new_page));
    memcpy(new_vaddr, old_vaddr, PAGE_SIZE);

    // Update page table entry
    uint64_t new_phys = page_to_phys(new_page);
    *pte = new_phys | PTE_PRESENT | PTE_WRITE | PTE_USER;

    // Update reference counts
    atomic_dec(&old_page->ref_count);
    atomic_set(&new_page->ref_count, 1);

    // Invalidate TLB
    flush_tlb_single(page_addr);
}
```

### Memory Compaction Algorithm

```c
// Memory compaction to reduce fragmentation
void compact_memory_zones(void) {
    for (int zone = 0; zone < MAX_MEMORY_ZONES; zone++) {
        if (should_compact_zone(zone)) {
            compact_zone(zone);
        }
    }
}

// Zone compaction algorithm
void compact_zone(int zone_id) {
    memory_zone_t* zone = &memory_zones[zone_id];
    uint64_t scan_start = zone->start_pfn;
    uint64_t scan_end = zone->end_pfn;

    // Two-pointer compaction algorithm
    uint64_t free_pfn = scan_start;
    uint64_t migrate_pfn = scan_start;

    while (migrate_pfn < scan_end && free_pfn < scan_end) {
        // Find next movable page
        while (migrate_pfn < scan_end &&
               !is_movable_page(pfn_to_page(migrate_pfn))) {
            migrate_pfn++;
        }

        // Find next free page
        while (free_pfn < scan_end &&
               !is_free_page(pfn_to_page(free_pfn))) {
            free_pfn++;
        }

        // Ensure free page is before migrate page
        if (free_pfn >= migrate_pfn) {
            free_pfn = migrate_pfn + 1;
            continue;
        }

        // Migrate page if beneficial
        if (should_migrate_page(migrate_pfn, free_pfn)) {
            migrate_page(migrate_pfn, free_pfn);
        }

        migrate_pfn++;
    }
}

// Page migration algorithm
int migrate_page(uint64_t old_pfn, uint64_t new_pfn) {
    page_t* old_page = pfn_to_page(old_pfn);
    page_t* new_page = pfn_to_page(new_pfn);

    // Lock both pages
    lock_page(old_page);
    lock_page(new_page);

    // Copy page contents
    void* old_addr = page_to_virt(old_page);
    void* new_addr = page_to_virt(new_page);
    memcpy(new_addr, old_addr, PAGE_SIZE);

    // Update all page table entries pointing to old page
    remap_page_references(old_pfn, new_pfn);

    // Update reverse mapping
    update_reverse_mapping(old_page, new_page);

    // Mark old page as free
    mark_page_free(old_page);

    unlock_page(new_page);
    unlock_page(old_page);

    return 0;
}
```

## NUMA-Aware Allocation

### NUMA Policy Implementation

```c
// NUMA-aware page allocation
page_t* alloc_pages_numa(uint32_t order, int preferred_node, numa_policy_t policy) {
    switch (policy) {
        case NUMA_POLICY_LOCAL:
            return alloc_pages_node(preferred_node, order);

        case NUMA_POLICY_INTERLEAVE:
            return alloc_pages_interleaved(order);

        case NUMA_POLICY_BIND:
            return alloc_pages_strict(preferred_node, order);

        case NUMA_POLICY_PREFERRED:
            // Try preferred node first, fall back to others
            page_t* page = alloc_pages_node(preferred_node, order);
            if (!page) {
                page = alloc_pages_fallback(order, preferred_node);
            }
            return page;
    }

    return NULL;
}

// NUMA distance-aware fallback allocation
page_t* alloc_pages_fallback(uint32_t order, int preferred_node) {
    // Sort nodes by NUMA distance
    int fallback_nodes[MAX_NUMA_NODES];
    sort_nodes_by_distance(fallback_nodes, preferred_node);

    // Try nodes in distance order
    for (int i = 0; i < num_numa_nodes; i++) {
        int node = fallback_nodes[i];
        if (node == preferred_node) continue; // Already tried

        page_t* page = alloc_pages_node(node, order);
        if (page) return page;
    }

    return NULL; // No memory available
}

// Interleaved allocation algorithm
page_t* alloc_pages_interleaved(uint32_t order) {
    static atomic_t interleave_counter = ATOMIC_INIT(0);

    int node = atomic_inc_return(&interleave_counter) % num_numa_nodes;

    // Try current node
    page_t* page = alloc_pages_node(node, order);
    if (page) return page;

    // Fall back to any available node
    return alloc_pages_fallback(order, node);
}
```

### Memory Migration for NUMA Optimization

```c
// Automatic NUMA balancing
void numa_balance_process_memory(process_t* proc) {
    // Analyze page access patterns
    numa_stats_t stats;
    collect_numa_stats(proc, &stats);

    // Determine optimal node placement
    int optimal_node = find_optimal_numa_node(&stats);

    if (optimal_node != proc->numa_preferred_node) {
        // Migrate pages to optimal node
        migrate_process_pages(proc, optimal_node);
        proc->numa_preferred_node = optimal_node;
    }
}

// Page access tracking for NUMA balancing
void track_numa_page_access(uint64_t vaddr, int cpu) {
    numa_page_info_t* info = get_numa_page_info(vaddr);
    int node = cpu_to_numa_node(cpu);

    // Update access counters
    atomic_inc(&info->access_count[node]);
    info->last_access_time = get_system_time();

    // Trigger migration if access pattern changed significantly
    if (should_migrate_for_numa_balance(info)) {
        schedule_numa_migration(vaddr, find_best_numa_node(info));
    }
}
```

## Kernel Memory Management

### Kernel Heap Algorithm (kmalloc)

```c
// Kernel memory allocator with multiple size classes
typedef struct kmem_cache {
    size_t size;
    const char* name;
    slab_cache_t* slab_cache;
    struct kmem_cache* next;
} kmem_cache_t;

// Pre-defined size classes for common allocations
static size_t size_classes[] = {
    8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192
};

void* kmalloc(size_t size, gfp_flags_t flags) {
    if (size == 0) return NULL;

    // Large allocations go directly to page allocator
    if (size > MAX_KMALLOC_SIZE) {
        uint32_t order = get_order(size);
        page_t* pages = alloc_pages(order);
        return pages ? page_to_virt(pages) : NULL;
    }

    // Find appropriate size class
    kmem_cache_t* cache = find_kmem_cache(size);
    if (!cache) {
        cache = create_kmem_cache(size);
        if (!cache) return NULL;
    }

    // Allocate from slab cache
    void* ptr = slab_alloc(cache->slab_cache);

    // Zero memory if requested
    if (ptr && (flags & GFP_ZERO)) {
        memset(ptr, 0, size);
    }

    return ptr;
}

// Kernel free with size class lookup
void kfree(void* ptr) {
    if (!ptr) return;

    // Check if this is a large allocation
    if (is_large_allocation(ptr)) {
        uint32_t order = get_allocation_order(ptr);
        page_t* page = virt_to_page(ptr);
        free_pages(page, order);
        return;
    }

    // Find slab cache and free object
    slab_t* slab = find_slab_for_object(ptr);
    if (slab) {
        slab_free(slab->cache, ptr);
    }
}
```

### Vmalloc Implementation

```c
// Virtual memory allocation for kernel
void* vmalloc(size_t size) {
    if (size == 0) return NULL;

    // Align size to page boundary
    size = ALIGN_UP(size, PAGE_SIZE);
    uint32_t num_pages = size / PAGE_SIZE;

    // Find contiguous virtual address range
    uint64_t vaddr = find_vmalloc_area(size);
    if (!vaddr) return NULL;

    // Allocate physical pages and map them
    for (uint32_t i = 0; i < num_pages; i++) {
        uint64_t page_vaddr = vaddr + (i * PAGE_SIZE);

        page_t* page = page_alloc();
        if (!page) {
            // Cleanup partial allocation
            vfree_partial(vaddr, i * PAGE_SIZE);
            return NULL;
        }

        uint64_t phys_addr = page_to_phys(page);

        // Map page into kernel virtual address space
        if (map_kernel_page(page_vaddr, phys_addr, PTE_WRITE) != 0) {
            page_free(page);
            vfree_partial(vaddr, i * PAGE_SIZE);
            return NULL;
        }
    }

    // Record allocation for later cleanup
    record_vmalloc_allocation(vaddr, size);

    return (void*)vaddr;
}
```

## Memory Reclaim Algorithms

### Page Replacement (LRU)

```c
// Clock-based LRU approximation for page replacement
page_t* select_page_for_eviction(void) {
    static page_t* clock_hand = NULL;
    page_t* candidate = NULL;
    int scanned = 0;

    if (!clock_hand) {
        clock_hand = &page_array[0];
    }

    // Two-handed clock algorithm
    while (scanned < total_pages) {
        if (is_reclaimable_page(clock_hand)) {
            if (page_referenced(clock_hand)) {
                // Clear reference bit and continue
                clear_page_reference(clock_hand);
            } else {
                // Found candidate for eviction
                candidate = clock_hand;
                break;
            }
        }

        clock_hand = next_page(clock_hand);
        scanned++;
    }

    return candidate;
}

// Memory pressure detection and response
void handle_memory_pressure(void) {
    memory_pressure_level_t level = assess_memory_pressure();

    switch (level) {
        case PRESSURE_LOW:
            // Gentle background reclaim
            reclaim_pages(LOW_PRESSURE_TARGET);
            break;

        case PRESSURE_MEDIUM:
            // More aggressive reclaim
            reclaim_pages(MEDIUM_PRESSURE_TARGET);
            compact_memory_zones();
            break;

        case PRESSURE_HIGH:
            // Emergency reclaim
            reclaim_pages(HIGH_PRESSURE_TARGET);
            compact_memory_zones();
            oom_kill_process();
            break;
    }
}
```

## Performance Characteristics

### Algorithm Complexity Summary

| Algorithm | Best Case | Average Case | Worst Case | Space | Notes |
|-----------|-----------|--------------|------------|--------|-------|
| Buddy Allocation | O(1) | O(log n) | O(log n) | O(n) | Coalescing overhead |
| Slab Allocation | O(1) | O(1) | O(n) | O(n) | Bitmap scan worst case |
| Page Table Walk | O(1) | O(1) | O(4) | O(1) | Fixed 4-level depth |
| NUMA Allocation | O(1) | O(nodes) | O(nodes²) | O(nodes) | Distance sorting |
| Memory Compaction | O(n) | O(n log n) | O(n²) | O(1) | Page migration cost |

### Performance Targets

- **Page Allocation**: <10μs for order-0 pages
- **Slab Allocation**: <1μs for small objects
- **Page Fault Handling**: <50μs for anonymous pages
- **TLB Miss Cost**: 200-300 cycles on modern CPUs
- **Memory Compaction**: <100ms for 1GB zone

---
*CloudOS Memory Algorithms v1.0 - Scalable and NUMA-Aware*