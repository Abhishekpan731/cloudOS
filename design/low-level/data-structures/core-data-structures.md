# Core Data Structures - Low-Level Design

## Overview

This document defines the core data structures used throughout CloudOS, including process control blocks, virtual memory areas, network buffers, and security contexts. These structures form the foundation for inter-module communication and system state management.

## Process Control Block (PCB)

Located in: `design/low-level/modules/process-management.md`

The Process Control Block is the primary structure for process management, containing:
- Process identification (PID, PPID)
- Scheduling information (priority, time slice, state)
- Memory management (page tables, VMAs)
- Security context (UID, GID, capabilities)
- Container association and resource limits

## Virtual Memory Areas (VMA)

```c
typedef struct vm_area {
    uint64_t start;              // Start virtual address
    uint64_t end;                // End virtual address
    uint32_t flags;              // VMA_READ, VMA_WRITE, VMA_EXEC, etc.
    vm_area_type_t type;         // ANONYMOUS, FILE_BACKED, SHARED

    // File backing (if applicable)
    vfs_node_t* file;            // Backing file
    off_t file_offset;           // Offset in file

    // Memory management
    struct page** pages;         // Physical pages (if present)
    uint32_t page_count;         // Number of pages

    // Linking
    struct vm_area* next;        // Next VMA in list
    struct vm_area* prev;        // Previous VMA in list

    // Synchronization
    rwlock_t lock;               // VMA protection
} vm_area_t;
```

## Network Buffer (sk_buff)

Located in: `design/low-level/modules/network-stack.md`

The socket buffer structure for network packet management, including:
- Packet data pointers (head, data, tail, end)
- Protocol information (network, transport headers)
- Device and routing information
- Fragment handling for large packets

## VFS Nodes

Located in: `design/low-level/modules/file-system.md`

Virtual File System node structure containing:
- File metadata (inode, size, permissions, timestamps)
- Directory structure (parent, children, siblings)
- File operations function pointers
- Page cache for data caching

## Security Contexts

Located in: `design/low-level/modules/security.md`

Security context structure including:
- User/group identification (UID, GID, supplementary groups)
- Capabilities (effective, permitted, inheritable, bounding)
- MAC labels (type, role, user, level)
- Container security namespace

## Page Descriptors

```c
typedef struct page {
    uint32_t flags;              // Page flags (allocated, dirty, etc.)
    atomic_t ref_count;          // Reference counter
    void* virtual_addr;          // Virtual address mapping

    // Memory zone information
    struct memory_zone* zone;    // Memory zone this page belongs to
    uint32_t order;              // Buddy system order

    // Page cache integration
    struct address_space* mapping; // Address space mapping
    off_t index;                 // Index in address space

    // LRU management
    struct list_head lru;        // LRU list linkage
    uint64_t last_accessed;      // Last access time

    // Linking for buddy system
    struct page* buddy;          // Buddy page pointer
    struct page* next_free;      // Next free page
} page_t;
```

## Device Structures

Located in: `design/low-level/modules/device-drivers.md`

Generic device structure with:
- Device identification (major:minor numbers)
- Device operations function pointers
- Power management state
- Device tree hierarchy

## Hash Tables and Lists

```c
// Generic hash table
typedef struct hash_table {
    struct hlist_head* buckets;  // Hash buckets
    uint32_t bucket_count;       // Number of buckets
    uint32_t item_count;         // Number of items
    hash_function_t hash_fn;     // Hash function
    compare_function_t cmp_fn;   // Comparison function
    spinlock_t lock;             // Hash table lock
} hash_table_t;

// Doubly-linked list
typedef struct list_head {
    struct list_head* next;      // Next element
    struct list_head* prev;      // Previous element
} list_head_t;

// Hash list (for collision handling)
typedef struct hlist_head {
    struct hlist_node* first;    // First node in bucket
} hlist_head_t;

typedef struct hlist_node {
    struct hlist_node* next;     // Next node
    struct hlist_node** pprev;   // Previous node's next pointer
} hlist_node_t;
```

## Wait Queues

```c
typedef struct wait_queue_entry {
    process_t* process;          // Waiting process
    wait_function_t func;        // Wake-up function
    struct list_head task_list;  // Queue linkage
    uint32_t flags;              // Wait flags
} wait_queue_entry_t;

typedef struct wait_queue_head {
    spinlock_t lock;             // Queue protection
    struct list_head task_list;  // List of waiting tasks
} wait_queue_head_t;
```

## Atomic Operations and Synchronization

```c
// Atomic counter
typedef struct atomic {
    volatile int counter;        // Atomic value
} atomic_t;

// Spinlock
typedef struct spinlock {
    volatile uint32_t lock;      // Lock value
    uint32_t owner_cpu;          // CPU holding lock (debug)
} spinlock_t;

// Read-write lock
typedef struct rwlock {
    volatile int32_t lock;       // Lock value (positive=readers, negative=writer)
    atomic_t readers;            // Reader count
    spinlock_t wait_lock;        // Wait queue lock
    wait_queue_head_t read_wait; // Reader wait queue
    wait_queue_head_t write_wait; // Writer wait queue
} rwlock_t;

// Semaphore
typedef struct semaphore {
    atomic_t count;              // Semaphore count
    spinlock_t lock;             // Semaphore lock
    wait_queue_head_t wait;      // Wait queue
} semaphore_t;
```

## Timer Structures

```c
typedef struct timer {
    struct list_head list;       // Timer list linkage
    uint64_t expires;            // Expiration time
    timer_function_t function;   // Timer callback function
    void* data;                  // Callback data
    uint32_t flags;              // Timer flags
} timer_t;

typedef struct timer_wheel {
    struct list_head buckets[TIMER_BUCKETS]; // Timer buckets
    uint64_t current_jiffies;    // Current time
    spinlock_t lock;             // Timer wheel lock
} timer_wheel_t;
```

## Statistics and Counters

```c
typedef struct system_stats {
    // Memory statistics
    uint64_t total_memory;       // Total system memory
    uint64_t free_memory;        // Free memory
    uint64_t cached_memory;      // Cached memory
    uint64_t buffer_memory;      // Buffer memory

    // Process statistics
    uint32_t total_processes;    // Total processes
    uint32_t running_processes;  // Running processes
    uint32_t blocked_processes;  // Blocked processes

    // I/O statistics
    uint64_t disk_reads;         // Disk read operations
    uint64_t disk_writes;        // Disk write operations
    uint64_t network_rx_bytes;   // Network bytes received
    uint64_t network_tx_bytes;   // Network bytes transmitted

    // System load
    uint32_t load_average[3];    // 1, 5, 15 minute load averages
    uint64_t context_switches;   // Context switch count
    uint64_t interrupts;         // Interrupt count

    // Timestamps
    uint64_t boot_time;          // System boot time
    uint64_t uptime;             // System uptime
} system_stats_t;
```

## Data Structure Relationships

```
Process (PCB)
├── Memory Management
│   ├── Page Table (vmm.c)
│   └── VMAs (linked list)
├── File System
│   ├── File Descriptors (array)
│   └── Current Directory (VFS node)
├── Security
│   ├── Security Context
│   └── Capabilities
└── Scheduling
    ├── Run Queue Links
    └── Timer Structures

VFS Node
├── File Operations
├── Page Cache
├── Security Label
└── Directory Children

Network Device
├── Socket Buffers (queues)
├── Device Statistics
└── Protocol Handlers

Container
├── Process List
├── Security Policy
├── Resource Limits
└── Network Namespace
```

## Memory Layout Considerations

### Data Structure Alignment
- All structures aligned to cache line boundaries (64 bytes)
- Critical path structures fit within single cache lines
- Related data co-located to minimize cache misses

### Size Optimization
- Bit fields used for flags to reduce memory usage
- Union types for variant data
- Careful ordering to minimize padding

### Performance Characteristics

| Structure | Size | Cache Lines | Access Pattern |
|-----------|------|-------------|----------------|
| PCB | 512 bytes | 8 | Random |
| VMA | 64 bytes | 1 | Sequential |
| sk_buff | 192 bytes | 3 | Random |
| VFS Node | 256 bytes | 4 | Random |
| Page | 32 bytes | 0.5 | Sequential |

---
*Core Data Structures v1.0 - Optimized for Performance and Scalability*