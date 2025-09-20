# Kernel APIs - Low-Level Design

## Overview

This document defines the internal kernel APIs used by CloudOS modules for inter-module communication, resource management, and system services. These APIs provide clean abstractions while maintaining high performance.

## Memory Management APIs

### Physical Memory Allocation

```c
// Core memory allocation functions
page_t* page_alloc(void);                           // Allocate single page
void page_free(page_t* page);                       // Free single page
page_t* alloc_pages(uint32_t order);               // Allocate 2^order pages
void free_pages(page_t* pages, uint32_t order);    // Free page block

// Kernel heap allocation
void* kmalloc(size_t size, gfp_flags_t flags);     // Allocate kernel memory
void kfree(void* ptr);                              // Free kernel memory
void* kcalloc(size_t nmemb, size_t size);          // Zero-initialized allocation
void* krealloc(void* ptr, size_t new_size);        // Resize allocation

// Virtual memory allocation
void* vmalloc(size_t size);                        // Allocate virtual memory
void vfree(void* ptr);                             // Free virtual memory
```

### Virtual Memory Management

```c
// Page table operations
uint64_t* vmm_create_page_table(void);
void vmm_destroy_page_table(uint64_t* pml4);
int vmm_map_page(uint64_t* pml4, uint64_t virt, uint64_t phys, uint64_t flags);
void vmm_unmap_page(uint64_t* pml4, uint64_t virt);
uint64_t vmm_virt_to_phys(uint64_t* pml4, uint64_t virt);

// VMA management
vm_area_t* create_vma(uint64_t start, uint64_t end, uint32_t flags);
void destroy_vma(vm_area_t* vma);
int add_vma_to_process(process_t* proc, vm_area_t* vma);
vm_area_t* find_vma(process_t* proc, uint64_t addr);
```

## Process Management APIs

### Process Control

```c
// Process lifecycle
pid_t create_process(process_t* parent, bool copy_memory);
int terminate_process(process_t* proc, int exit_code);
process_t* find_process(pid_t pid);
int wait_for_process(pid_t pid, int* status, int options);

// Process scheduling
void schedule(void);                                // Main scheduler
void yield(void);                                   // Voluntary yield
void wake_up_process(process_t* proc);             // Wake sleeping process
void set_process_state(process_t* proc, process_state_t state);

// Process attributes
int set_process_priority(process_t* proc, int priority);
int set_process_affinity(process_t* proc, uint64_t cpu_mask);
int set_process_limits(process_t* proc, resource_limit_t* limits);
```

### Inter-Process Communication

```c
// Message queues
mqd_t mq_create(const char* name, struct mq_attr* attr);
int mq_send(mqd_t mqd, const void* msg, size_t len, uint32_t priority);
ssize_t mq_receive(mqd_t mqd, void* buf, size_t len, uint32_t* priority);
int mq_close(mqd_t mqd);

// Shared memory
shmid_t shm_create(key_t key, size_t size, int flags);
void* shm_attach(shmid_t shmid, void* addr, int flags);
int shm_detach(void* addr);
int shm_destroy(shmid_t shmid);

// Semaphores
semid_t sem_create(key_t key, int nsems, int flags);
int sem_op(semid_t semid, struct sembuf* ops, size_t nops);
int sem_control(semid_t semid, int semnum, int cmd, void* arg);
```

## File System APIs

### VFS Operations

```c
// File operations
file_descriptor_t* vfs_open(const char* path, int flags, mode_t mode);
ssize_t vfs_read(file_descriptor_t* fd, void* buf, size_t count);
ssize_t vfs_write(file_descriptor_t* fd, const void* buf, size_t count);
off_t vfs_seek(file_descriptor_t* fd, off_t offset, int whence);
int vfs_close(file_descriptor_t* fd);

// Directory operations
vfs_node_t* vfs_lookup(const char* path);
int vfs_mkdir(const char* path, mode_t mode);
int vfs_rmdir(const char* path);
int vfs_readdir(file_descriptor_t* fd, struct dirent* dirp, size_t count);

// File system mounting
int vfs_mount(const char* source, const char* target, const char* fstype, int flags);
int vfs_unmount(const char* target, int flags);
```

### File System Implementation

```c
// Superblock operations
super_block_t* register_filesystem(const char* name, fs_operations_t* ops);
int unregister_filesystem(const char* name);
super_block_t* mount_filesystem(const char* device, const char* fstype);

// Inode operations
vfs_node_t* alloc_inode(super_block_t* sb);
void free_inode(vfs_node_t* inode);
int write_inode(vfs_node_t* inode);
int sync_filesystem(super_block_t* sb);
```

## Network APIs

### Socket Interface

```c
// Socket management
socket_t* socket_create(int family, int type, int protocol);
int socket_bind(socket_t* sock, const struct sockaddr* addr, socklen_t len);
int socket_listen(socket_t* sock, int backlog);
socket_t* socket_accept(socket_t* sock, struct sockaddr* addr, socklen_t* len);
int socket_connect(socket_t* sock, const struct sockaddr* addr, socklen_t len);

// Data transfer
ssize_t socket_send(socket_t* sock, const void* buf, size_t len, int flags);
ssize_t socket_recv(socket_t* sock, void* buf, size_t len, int flags);
ssize_t socket_sendto(socket_t* sock, const void* buf, size_t len, int flags,
                     const struct sockaddr* addr, socklen_t addrlen);
ssize_t socket_recvfrom(socket_t* sock, void* buf, size_t len, int flags,
                       struct sockaddr* addr, socklen_t* addrlen);

// Socket options
int socket_setsockopt(socket_t* sock, int level, int optname, const void* optval, socklen_t len);
int socket_getsockopt(socket_t* sock, int level, int optname, void* optval, socklen_t* len);
int socket_shutdown(socket_t* sock, int how);
int socket_close(socket_t* sock);
```

### Network Device Management

```c
// Device registration
int register_netdev(net_device_t* dev);
void unregister_netdev(net_device_t* dev);
net_device_t* find_netdev(const char* name);

// Packet handling
int netif_rx(sk_buff_t* skb);                      // Receive packet
int netif_tx(sk_buff_t* skb);                      // Transmit packet
sk_buff_t* alloc_skb(uint32_t size);               // Allocate socket buffer
void free_skb(sk_buff_t* skb);                     // Free socket buffer

// Network interfaces
int netif_up(net_device_t* dev);                   // Bring interface up
int netif_down(net_device_t* dev);                 // Bring interface down
int netif_set_ip(net_device_t* dev, struct in_addr* ip);
```

## Security APIs

### Access Control

```c
// Security context management
security_context_t* create_security_context(uid_t uid, gid_t gid);
void destroy_security_context(security_context_t* ctx);
int set_security_context(process_t* proc, security_context_t* ctx);

// Access control decisions
access_result_t security_check_access(security_context_t* subject,
                                     vfs_node_t* object, access_mode_t mode);
bool capability_check(security_context_t* ctx, capability_t cap);
int security_check_exec(security_context_t* ctx, const char* path);

// Authentication
int authenticate_user(const char* username, auth_token_t* token, login_session_t** session);
login_session_t* create_session(user_account_t* account);
void destroy_session(login_session_t* session);
```

### Audit Interface

```c
// Audit logging
int audit_log(audit_event_t event, const char* format, ...);
int audit_log_access(security_context_t* ctx, vfs_node_t* obj, access_mode_t mode, bool allowed);
int audit_log_exec(security_context_t* ctx, const char* path, char* const argv[]);
int audit_log_login(const char* username, bool success, const char* tty);

// Audit configuration
int audit_enable(audit_level_t level);
int audit_disable(void);
int audit_set_filter(audit_filter_t* filter);
```

## Device Driver APIs

### Device Registration

```c
// Device management
int register_device(device_t* dev);
void unregister_device(device_t* dev);
device_t* find_device(dev_t dev_id);
dev_t alloc_device_number(device_type_t type);

// Character device interface
int register_chrdev(uint32_t major, const char* name, device_operations_t* ops);
int unregister_chrdev(uint32_t major);

// Block device interface
int register_blkdev(uint32_t major, const char* name, block_operations_t* ops);
int unregister_blkdev(uint32_t major);
```

### Interrupt Handling

```c
// Interrupt management
int request_irq(uint32_t irq, irq_handler_t handler, uint32_t flags, const char* name, void* data);
void free_irq(uint32_t irq, void* data);
void enable_irq(uint32_t irq);
void disable_irq(uint32_t irq);

// Interrupt service routines
void handle_interrupt(uint32_t irq_num, interrupt_context_t* ctx);
void schedule_softirq(softirq_type_t type);
```

## Synchronization APIs

### Locking Primitives

```c
// Spinlocks
void spinlock_init(spinlock_t* lock);
void spin_lock(spinlock_t* lock);
void spin_unlock(spinlock_t* lock);
void spin_lock_irqsave(spinlock_t* lock, unsigned long* flags);
void spin_unlock_irqrestore(spinlock_t* lock, unsigned long flags);

// Read-write locks
void rwlock_init(rwlock_t* lock);
void read_lock(rwlock_t* lock);
void read_unlock(rwlock_t* lock);
void write_lock(rwlock_t* lock);
void write_unlock(rwlock_t* lock);

// Semaphores
void sema_init(semaphore_t* sem, int val);
int down(semaphore_t* sem);                         // Acquire (blocking)
int down_trylock(semaphore_t* sem);                 // Acquire (non-blocking)
void up(semaphore_t* sem);                          // Release
```

### Wait Queues

```c
// Wait queue management
void init_waitqueue_head(wait_queue_head_t* wq);
void add_wait_queue(wait_queue_head_t* wq, wait_queue_entry_t* entry);
void remove_wait_queue(wait_queue_head_t* wq, wait_queue_entry_t* entry);
void wake_up(wait_queue_head_t* wq);
void wake_up_all(wait_queue_head_t* wq);

// Sleeping and waking
int sleep_on(wait_queue_head_t* wq);
int sleep_on_timeout(wait_queue_head_t* wq, uint64_t timeout);
void sleep_on_condition(wait_queue_head_t* wq, condition_t condition);
```

## Timer APIs

### Timer Management

```c
// Timer operations
void timer_init(timer_t* timer, timer_function_t function, void* data);
int add_timer(timer_t* timer, uint64_t expires);
int del_timer(timer_t* timer);
int mod_timer(timer_t* timer, uint64_t expires);

// Time functions
uint64_t get_system_time(void);                     // Get current time
uint64_t get_monotonic_time(void);                  // Get monotonic time
void msleep(uint32_t msecs);                        // Sleep in milliseconds
void usleep(uint32_t usecs);                        // Sleep in microseconds
```

## Container APIs

### Container Management

```c
// Container lifecycle
container_t* create_container(const char* name, container_config_t* config);
int destroy_container(container_t* container);
int start_container(container_t* container);
int stop_container(container_t* container);

// Process management within containers
int add_process_to_container(container_t* container, process_t* process);
int remove_process_from_container(container_t* container, process_t* process);

// Resource management
int set_container_memory_limit(container_t* container, uint64_t limit);
int set_container_cpu_limit(container_t* container, uint32_t cpu_shares);
int apply_container_security_policy(container_t* container, security_policy_t* policy);
```

## Utility APIs

### String and Memory Utilities

```c
// String functions
size_t strlen(const char* s);
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);
char* strdup(const char* s);

// Memory functions
void* memcpy(void* dest, const void* src, size_t n);
void* memmove(void* dest, const void* src, size_t n);
int memcmp(const void* s1, const void* s2, size_t n);
void* memset(void* s, int c, size_t n);
```

### Debugging and Logging

```c
// Kernel logging
int printk(const char* format, ...);               // Kernel print
int vprintk(const char* format, va_list args);     // va_list version

// Debug utilities
void dump_stack(void);                              // Stack trace
void dump_process(process_t* proc);                 // Process info dump
void dump_memory_stats(void);                       // Memory statistics

// Assertion macros
#define ASSERT(condition) do { \
    if (!(condition)) { \
        panic("Assertion failed: %s at %s:%d", #condition, __FILE__, __LINE__); \
    } \
} while (0)

#define BUG_ON(condition) ASSERT(!(condition))
```

## API Usage Guidelines

### Error Handling
- All APIs return standard error codes (0 = success, negative = error)
- Use appropriate error codes from `<errno.h>`
- Clean up resources on error paths

### Thread Safety
- All APIs are thread-safe unless explicitly documented otherwise
- Use appropriate locking for shared data structures
- Avoid holding locks across potentially blocking operations

### Performance Considerations
- Minimize system call overhead with batching
- Use appropriate data structures for access patterns
- Consider cache locality in data structure design

### Memory Management
- Always free allocated memory
- Use appropriate allocation flags (GFP_KERNEL, GFP_ATOMIC, etc.)
- Check for allocation failures

---
*Kernel APIs v1.0 - High-Performance Internal Interfaces*