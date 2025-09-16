#include "kernel/syscall.h"
#include "kernel/kernel.h"
#include "kernel/process.h"
#include "kernel/memory.h"

static long (*syscall_table[])(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) = {
    [SYSCALL_EXIT]    = (void*)sys_exit,
    [SYSCALL_READ]    = (void*)sys_read,
    [SYSCALL_WRITE]   = (void*)sys_write,
    [SYSCALL_OPEN]    = (void*)sys_open,
    [SYSCALL_CLOSE]   = (void*)sys_close,
    [SYSCALL_FORK]    = (void*)sys_fork,
    [SYSCALL_EXECVE]  = (void*)sys_execve,
    [SYSCALL_GETPID]  = (void*)sys_getpid,
    [SYSCALL_KILL]    = (void*)sys_kill,
    [SYSCALL_MMAP]    = (void*)sys_mmap,
    [SYSCALL_MUNMAP]  = (void*)sys_munmap,
    [SYSCALL_BRK]     = (void*)sys_brk,
};

void syscall_init(void) {
    kprintf("System calls: Initialized\n");
}

uint64_t syscall_handler(uint64_t syscall_num, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    if (syscall_num >= sizeof(syscall_table) / sizeof(syscall_table[0]) ||
        syscall_table[syscall_num] == NULL) {
        return -1; // ENOSYS
    }

    return syscall_table[syscall_num](arg1, arg2, arg3, arg4, arg5);
}

long sys_exit(int exit_code) {
    (void)exit_code; // TODO: Use exit code for process cleanup
    process_t* current = process_get_current();
    if (current && current->pid != 0) { // Don't exit kernel process
        current->state = PROCESS_TERMINATED;
        process_schedule();
    }
    return 0;
}

long sys_read(int fd, void* buffer, size_t count) {
    // Basic implementation - for now just return 0 (EOF)
    (void)fd; (void)buffer; (void)count;
    return 0;
}

long sys_write(int fd, const void* buffer, size_t count) {
    if (fd == 1 || fd == 2) { // stdout/stderr
        const char* str = (const char*)buffer;
        for (size_t i = 0; i < count; i++) {
            if (str[i] == '\0') break;
            kprintf("%c", str[i]);
        }
        return count;
    }
    return -1;
}

long sys_open(const char* pathname, int flags) {
    // Basic implementation - return dummy fd
    (void)pathname; (void)flags;
    return 3; // First non-standard fd
}

long sys_close(int fd) {
    // Basic implementation
    (void)fd;
    return 0;
}

long sys_fork(void) {
    process_t* parent = process_get_current();
    if (!parent) return -1;

    process_t* child = process_create(parent->name, (void*)parent->rip);
    if (!child) return -1;

    // Copy parent's memory state (simplified)
    child->rsp = parent->rsp;
    child->priority = parent->priority;

    return child->pid; // Return child PID to parent
}

long sys_execve(const char* filename, char* const argv[], char* const envp[]) {
    // Basic implementation - just change current process entry point
    process_t* current = process_get_current();
    if (!current) return -1;

    // In real implementation, would load executable from filesystem
    (void)filename; (void)argv; (void)envp;

    return 0;
}

long sys_getpid(void) {
    process_t* current = process_get_current();
    return current ? current->pid : -1;
}

long sys_kill(uint32_t pid, int signal) {
    (void)signal; // TODO: Handle different signal types
    // Find process and terminate it
    process_t* proc = process_list;
    while (proc) {
        if (proc->pid == pid) {
            proc->state = PROCESS_TERMINATED;
            return 0;
        }
        proc = proc->next;
    }
    return -1; // Process not found
}

long sys_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    // Basic memory mapping - allocate pages
    (void)addr; (void)prot; (void)flags; (void)fd; (void)offset;

    size_t pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    void* mapped_addr = NULL;

    for (size_t i = 0; i < pages; i++) {
        void* page = page_alloc();
        if (!page) {
            return (long)MAP_FAILED;
        }
        if (i == 0) mapped_addr = page;
    }

    return (long)mapped_addr;
}

long sys_munmap(void* addr, size_t length) {
    // Basic implementation - just mark as free
    (void)addr; (void)length;
    return 0;
}

long sys_brk(void* addr) {
    // Basic heap management
    static void* current_brk = (void*)0x600000; // Start of heap

    if (addr == NULL) {
        return (long)current_brk;
    }

    if (addr > current_brk) {
        // Expand heap
        size_t pages_needed = ((char*)addr - (char*)current_brk + PAGE_SIZE - 1) / PAGE_SIZE;
        for (size_t i = 0; i < pages_needed; i++) {
            if (!page_alloc()) {
                return -1; // Out of memory
            }
        }
    }

    current_brk = addr;
    return (long)current_brk;
}
