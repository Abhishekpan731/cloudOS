#ifndef KERNEL_SYSCALL_H
#define KERNEL_SYSCALL_H

#include "types.h"

#define SYSCALL_EXIT        1
#define SYSCALL_READ        3
#define SYSCALL_WRITE       4
#define SYSCALL_OPEN        5
#define SYSCALL_CLOSE       6
#define SYSCALL_FORK        57
#define SYSCALL_EXECVE      59
#define SYSCALL_GETPID      39
#define SYSCALL_KILL        62
#define SYSCALL_MMAP        9
#define SYSCALL_MUNMAP      11
#define SYSCALL_BRK         12

#define MAP_FAILED          ((void*)-1)

typedef struct {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi;
    uint64_t rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
} registers_t;

void syscall_init(void);
uint64_t syscall_handler(uint64_t syscall_num, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5);

long sys_exit(int exit_code);
long sys_read(int fd, void* buffer, size_t count);
long sys_write(int fd, const void* buffer, size_t count);
long sys_open(const char* pathname, int flags);
long sys_close(int fd);
long sys_fork(void);
long sys_execve(const char* filename, char* const argv[], char* const envp[]);
long sys_getpid(void);
long sys_kill(uint32_t pid, int signal);
long sys_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
long sys_munmap(void* addr, size_t length);
long sys_brk(void* addr);

#endif
