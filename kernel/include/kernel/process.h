#ifndef KERNEL_PROCESS_H
#define KERNEL_PROCESS_H

#include "types.h"

#define MAX_PROCESSES 256
#define PROCESS_NAME_MAX 64

typedef enum {
    PROCESS_READY,
    PROCESS_RUNNING,
    PROCESS_BLOCKED,
    PROCESS_TERMINATED
} process_state_t;

typedef struct process {
    uint32_t pid;
    char name[PROCESS_NAME_MAX];
    process_state_t state;
    uint64_t rsp;
    uint64_t rip;
    uint64_t* page_table;
    struct process* next;
    uint64_t priority;
    uint64_t cpu_time;
    uint64_t memory_usage;
} process_t;

void process_init(void);
process_t* process_create(const char* name, void* entry_point);
void process_destroy(process_t* proc);
void process_schedule(void);
process_t* process_get_current(void);
uint32_t process_get_next_pid(void);

#endif