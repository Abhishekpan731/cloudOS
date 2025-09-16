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
    uint8_t priority;        // Priority 0-255 (higher = more important)
    uint64_t cpu_time;       // Total CPU time used
    uint64_t memory_usage;   // Memory usage in bytes
    uint32_t time_slice;     // Remaining time slice in ticks
    uint32_t nice_value;     // Nice value (-20 to 19)
    uint64_t last_run;       // Last time process was scheduled
    uint64_t wait_time;      // Time spent waiting
} process_t;

#define DEFAULT_PRIORITY    128
#define MAX_PRIORITY       255
#define MIN_PRIORITY       0
#define DEFAULT_TIME_SLICE 10
#define PRIORITY_BOOST     10

void process_init(void);
process_t* process_create(const char* name, void* entry_point);
void process_destroy(process_t* proc);
void process_schedule(void);
process_t* process_get_current(void);
uint32_t process_get_next_pid(void);

void process_set_priority(process_t* proc, uint8_t priority);
void process_set_nice(process_t* proc, int32_t nice_value);
process_t* process_find_by_pid(uint32_t pid);
void process_update_cpu_time(process_t* proc, uint64_t time_delta);
void process_aging(void);

extern process_t* process_list;

#endif
