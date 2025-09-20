#include "kernel/process.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"
#include "kernel/time.h"

process_t* process_list = NULL;
static process_t* current_process = NULL;
static uint32_t next_pid = 1;

void process_init(void) {
    // Initialize kernel process
    process_t* kernel_proc = (process_t*)kmalloc(sizeof(process_t));
    if (!kernel_proc) {
        kernel_panic("Failed to allocate kernel process");
    }

    kernel_proc->pid = 0;
    for (int i = 0; i < PROCESS_NAME_MAX; i++) {
        kernel_proc->name[i] = "kernel"[i];
        if (kernel_proc->name[i] == '\0') break;
    }
    kernel_proc->state = PROCESS_RUNNING;
    kernel_proc->rsp = 0;
    kernel_proc->rip = 0;
    kernel_proc->page_table = NULL;
    kernel_proc->next = NULL;
    kernel_proc->priority = MAX_PRIORITY;
    kernel_proc->cpu_time = 0;
    kernel_proc->memory_usage = 0;
    kernel_proc->time_slice = DEFAULT_TIME_SLICE;
    kernel_proc->nice_value = 0;
    kernel_proc->last_run = 0;
    kernel_proc->wait_time = 0;

    process_list = kernel_proc;
    current_process = kernel_proc;
}

process_t* process_create(const char* name, void* entry_point) {
    process_t* proc = (process_t*)kmalloc(sizeof(process_t));
    if (!proc) {
        return NULL;
    }

    proc->pid = process_get_next_pid();

    // Copy name
    int i;
    for (i = 0; i < PROCESS_NAME_MAX - 1 && name[i]; i++) {
        proc->name[i] = name[i];
    }
    proc->name[i] = '\0';

    proc->state = PROCESS_READY;
    proc->rip = (uint64_t)entry_point;
    proc->priority = DEFAULT_PRIORITY;
    proc->cpu_time = 0;
    proc->memory_usage = 0;
    proc->time_slice = DEFAULT_TIME_SLICE;
    proc->nice_value = 0;
    proc->last_run = 0;
    proc->wait_time = 0;

    // Allocate stack
    void* stack = page_alloc();
    if (!stack) {
        kfree(proc);
        return NULL;
    }
    proc->rsp = (uint64_t)stack + PAGE_SIZE - 8;

    // Add to process list
    proc->next = process_list;
    process_list = proc;

    return proc;
}

void process_destroy(process_t* proc) {
    if (!proc) return;

    // Remove from process list
    if (process_list == proc) {
        process_list = proc->next;
    } else {
        process_t* current = process_list;
        while (current && current->next != proc) {
            current = current->next;
        }
        if (current) {
            current->next = proc->next;
        }
    }

    // Free process structure
    kfree(proc);
}

void process_schedule(void) {
    if (!process_list) {
        return;
    }

    process_t* highest_priority = NULL;
    process_t* current = process_list;
    uint8_t max_priority = 0;
    uint64_t current_time = get_system_time_ms();

    // Update current process time slice
    if (current_process && current_process->state == PROCESS_RUNNING) {
        if (current_process->time_slice > 0) {
            current_process->time_slice--;
        }
        current_process->cpu_time++;
    }

    // Find highest priority ready process
    while (current) {
        if (current->state == PROCESS_READY || current->state == PROCESS_RUNNING) {
            // Calculate dynamic priority based on nice value and aging
            uint8_t dynamic_priority = current->priority;

            // Apply nice value effect (nice -20 = highest priority, +19 = lowest)
            int32_t priority_adjustment = current->nice_value * -5;
            int32_t new_priority = (int32_t)dynamic_priority + priority_adjustment;

            if (new_priority < MIN_PRIORITY) {
                dynamic_priority = MIN_PRIORITY;
            } else if (new_priority > MAX_PRIORITY) {
                dynamic_priority = MAX_PRIORITY;
            } else {
                dynamic_priority = (uint8_t)new_priority;
            }

            // Aging: boost priority for processes that haven't run recently
            uint64_t wait_bonus = (current_time - current->last_run) / 1000;
            if (wait_bonus > PRIORITY_BOOST) wait_bonus = PRIORITY_BOOST;
            if (dynamic_priority + wait_bonus <= MAX_PRIORITY) {
                dynamic_priority += wait_bonus;
            }

            // Select highest priority process, or same priority with expired time slice
            if (dynamic_priority > max_priority ||
                (dynamic_priority == max_priority && current != current_process) ||
                (current == current_process && current->time_slice == 0)) {

                max_priority = dynamic_priority;
                highest_priority = current;
            }
        }
        current = current->next;
    }

    // Switch to highest priority process
    if (highest_priority && highest_priority != current_process) {
        if (current_process && current_process->state == PROCESS_RUNNING) {
            current_process->state = PROCESS_READY;
        }

        current_process = highest_priority;
        current_process->state = PROCESS_RUNNING;
        current_process->time_slice = DEFAULT_TIME_SLICE;
        current_process->last_run = current_time;
    } else if (current_process && current_process->time_slice == 0) {
        // Reset time slice for current process
        current_process->time_slice = DEFAULT_TIME_SLICE;
    }
}

process_t* process_get_current(void) {
    return current_process;
}

uint32_t process_get_next_pid(void) {
    return next_pid++;
}

void process_set_priority(process_t* proc, uint8_t priority) {
    if (proc && priority <= MAX_PRIORITY) {
        proc->priority = priority;
    }
}

void process_set_nice(process_t* proc, int32_t nice_value) {
    if (proc && nice_value >= -20 && nice_value <= 19) {
        proc->nice_value = nice_value;
    }
}

process_t* process_find_by_pid(uint32_t pid) {
    process_t* current = process_list;
    while (current) {
        if (current->pid == pid) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void process_update_cpu_time(process_t* proc, uint64_t time_delta) {
    if (proc) {
        proc->cpu_time += time_delta;
    }
}

void process_aging(void) {
    process_t* current = process_list;
    uint64_t current_time = get_system_time_ms();

    while (current) {
        if (current->state == PROCESS_READY) {
            current->wait_time = current_time - current->last_run;

            // Boost priority for long-waiting processes
            if (current->wait_time > 5000 && current->priority < MAX_PRIORITY - PRIORITY_BOOST) {
                current->priority += PRIORITY_BOOST / 2;
            }
        }
        current = current->next;
    }
}
