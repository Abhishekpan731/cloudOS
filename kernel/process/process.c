#include "kernel/process.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"

static process_t* process_list = NULL;
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
    kernel_proc->priority = 10;
    kernel_proc->cpu_time = 0;
    kernel_proc->memory_usage = 0;

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
    proc->priority = 5; // Default priority
    proc->cpu_time = 0;
    proc->memory_usage = 0;

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
    if (!current_process || !current_process->next) {
        return; // No other process to switch to
    }

    // Simple round-robin scheduling
    process_t* next = current_process->next;
    if (!next) {
        next = process_list;
    }

    // Find next ready process
    process_t* start = next;
    do {
        if (next->state == PROCESS_READY) {
            current_process->state = PROCESS_READY;
            current_process = next;
            current_process->state = PROCESS_RUNNING;
            break;
        }
        next = next->next;
        if (!next) next = process_list;
    } while (next != start);
}

process_t* process_get_current(void) {
    return current_process;
}

uint32_t process_get_next_pid(void) {
    return next_pid++;
}