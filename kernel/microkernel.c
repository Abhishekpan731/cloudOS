/* Minimal microkernel skeleton implementation for Phase 1.
 * Provides initialization and service registration stubs.
 */

#include "kernel/microkernel.h"
#include "kernel/kernel.h"
#include "kernel/process.h"
#include "kernel/memory.h"

static const char *mk_status = "uninitialized";

mk_status_t microkernel_init(void)
{
    if (mk_status && mk_status[0] == 'r')
    {
        return MK_OK; // already running
    }

    // Basic init sequence: initialize memory and processes
    memory_init();
    process_init();

    mk_status = "running";
    kprintf("microkernel: initialized\n");
    return MK_OK;
}

mk_status_t microkernel_register_service(const char *name, void *entry_point)
{
    if (!name || !entry_point)
        return MK_ERROR;
    // For now, register by creating a process entry with the given entry point.
    if (!process_create(name, entry_point))
        return MK_ERROR;
    kprintf("microkernel: registered service %s\n", name);
    return MK_OK;
}

const char *microkernel_status(void)
{
    return mk_status;
}
