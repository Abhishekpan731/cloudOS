#ifndef KERNEL_MICROKERNEL_H
#define KERNEL_MICROKERNEL_H

#include "types.h"

/* Minimal microkernel public API for Phase 1.
 * This header defines the initialization entrypoint and a
 * couple of lightweight helpers for early-stage development.
 */

typedef enum
{
    MK_OK = 0,
    MK_ERROR = -1
} mk_status_t;

/* Initialize microkernel core subsystems. Should be idempotent. */
mk_status_t microkernel_init(void);

/* Register a simple service or task by name. Returns MK_OK or MK_ERROR. */
mk_status_t microkernel_register_service(const char *name, void *entry_point);

/* Query microkernel status string (read-only). */
const char *microkernel_status(void);

#endif
