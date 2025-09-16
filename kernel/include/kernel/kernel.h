#ifndef KERNEL_KERNEL_H
#define KERNEL_KERNEL_H

#include "types.h"

#define KERNEL_VERSION_MAJOR 0
#define KERNEL_VERSION_MINOR 1
#define KERNEL_VERSION_PATCH 0

#define KERNEL_STACK_SIZE 0x4000

void kernel_main(void);
void kernel_panic(const char* message);

void kprintf(const char* format, ...);

#endif
