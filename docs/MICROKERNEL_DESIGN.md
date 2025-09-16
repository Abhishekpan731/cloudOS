# Microkernel Design (Phase 1)

This document outlines a minimal microkernel architecture for CloudOS Phase 1.

Goals
- Provide a tiny, well-defined core that initializes memory and process management.
- Expose a simple service registration API used by early system services.
- Keep the implementation portable between x86_64 and ARM64 by isolating HAL and arch-specific code.

Core components
- microkernel (kernel/microkernel.c, kernel/include/kernel/microkernel.h):
  - Initialization entrypoint `microkernel_init`.
  - Simple service registration `microkernel_register_service`.
  - Status query `microkernel_status`.

- Process manager (kernel/process): existing code provides basic PCB and scheduling.
- Memory manager (kernel/memory): existing API `memory_init`, `kmalloc`, `kfree`, and page allocator.
- HAL: architecture-specific code lives under `kernel/arch/*` and should present consistent init/context APIs.

Boot and initialization
- `kernel_main` remains the primary boot entry for now.
- `kernel_main` will call `microkernel_init` in Phase 1 to initialize core subsystems.

Next steps (Phase 1 milestones)
- Flesh out process switching and context save/restore in HAL for x86_64 and ARM64.
- Implement a simple IPC mechanism (message-passing) between services.
- Add tests under `kernel/tests/` to validate initialization and basic service creation.

Acceptance criteria for Phase 1 (Months 1-6)
- Design doc present and reviewed.
- Microkernel skeleton compiles with existing Makefile and integrates with memory and process modules.
- Basic service registration creates process stubs that appear in process list.

*** End of document
