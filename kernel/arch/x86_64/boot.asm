; CloudOS Boot Loader - Multiboot2 compatible
; x86_64 architecture

MAGIC    equ 0xE85250D6
ARCH     equ 0
LENGTH   equ (header_end - header_start)
CHECKSUM equ -(MAGIC + ARCH + LENGTH)

section .multiboot
header_start:
    dd MAGIC
    dd ARCH
    dd LENGTH
    dd CHECKSUM

    ; End tag
    dw 0
    dw 0
    dd 8
header_end:

section .bss
align 16
stack_bottom:
    resb 16384  ; 16KB stack
stack_top:

section .text
bits 32
global _start
_start:
    ; Set up stack
    mov esp, stack_top

    ; Check multiboot2 magic
    cmp eax, 0x36d76289
    jne .no_multiboot

    ; Save multiboot information
    push ebx
    push eax

    ; Check for long mode support
    call check_long_mode
    test eax, eax
    jz .no_long_mode

    ; Set up paging for long mode
    call setup_paging

    ; Load GDT
    lgdt [gdt64.pointer]

    ; Enable long mode
    mov eax, cr0
    or eax, 1 << 31  ; Enable paging
    mov cr0, eax

    ; Jump to long mode
    jmp gdt64.code:long_mode_start

.no_multiboot:
    mov al, "0"
    jmp error

.no_long_mode:
    mov al, "1"
    jmp error

error:
    mov dword [0xb8000], 0x4f524f45 ; "ER" in red
    mov dword [0xb8004], 0x4f3a4f52 ; "R:" in red
    mov dword [0xb8008], 0x4f204f20 ; "  " in red
    mov byte [0xb800a], al
    hlt

check_long_mode:
    ; Check for CPUID support
    pushfd
    pushfd
    xor dword [esp], 1 << 21
    popfd
    pushfd
    pop eax
    xor eax, [esp]
    popfd
    and eax, 1 << 21
    jz .no_cpuid

    ; Check for long mode
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode

    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .no_long_mode

    mov eax, 1
    ret

.no_cpuid:
.no_long_mode:
    mov eax, 0
    ret

setup_paging:
    ; Map first 2MB
    mov eax, p3_table
    or eax, 0b11 ; present + writable
    mov [p4_table], eax

    mov eax, p2_table
    or eax, 0b11 ; present + writable
    mov [p3_table], eax

    ; Map each P2 entry to a 2MB page
    mov ecx, 0
.map_p2_table:
    mov eax, 0x200000
    mul ecx
    or eax, 0b10000011 ; present + writable + huge page
    mov [p2_table + ecx * 8], eax
    inc ecx
    cmp ecx, 512
    jne .map_p2_table

    ; Enable PAE
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    ; Set long mode bit in EFER MSR
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr

    ; Load P4 table
    mov eax, p4_table
    mov cr3, eax

    ret

section .bss
align 4096
p4_table:
    resb 4096
p3_table:
    resb 4096
p2_table:
    resb 4096

section .rodata
gdt64:
    dq 0 ; zero entry
.code: equ $ - gdt64
    dq (1<<43) | (1<<44) | (1<<47) | (1<<53) ; code segment
.pointer:
    dw $ - gdt64 - 1
    dq gdt64

bits 64
extern kernel_main
long_mode_start:
    ; Clear segment registers
    mov ax, 0
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Call kernel main
    call kernel_main

    ; Halt
    cli
.halt:
    hlt
    jmp .halt