# Device Drivers Module - Low-Level Design

## Module Overview

The device drivers module provides a unified device abstraction layer with support for character devices, block devices, and network devices. It includes console, keyboard, storage, and null device drivers with a plug-and-play framework for dynamic device management.

## File Structure

```
kernel/device/
├── device.c       - Device framework (197 lines)
├── console.c      - Console driver (87 lines)
├── keyboard.c     - Keyboard driver (86 lines)
├── null.c         - Null device (48 lines)
└── include/
    ├── device.h   - Device framework interface
    └── drivers.h  - Driver registration interface
```

## Core Data Structures

### Generic Device Structure

```c
// Generic device representation
typedef struct device {
    dev_t dev_id;                    // Device ID (major:minor)
    device_type_t type;              // CHAR, BLOCK, NETWORK
    char name[DEV_NAME_MAX];         // Device name
    device_class_t class;            // TTY, STORAGE, INPUT, etc.

    // Device operations
    struct device_operations* ops;   // Device-specific operations
    void* private_data;              // Driver private data

    // Device state
    device_state_t state;            // ACTIVE, SUSPENDED, REMOVED
    atomic_t ref_count;              // Reference count

    // Power management
    power_state_t power_state;       // D0, D1, D2, D3
    bool can_wakeup;                 // Wake-up capability

    // Device tree integration
    struct device* parent;           // Parent device
    struct device* children;         // Child devices
    struct device* sibling;          // Sibling device

    // Synchronization
    spinlock_t lock;                 // Device lock
    wait_queue_t wait_queue;         // Wait queue for blocking operations

    // Statistics
    struct device_stats stats;       // Device statistics
} device_t;

// Device operations
typedef struct device_operations {
    int (*open)(device_t* dev, int flags);
    int (*close)(device_t* dev);
    ssize_t (*read)(device_t* dev, void* buf, size_t count, off_t offset);
    ssize_t (*write)(device_t* dev, const void* buf, size_t count, off_t offset);
    int (*ioctl)(device_t* dev, unsigned int cmd, void* arg);
    int (*mmap)(device_t* dev, vm_area_t* vma);
    unsigned int (*poll)(device_t* dev, poll_table_t* wait);
    int (*flush)(device_t* dev);
    int (*fsync)(device_t* dev);
} device_operations_t;
```

### Console Device

```c
// Console device structure
typedef struct console_device {
    device_t base;                   // Base device structure

    // Display parameters
    uint16_t width;                  // Screen width in characters
    uint16_t height;                 // Screen height in characters
    uint16_t cursor_x;               // Current cursor X position
    uint16_t cursor_y;               // Current cursor Y position

    // Video memory
    uint16_t* video_memory;          // VGA text mode memory
    uint32_t video_memory_size;      // Memory size

    // Color attributes
    uint8_t foreground_color;        // Foreground color
    uint8_t background_color;        // Background color
    uint8_t default_attr;            // Default attribute

    // Output buffer
    char output_buffer[CONSOLE_BUFFER_SIZE];
    size_t buffer_head;              // Buffer write position
    size_t buffer_tail;              // Buffer read position

    // Console state
    bool cursor_visible;             // Cursor visibility
    console_mode_t mode;             // TEXT, GRAPHICS

    spinlock_t lock;                 // Console lock
} console_device_t;
```

## Key Functions Summary

| Function | Purpose | Location | Status |
|----------|---------|----------|--------|
| `device_init()` | Initialize device framework | device.c:15 | ✅ |
| `register_device()` | Register new device | device.c:45 | ✅ |
| `console_write()` | Console output | console.c:28 | ✅ |
| `keyboard_read()` | Keyboard input | keyboard.c:42 | ✅ |

---
*Device Drivers Module v1.0 - Unified Device Abstraction*