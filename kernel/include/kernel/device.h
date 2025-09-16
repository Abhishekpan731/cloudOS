#ifndef KERNEL_DEVICE_H
#define KERNEL_DEVICE_H

#include "types.h"

#define MAX_DEVICES 64
#define DEVICE_NAME_MAX 32

typedef enum {
    DEVICE_TYPE_CHAR,
    DEVICE_TYPE_BLOCK,
    DEVICE_TYPE_NETWORK
} device_type_t;

struct device;

typedef struct device_ops {
    int (*open)(struct device* dev);
    int (*close)(struct device* dev);
    ssize_t (*read)(struct device* dev, void* buffer, size_t count, off_t offset);
    ssize_t (*write)(struct device* dev, const void* buffer, size_t count, off_t offset);
    int (*ioctl)(struct device* dev, unsigned int cmd, unsigned long arg);
} device_ops_t;

typedef struct device {
    uint32_t major;
    uint32_t minor;
    char name[DEVICE_NAME_MAX];
    device_type_t type;
    device_ops_t* ops;
    void* private_data;
    uint32_t flags;
    uint32_t ref_count;
    struct device* next;
} device_t;

void device_init(void);
int device_register(device_t* dev);
int device_unregister(uint32_t major, uint32_t minor);
device_t* device_find(uint32_t major, uint32_t minor);
device_t* device_find_by_name(const char* name);

int device_open(device_t* dev);
int device_close(device_t* dev);
ssize_t device_read(device_t* dev, void* buffer, size_t count, off_t offset);
ssize_t device_write(device_t* dev, const void* buffer, size_t count, off_t offset);
int device_ioctl(device_t* dev, unsigned int cmd, unsigned long arg);

// Standard device types
#define DEVICE_MAJOR_CONSOLE    1
#define DEVICE_MAJOR_KEYBOARD   2
#define DEVICE_MAJOR_MOUSE      3
#define DEVICE_MAJOR_DISK       4
#define DEVICE_MAJOR_NETWORK    5

// Console device
int console_init(void);
extern device_t console_device;

// Keyboard device
int keyboard_init(void);
void keyboard_interrupt_handler(void);
extern device_t keyboard_device;

// Null device
int null_init(void);
extern device_t null_device;

#endif
