#include "kernel/device.h"
#include "kernel/kernel.h"

static int console_open(device_t* dev);
static int console_close(device_t* dev);
static ssize_t console_read(device_t* dev, void* buffer, size_t count, off_t offset);
static ssize_t console_write(device_t* dev, const void* buffer, size_t count, off_t offset);
static int console_ioctl(device_t* dev, unsigned int cmd, unsigned long arg);

static device_ops_t console_ops = {
    .open = console_open,
    .close = console_close,
    .read = console_read,
    .write = console_write,
    .ioctl = console_ioctl
};

device_t console_device = {
    .major = DEVICE_MAJOR_CONSOLE,
    .minor = 0,
    .name = "console",
    .type = DEVICE_TYPE_CHAR,
    .ops = &console_ops,
    .private_data = NULL,
    .flags = 0,
    .ref_count = 0,
    .next = NULL
};

int console_init(void) {
    return device_register(&console_device);
}

static int console_open(device_t* dev) {
    (void)dev;
    return 0; // Console is always available
}

static int console_close(device_t* dev) {
    (void)dev;
    return 0; // Console remains available
}

static ssize_t console_read(device_t* dev, void* buffer, size_t count, off_t offset) {
    (void)dev;
    (void)buffer;
    (void)count;
    (void)offset;
    // Console input not implemented yet - return 0 (EOF)
    return 0;
}

static ssize_t console_write(device_t* dev, const void* buffer, size_t count, off_t offset) {
    (void)dev;
    (void)offset;

    const char* str = (const char*)buffer;
    for (size_t i = 0; i < count; i++) {
        if (str[i] == '\0') {
            break;
        }
        // Use existing kprintf character output
        kprintf("%c", str[i]);
    }

    return count;
}

static int console_ioctl(device_t* dev, unsigned int cmd, unsigned long arg) {
    (void)dev;
    (void)cmd;
    (void)arg;
    return -1; // Not implemented
}
