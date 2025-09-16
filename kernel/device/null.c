#include "kernel/device.h"
#include "kernel/kernel.h"

static int null_open(device_t* dev);
static int null_close(device_t* dev);
static ssize_t null_read(device_t* dev, void* buffer, size_t count, off_t offset);
static ssize_t null_write(device_t* dev, const void* buffer, size_t count, off_t offset);
static int null_ioctl(device_t* dev, unsigned int cmd, unsigned long arg);

static device_ops_t null_ops = {
    .open = null_open,
    .close = null_close,
    .read = null_read,
    .write = null_write,
    .ioctl = null_ioctl
};

device_t null_device = {
    .major = 1,
    .minor = 3,
    .name = "null",
    .type = DEVICE_TYPE_CHAR,
    .ops = &null_ops,
    .private_data = NULL,
    .flags = 0,
    .ref_count = 0,
    .next = NULL
};

int null_init(void) {
    return device_register(&null_device);
}

static int null_open(device_t* dev) {
    (void)dev;
    return 0;
}

static int null_close(device_t* dev) {
    (void)dev;
    return 0;
}

static ssize_t null_read(device_t* dev, void* buffer, size_t count, off_t offset) {
    (void)dev;
    (void)buffer;
    (void)count;
    (void)offset;
    return 0; // Always return EOF
}

static ssize_t null_write(device_t* dev, const void* buffer, size_t count, off_t offset) {
    (void)dev;
    (void)buffer;
    (void)offset;
    return count; // Pretend we wrote everything
}

static int null_ioctl(device_t* dev, unsigned int cmd, unsigned long arg) {
    (void)dev;
    (void)cmd;
    (void)arg;
    return -1; // Not supported
}
