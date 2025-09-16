#include "kernel/device.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

static device_t* device_list = NULL;
static uint32_t device_count = 0;

void device_init(void) {
    kprintf("Device Manager: Initializing...\n");

    // Initialize built-in devices
    console_init();
    keyboard_init();
    null_init();

    kprintf("Device Manager: Ready\n");
}

int device_register(device_t* dev) {
    if (!dev || device_count >= MAX_DEVICES) {
        return -1;
    }

    // Check for duplicate major/minor
    device_t* existing = device_find(dev->major, dev->minor);
    if (existing) {
        return -1; // Device already exists
    }

    // Add to device list
    dev->next = device_list;
    device_list = dev;
    device_count++;

    kprintf("Device registered: %s (%d:%d)\n", dev->name, dev->major, dev->minor);
    return 0;
}

int device_unregister(uint32_t major, uint32_t minor) {
    device_t** current = &device_list;

    while (*current) {
        if ((*current)->major == major && (*current)->minor == minor) {
            device_t* to_remove = *current;
            *current = (*current)->next;
            device_count--;
            kprintf("Device unregistered: %s (%d:%d)\n", to_remove->name, major, minor);
            return 0;
        }
        current = &(*current)->next;
    }

    return -1; // Device not found
}

device_t* device_find(uint32_t major, uint32_t minor) {
    device_t* current = device_list;

    while (current) {
        if (current->major == major && current->minor == minor) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

device_t* device_find_by_name(const char* name) {
    if (!name) {
        return NULL;
    }

    device_t* current = device_list;

    while (current) {
        int match = 1;
        for (int i = 0; i < DEVICE_NAME_MAX; i++) {
            if (current->name[i] != name[i]) {
                match = 0;
                break;
            }
            if (current->name[i] == '\0') {
                break;
            }
        }

        if (match) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

int device_open(device_t* dev) {
    if (!dev || !dev->ops || !dev->ops->open) {
        return -1;
    }

    dev->ref_count++;
    return dev->ops->open(dev);
}

int device_close(device_t* dev) {
    if (!dev || !dev->ops || !dev->ops->close) {
        return -1;
    }

    if (dev->ref_count > 0) {
        dev->ref_count--;
    }

    return dev->ops->close(dev);
}

ssize_t device_read(device_t* dev, void* buffer, size_t count, off_t offset) {
    if (!dev || !dev->ops || !dev->ops->read) {
        return -1;
    }

    return dev->ops->read(dev, buffer, count, offset);
}

ssize_t device_write(device_t* dev, const void* buffer, size_t count, off_t offset) {
    if (!dev || !dev->ops || !dev->ops->write) {
        return -1;
    }

    return dev->ops->write(dev, buffer, count, offset);
}

int device_ioctl(device_t* dev, unsigned int cmd, unsigned long arg) {
    if (!dev || !dev->ops || !dev->ops->ioctl) {
        return -1;
    }

    return dev->ops->ioctl(dev, cmd, arg);
}
