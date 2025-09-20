/*
 * CloudFS Storage Drivers
 * NVMe, SATA/AHCI, and RAM disk drivers for CloudFS
 */

#include "kernel/fs.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"

// Simple string and memory functions for kernel use
static void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++)
    {
        d[i] = s[i];
    }
    return dest;
}
static int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

static char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++) != '\0');
    return dest;
}

static void *memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    for (size_t i = 0; i < n; i++) {
        p[i] = (unsigned char)c;
    }
    return s;
}

// Storage driver types
typedef enum {
    STORAGE_NVME = 1,
    STORAGE_SATA = 2,
    STORAGE_AHCI = 3,
    STORAGE_RAMDISK = 4
} storage_type_t;

// Storage device structure
typedef struct storage_device {
    storage_type_t type;
    char name[32];
    uint64_t capacity;      // Total capacity in bytes
    uint32_t block_size;    // Block size in bytes
    uint32_t max_transfer;  // Maximum transfer size
    void *private_data;     // Driver-specific data

    // Operations
    int (*read_blocks)(struct storage_device *dev, uint64_t start_block,
                      uint32_t num_blocks, void *buffer);
    int (*write_blocks)(struct storage_device *dev, uint64_t start_block,
                       uint32_t num_blocks, const void *buffer);
    int (*flush)(struct storage_device *dev);
    int (*get_info)(struct storage_device *dev);

    struct storage_device *next;
} storage_device_t;

// Global storage device list
static storage_device_t *storage_devices = NULL;

// NVMe driver structures
#define NVME_QUEUE_DEPTH 64
#define NVME_MAX_NAMESPACES 16

typedef struct nvme_controller {
    uint64_t mmio_base;
    uint32_t queue_depth;
    uint32_t max_transfer;
    uint16_t num_queues;
    void *queues[NVME_QUEUE_DEPTH];
} nvme_controller_t;

typedef struct nvme_namespace {
    uint32_t nsid;
    uint64_t capacity;
    uint32_t block_size;
    uint32_t max_transfer;
    nvme_controller_t *controller;
} nvme_namespace_t;

// SATA/AHCI driver structures
#define AHCI_MAX_PORTS 32
#define AHCI_COMMAND_LIST_SIZE 1024

typedef struct ahci_port {
    uint32_t port_num;
    uint32_t mmio_base;
    uint8_t *command_list;
    uint8_t *fis_receive;
    uint32_t command_list_phys;
    uint32_t fis_receive_phys;
} ahci_port_t;

typedef struct ahci_controller {
    uint32_t mmio_base;
    uint32_t num_ports;
    ahci_port_t ports[AHCI_MAX_PORTS];
} ahci_controller_t;

// RAM disk driver structures
typedef struct ramdisk_device {
    uint8_t *data;
    uint64_t capacity;
    uint32_t block_size;
} ramdisk_device_t;

// Forward declarations
static int nvme_probe(void);
static int ahci_probe(void);
static int ramdisk_create(uint64_t capacity, uint32_t block_size);

// Storage device registration
int storage_register_device(storage_device_t *dev) {
    if (!dev) return -1;

    dev->next = storage_devices;
    storage_devices = dev;

    kprintf("Storage: Registered device %s (%llu MB)\n",
            dev->name, dev->capacity / (1024 * 1024));
    return 0;
}

storage_device_t *storage_find_device(const char *name) {
    storage_device_t *dev = storage_devices;

    while (dev) {
        if (strcmp(dev->name, name) == 0) {
            return dev;
        }
        dev = dev->next;
    }

    return NULL;
}

// NVMe driver implementation
static int nvme_read_blocks(storage_device_t *dev, uint64_t start_block,
                           uint32_t num_blocks, void *buffer) {
    nvme_namespace_t *ns = (nvme_namespace_t *)dev->private_data;
    (void)ns; // TODO: Implement NVMe read
    (void)start_block; // TODO: Use start_block parameter

    // Placeholder - fill with test pattern
    memset(buffer, 0xAA, num_blocks * dev->block_size);
    return 0;
}

static int nvme_write_blocks(storage_device_t *dev, uint64_t start_block,
                            uint32_t num_blocks, const void *buffer) {
    nvme_namespace_t *ns = (nvme_namespace_t *)dev->private_data;
    (void)ns; // TODO: Implement NVMe write
    (void)start_block;
    (void)num_blocks;
    (void)buffer;

    // Placeholder - do nothing
    return 0;
}

static int nvme_flush(storage_device_t *dev) {
    (void)dev; // TODO: Implement NVMe flush
    return 0;
}

static int nvme_get_info(storage_device_t *dev) {
    nvme_namespace_t *ns = (nvme_namespace_t *)dev->private_data;
    (void)ns; // TODO: Implement NVMe info
    return 0;
}

static int nvme_probe(void) {
    // TODO: Probe for NVMe controllers
    // For now, create a dummy NVMe device

    nvme_namespace_t *ns = (nvme_namespace_t *)kmalloc(sizeof(nvme_namespace_t));
    if (!ns) return -1;

    ns->nsid = 1;
    ns->capacity = 512 * 1024 * 1024; // 512MB
    ns->block_size = 4096;
    ns->max_transfer = 128 * 1024; // 128KB
    ns->controller = NULL;

    storage_device_t *dev = (storage_device_t *)kmalloc(sizeof(storage_device_t));
    if (!dev) {
        kfree(ns);
        return -1;
    }

    strcpy(dev->name, "nvme0n1");
    dev->type = STORAGE_NVME;
    dev->capacity = ns->capacity;
    dev->block_size = ns->block_size;
    dev->max_transfer = ns->max_transfer;
    dev->private_data = ns;

    dev->read_blocks = nvme_read_blocks;
    dev->write_blocks = nvme_write_blocks;
    dev->flush = nvme_flush;
    dev->get_info = nvme_get_info;

    return storage_register_device(dev);
}

// SATA/AHCI driver implementation
static int ahci_read_blocks(storage_device_t *dev, uint64_t start_block,
                           uint32_t num_blocks, void *buffer) {
    ahci_port_t *port = (ahci_port_t *)dev->private_data;
    (void)port; // TODO: Implement AHCI read
    (void)start_block; // TODO: Use start_block parameter

    // Placeholder - fill with test pattern
    memset(buffer, 0xBB, num_blocks * dev->block_size);
    return 0;
}

static int ahci_write_blocks(storage_device_t *dev, uint64_t start_block,
                            uint32_t num_blocks, const void *buffer) {
    ahci_port_t *port = (ahci_port_t *)dev->private_data;
    (void)port; // TODO: Implement AHCI write
    (void)start_block;
    (void)num_blocks;
    (void)buffer;

    // Placeholder - do nothing
    return 0;
}

static int ahci_flush(storage_device_t *dev) {
    (void)dev; // TODO: Implement AHCI flush
    return 0;
}

static int ahci_get_info(storage_device_t *dev) {
    ahci_port_t *port = (ahci_port_t *)dev->private_data;
    (void)port; // TODO: Implement AHCI info
    return 0;
}

static int ahci_probe(void) {
    // TODO: Probe for AHCI controllers
    // For now, create a dummy SATA device

    ahci_port_t *port = (ahci_port_t *)kmalloc(sizeof(ahci_port_t));
    if (!port) return -1;

    port->port_num = 0;
    port->mmio_base = 0; // TODO: Get from PCI
    port->command_list = NULL;
    port->fis_receive = NULL;

    storage_device_t *dev = (storage_device_t *)kmalloc(sizeof(storage_device_t));
    if (!dev) {
        kfree(port);
        return -1;
    }

    strcpy(dev->name, "sda");
    dev->type = STORAGE_SATA;
    dev->capacity = 1000 * 1024 * 1024; // 1GB
    dev->block_size = 512;
    dev->max_transfer = 64 * 1024; // 64KB
    dev->private_data = port;

    dev->read_blocks = ahci_read_blocks;
    dev->write_blocks = ahci_write_blocks;
    dev->flush = ahci_flush;
    dev->get_info = ahci_get_info;

    return storage_register_device(dev);
}

// RAM disk driver implementation
static int ramdisk_read_blocks(storage_device_t *dev, uint64_t start_block,
                              uint32_t num_blocks, void *buffer) {
    ramdisk_device_t *ramdisk = (ramdisk_device_t *)dev->private_data;

    uint64_t offset = start_block * dev->block_size;
    uint64_t size = num_blocks * dev->block_size;

    if (offset + size > ramdisk->capacity) {
        return -1; // Out of bounds
    }

    memcpy(buffer, ramdisk->data + offset, size);
    return 0;
}

static int ramdisk_write_blocks(storage_device_t *dev, uint64_t start_block,
                               uint32_t num_blocks, const void *buffer) {
    ramdisk_device_t *ramdisk = (ramdisk_device_t *)dev->private_data;

    uint64_t offset = start_block * dev->block_size;
    uint64_t size = num_blocks * dev->block_size;

    if (offset + size > ramdisk->capacity) {
        return -1; // Out of bounds
    }

    memcpy(ramdisk->data + offset, buffer, size);
    return 0;
}

static int ramdisk_flush(storage_device_t *dev) {
    (void)dev; // RAM disk doesn't need flushing
    return 0;
}

static int ramdisk_get_info(storage_device_t *dev) {
    ramdisk_device_t *ramdisk = (ramdisk_device_t *)dev->private_data;
    (void)ramdisk;
    return 0;
}

static int ramdisk_create(uint64_t capacity, uint32_t block_size) {
    ramdisk_device_t *ramdisk = (ramdisk_device_t *)kmalloc(sizeof(ramdisk_device_t));
    if (!ramdisk) return -1;

    ramdisk->data = (uint8_t *)kmalloc(capacity);
    if (!ramdisk->data) {
        kfree(ramdisk);
        return -1;
    }

    ramdisk->capacity = capacity;
    ramdisk->block_size = block_size;

    // Clear RAM disk
    memset(ramdisk->data, 0, capacity);

    storage_device_t *dev = (storage_device_t *)kmalloc(sizeof(storage_device_t));
    if (!dev) {
        kfree(ramdisk->data);
        kfree(ramdisk);
        return -1;
    }

    strcpy(dev->name, "ram0");
    dev->type = STORAGE_RAMDISK;
    dev->capacity = capacity;
    dev->block_size = block_size;
    dev->max_transfer = 64 * 1024; // 64KB
    dev->private_data = ramdisk;

    dev->read_blocks = ramdisk_read_blocks;
    dev->write_blocks = ramdisk_write_blocks;
    dev->flush = ramdisk_flush;
    dev->get_info = ramdisk_get_info;

    return storage_register_device(dev);
}

// Storage driver initialization
int storage_init(void) {
    kprintf("Storage: Initializing storage drivers...\n");

    int result = 0;

    // Probe for NVMe devices
    if (nvme_probe() != 0) {
        kprintf("Storage: NVMe probe failed\n");
    }

    // Probe for SATA/AHCI devices
    if (ahci_probe() != 0) {
        kprintf("Storage: AHCI probe failed\n");
    }

    // Create RAM disk for testing
    if (ramdisk_create(64 * 1024 * 1024, 4096) != 0) { // 64MB RAM disk
        kprintf("Storage: RAM disk creation failed\n");
        result = -1;
    }

    kprintf("Storage: Storage drivers initialized\n");
    return result;
}

// Block device operations (for CloudFS integration)
int storage_read_blocks(const char *device, uint64_t start_block,
                       uint32_t num_blocks, void *buffer) {
    storage_device_t *dev = storage_find_device(device);
    if (!dev || !dev->read_blocks) return -1;

    return dev->read_blocks(dev, start_block, num_blocks, buffer);
}

int storage_write_blocks(const char *device, uint64_t start_block,
                        uint32_t num_blocks, const void *buffer) {
    storage_device_t *dev = storage_find_device(device);
    if (!dev || !dev->write_blocks) return -1;

    return dev->write_blocks(dev, start_block, num_blocks, buffer);
}

int storage_flush(const char *device) {
    storage_device_t *dev = storage_find_device(device);
    if (!dev || !dev->flush) return -1;

    return dev->flush(dev);
}

int storage_get_capacity(const char *device, uint64_t *capacity, uint32_t *block_size) {
    storage_device_t *dev = storage_find_device(device);
    if (!dev) return -1;

    if (capacity) *capacity = dev->capacity;
    if (block_size) *block_size = dev->block_size;

    return 0;
}

// List all storage devices
void storage_list_devices(void) {
    storage_device_t *dev = storage_devices;
    int count = 0;

    kprintf("Storage devices:\n");
    while (dev) {
        const char *type_str;
        switch (dev->type) {
            case STORAGE_NVME: type_str = "NVMe"; break;
            case STORAGE_SATA: type_str = "SATA"; break;
            case STORAGE_AHCI: type_str = "AHCI"; break;
            case STORAGE_RAMDISK: type_str = "RAM Disk"; break;
            default: type_str = "Unknown"; break;
        }

        kprintf("  %s: %s, %llu MB, %u bytes/block\n",
                dev->name, type_str, dev->capacity / (1024 * 1024), dev->block_size);
        dev = dev->next;
        count++;
    }

    if (count == 0) {
        kprintf("  No storage devices found\n");
    }
}

// Performance monitoring
void storage_get_stats(const char *device, uint64_t *read_ops, uint64_t *write_ops,
                      uint64_t *read_bytes, uint64_t *write_bytes) {
    // TODO: Implement performance statistics
    (void)device;
    if (read_ops) *read_ops = 0;
    if (write_ops) *write_ops = 0;
    if (read_bytes) *read_bytes = 0;
    if (write_bytes) *write_bytes = 0;
}

// Hotplug support (for future expansion)
int storage_hotplug_add(const char *device) {
    (void)device; // TODO: Implement hotplug add
    return -1;
}

int storage_hotplug_remove(const char *device) {
    (void)device; // TODO: Implement hotplug remove
    return -1;
}

// Power management
int storage_suspend(const char *device) {
    storage_device_t *dev = storage_find_device(device);
    if (!dev) return -1;

    // TODO: Implement device suspend
    (void)dev;
    return 0;
}

int storage_resume(const char *device) {
    storage_device_t *dev = storage_find_device(device);
    if (!dev) return -1;

    // TODO: Implement device resume
    (void)dev;
    return 0;
}
