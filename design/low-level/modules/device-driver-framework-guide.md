# CloudOS Device Driver Framework Guide

## Overview

The CloudOS device driver framework provides a comprehensive architecture for managing hardware devices, implementing device drivers, and handling device lifecycle operations. This guide details the driver model, device management, hotplug support, and power management features.

## Device Driver Architecture

### Core Components

```text
CloudOS Device Driver Architecture:
┌─────────────────────────────────────────────────────────────┐
│                    Device Driver Layer                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Block       │ │ Character  │ │ Network    │           │
│  │ Drivers     │ │ Drivers    │ │ Drivers    │           │
│  │             │ │            │ │            │           │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘           │
│         │                │                │                │
├─────────┼────────────────┼────────────────┼────────────────┤
│  ┌──────▼──────┐                                           │
│  │ Device      │                                           │
│  │ Driver Core │                                           │
│  │             │                                           │
│  │ • Driver    │                                           │
│  │   Registration│                                         │
│  │ • Device     │                                           │
│  │   Matching   │                                           │
│  │ • Probe/     │                                           │
│  │   Remove     │                                           │
│  └──────┬──────┘                                           │
│         │                                                  │
├─────────┼──────────────────────────────────────────────────┤
│  ┌──────▼──────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Bus         │ │ Device      │ │ Class      │           │
│  │ Abstraction │ │ Model       │ │ Interface  │           │
│  │             │ │             │ │            │           │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘           │
│         │                │                │                │
├─────────┼────────────────┼────────────────┼────────────────┤
│  ┌──────▼──────┐                                           │
│  │ Hardware    │                                           │
│  │ Abstraction │                                           │
│  │ Layer       │                                           │
│  │             │                                           │
│  └─────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

### Device and Driver Structures

```c
// Device structure
struct device {
    struct kobject kobj;                // Kernel object
    struct device *parent;              // Parent device
    struct device_private *p;           // Private data
    const char *init_name;              // Initial name
    const struct device_type *type;     // Device type
    struct bus_type *bus;               // Bus type
    struct device_driver *driver;       // Device driver
    void *platform_data;                // Platform data
    void *driver_data;                  // Driver data
    struct dev_pm_info power;            // Power management
    struct dev_msi_info msi;            // MSI information
    u64 *dma_mask;                      // DMA mask
    u64 coherent_dma_mask;              // Coherent DMA mask
    struct device_node *of_node;        // Device tree node
    struct fwnode_handle *fwnode;       // Firmware node
    dev_t devt;                         // Device number
    u32 id;                             // Device ID
    spinlock_t devres_lock;             // Device resource lock
    struct list_head devres_head;       // Device resource list
    struct class *class;                // Device class
    const struct attribute_group **groups; // Attribute groups
    void (*release)(struct device *dev); // Release function
    struct iommu_group *iommu_group;    // IOMMU group
    struct dev_iommu *iommu;            // IOMMU device
    bool offline_disabled:1;            // Offline disabled
    bool offline:1;                     // Device offline
    bool of_node_reused:1;              // OF node reused
    bool dma_32bit_only:1;              // 32-bit DMA only
};

// Device driver structure
struct device_driver {
    const char *name;                   // Driver name
    struct bus_type *bus;               // Bus type
    struct module *owner;               // Owner module
    const char *mod_name;               // Module name
    bool suppress_bind_attrs;           // Suppress bind attributes
    enum probe_type probe_type;         // Probe type
    const struct of_device_id *of_match_table; // OF match table
    const struct acpi_device_id *acpi_match_table; // ACPI match table
    int (*probe)(struct device *dev);   // Probe function
    int (*remove)(struct device *dev);  // Remove function
    void (*shutdown)(struct device *dev); // Shutdown function
    int (*suspend)(struct device *dev, pm_message_t state); // Suspend
    int (*resume)(struct device *dev);  // Resume
    const struct attribute_group **groups; // Attribute groups
    const struct dev_pm_ops *pm;        // Power management ops
    struct driver_private *p;           // Private data
};

// Bus type structure
struct bus_type {
    const char *name;                   // Bus name
    const char *dev_name;               // Device name format
    struct device *dev_root;            // Root device
    const struct attribute_group **bus_groups; // Bus attributes
    const struct attribute_group **dev_groups; // Device attributes
    const struct attribute_group **drv_groups; // Driver attributes
    int (*match)(struct device *dev, struct device_driver *drv); // Match
    int (*uevent)(struct device *dev, struct kobj_uevent_env *env); // Uevent
    int (*probe)(struct device *dev);   // Probe
    int (*remove)(struct device *dev);  // Remove
    void (*shutdown)(struct device *dev); // Shutdown
    int (*online)(struct device *dev);  // Online
    int (*offline)(struct device *dev); // Offline
    int (*suspend)(struct device *dev, pm_message_t state); // Suspend
    int (*resume)(struct device *dev);  // Resume
    const struct dev_pm_ops *pm;        // Power management ops
    const struct iommu_ops *iommu_ops;  // IOMMU operations
    struct subsys_private *p;           // Private data
    struct lock_class_key lock_key;     // Lock class key
};

// Device type structure
struct device_type {
    const char *name;                   // Type name
    const struct attribute_group **groups; // Attribute groups
    int (*uevent)(struct device *dev, struct kobj_uevent_env *env); // Uevent
    char *(*devnode)(struct device *dev, umode_t *mode, kuid_t *uid, kgid_t *gid); // Devnode
    void (*release)(struct device *dev); // Release
    const struct dev_pm_ops *pm;        // Power management ops
};
```

## Device Registration and Discovery

### Driver Registration

```c
// Register device driver
int driver_register(struct device_driver *drv) {
    int ret;

    // Initialize driver private data
    drv->p = kzalloc(sizeof(*drv->p), GFP_KERNEL);
    if (!drv->p) {
        return -ENOMEM;
    }

    // Initialize lists
    INIT_LIST_HEAD(&drv->p->klist_devices);
    INIT_LIST_HEAD(&drv->p->klist);

    // Set owner if not set
    if (!drv->owner) {
        drv->owner = THIS_MODULE;
    }

    // Add to bus driver list
    ret = bus_add_driver(drv);
    if (ret) {
        kfree(drv->p);
        return ret;
    }

    // Create driver attributes
    ret = driver_create_file(drv, &driver_attr_uevent);
    if (ret) {
        bus_remove_driver(drv);
        kfree(drv->p);
        return ret;
    }

    // Add to module driver list
    if (drv->owner) {
        module_add_driver(drv->owner, drv);
    }

    return 0;
}

// Unregister device driver
void driver_unregister(struct device_driver *drv) {
    // Remove from module driver list
    if (drv->owner) {
        module_remove_driver(drv);
    }

    // Remove driver attributes
    driver_remove_file(drv, &driver_attr_uevent);

    // Remove from bus
    bus_remove_driver(drv);

    // Free private data
    kfree(drv->p);
}

// Register bus type
int bus_register(struct bus_type *bus) {
    int ret;

    // Initialize bus private data
    bus->p = kzalloc(sizeof(*bus->p), GFP_KERNEL);
    if (!bus->p) {
        return -ENOMEM;
    }

    // Initialize lists
    INIT_LIST_HEAD(&bus->p->klist_devices);
    INIT_LIST_HEAD(&bus->p->klist_drivers);
    INIT_LIST_HEAD(&bus->p->interfaces);

    // Create bus kobject
    ret = kobject_set_name(&bus->p->subsys.kobj, "%s", bus->name);
    if (ret) {
        kfree(bus->p);
        return ret;
    }

    // Initialize subsystem
    bus->p->subsys.kobj.kset = bus_kset;
    bus->p->subsys.kobj.ktype = &bus_ktype;

    // Register subsystem
    ret = subsystem_register(&bus->p->subsys);
    if (ret) {
        kfree(bus->p);
        return ret;
    }

    // Create bus attributes
    ret = bus_create_file(bus, &bus_attr_uevent);
    if (ret) {
        subsystem_unregister(&bus->p->subsys);
        kfree(bus->p);
        return ret;
    }

    // Add to bus list
    mutex_lock(&bus_lock);
    list_add_tail(&bus->p->bus_list, &bus_list);
    mutex_unlock(&bus_lock);

    return 0;
}
```

### Device Registration

```c
// Register device
int device_register(struct device *dev) {
    int ret;

    // Set device name
    ret = device_set_name(dev);
    if (ret) {
        return ret;
    }

    // Initialize device private data
    dev->p = kzalloc(sizeof(*dev->p), GFP_KERNEL);
    if (!dev->p) {
        return -ENOMEM;
    }

    // Initialize lists
    INIT_LIST_HEAD(&dev->p->klist_children);
    INIT_LIST_HEAD(&dev->p->deferred_probe);
    INIT_LIST_HEAD(&dev->p->dma_pools);

    // Initialize device resources
    INIT_LIST_HEAD(&dev->devres_head);
    spin_lock_init(&dev->devres_lock);

    // Initialize power management
    pm_runtime_init(dev);

    // Add to bus device list
    ret = bus_add_device(dev);
    if (ret) {
        pm_runtime_remove(dev);
        kfree(dev->p);
        return ret;
    }

    // Create device attributes
    ret = device_create_file(dev, &dev_attr_uevent);
    if (ret) {
        bus_remove_device(dev);
        pm_runtime_remove(dev);
        kfree(dev->p);
        return ret;
    }

    // Add to class if specified
    if (dev->class) {
        ret = class_add_device(dev->class, dev);
        if (ret) {
            device_remove_file(dev, &dev_attr_uevent);
            bus_remove_device(dev);
            pm_runtime_remove(dev);
            kfree(dev->p);
            return ret;
        }
    }

    // Create device node
    ret = device_create_sys_dev_entry(dev);
    if (ret) {
        if (dev->class) {
            class_remove_device(dev->class, dev);
        }
        device_remove_file(dev, &dev_attr_uevent);
        bus_remove_device(dev);
        pm_runtime_remove(dev);
        kfree(dev->p);
        return ret;
    }

    return 0;
}

// Unregister device
void device_unregister(struct device *dev) {
    // Remove device node
    device_remove_sys_dev_entry(dev);

    // Remove from class
    if (dev->class) {
        class_remove_device(dev->class, dev);
    }

    // Remove device attributes
    device_remove_file(dev, &dev_attr_uevent);

    // Remove from bus
    bus_remove_device(dev);

    // Clean up power management
    pm_runtime_remove(dev);

    // Free private data
    kfree(dev->p);
}
```

## Device Matching and Probing

### Device Driver Matching

```c
// Device driver matching algorithm
int driver_match_device(struct device_driver *drv, struct device *dev) {
    int ret = 0;

    // Check if driver supports this device
    if (drv->bus->match) {
        ret = drv->bus->match(dev, drv);
        if (ret) {
            return ret;
        }
    }

    // Check OF match table
    if (drv->of_match_table) {
        ret = of_driver_match_device(dev, drv);
        if (ret) {
            return ret;
        }
    }

    // Check ACPI match table
    if (drv->acpi_match_table) {
        ret = acpi_driver_match_device(dev, drv);
        if (ret) {
            return ret;
        }
    }

    // Check device ID table
    if (drv->id_table) {
        ret = driver_match_id(drv->id_table, dev);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

// OF device matching
int of_driver_match_device(struct device *dev, struct device_driver *drv) {
    const struct of_device_id *matches = drv->of_match_table;
    struct device_node *node = dev->of_node;

    if (!matches || !node) {
        return 0;
    }

    // Check each match entry
    for (; matches->compatible[0]; matches++) {
        if (of_device_is_compatible(node, matches->compatible)) {
            // Store match data
            dev->driver_data = matches->data;
            return 1;
        }
    }

    return 0;
}

// ACPI device matching
int acpi_driver_match_device(struct device *dev, struct device_driver *drv) {
    const struct acpi_device_id *matches = drv->acpi_match_table;
    struct acpi_device *adev = ACPI_COMPANION(dev);

    if (!matches || !adev) {
        return 0;
    }

    // Check each match entry
    for (; matches->id[0]; matches++) {
        if (acpi_match_device_id(adev, matches)) {
            // Store match data
            dev->driver_data = (void *)matches->driver_data;
            return 1;
        }
    }

    return 0;
}
```

### Device Probing

```c
// Device probe process
int device_probe(struct device *dev) {
    struct device_driver *drv;
    int ret = 0;

    // Check if device is already bound
    if (dev->driver) {
        return -EBUSY;
    }

    // Find matching driver
    drv = bus_find_driver(dev->bus, dev);
    if (!drv) {
        return -ENODEV;
    }

    // Bind device to driver
    ret = driver_bind_device(dev, drv);
    if (ret) {
        return ret;
    }

    // Call probe function
    if (drv->probe) {
        ret = drv->probe(dev);
        if (ret) {
            driver_unbind_device(dev, drv);
            return ret;
        }
    }

    // Mark device as probed
    dev->driver = drv;
    dev_set_drvdata(dev, NULL);

    // Create device links
    device_links_driver_bound(dev);

    // Send uevent
    kobject_uevent(&dev->kobj, KOBJ_BIND);

    return 0;
}

// Driver probe function
int driver_probe_device(struct device_driver *drv, struct device *dev) {
    int ret;

    // Check probe type
    if (drv->probe_type == PROBE_PREFER_ASYNCHRONOUS) {
        // Asynchronous probe
        ret = driver_probe_async(dev, drv);
    } else {
        // Synchronous probe
        ret = really_probe(dev, drv);
    }

    return ret;
}

// Asynchronous device probe
int driver_probe_async(struct device *dev, struct device_driver *drv) {
    struct driver_probe_work *work;

    // Allocate work structure
    work = kzalloc(sizeof(*work), GFP_KERNEL);
    if (!work) {
        return -ENOMEM;
    }

    // Initialize work
    INIT_WORK(&work->work, driver_probe_async_work);
    work->dev = dev;
    work->drv = drv;

    // Queue work
    queue_work(driver_probe_wq, &work->work);

    return 0;
}

// Asynchronous probe work function
void driver_probe_async_work(struct work_struct *work) {
    struct driver_probe_work *probe_work;
    struct device *dev;
    struct device_driver *drv;
    int ret;

    probe_work = container_of(work, struct driver_probe_work, work);
    dev = probe_work->dev;
    drv = probe_work->drv;

    // Perform probe
    ret = really_probe(dev, drv);

    // Free work structure
    kfree(probe_work);
}
```

## Hotplug Support

### Hotplug Event Handling

```c
// Hotplug event structure
struct hotplug_event {
    struct device *dev;                 // Device
    enum hotplug_event_type type;       // Event type
    struct kobj_uevent_env *env;        // Uevent environment
    struct list_head list;              // Event list
};

// Hotplug event types
enum hotplug_event_type {
    HOTPLUG_EVENT_ADD,                  // Device added
    HOTPLUG_EVENT_REMOVE,               // Device removed
    HOTPLUG_EVENT_CHANGE,               // Device changed
    HOTPLUG_EVENT_MOVE,                 // Device moved
    HOTPLUG_EVENT_ONLINE,               // Device online
    HOTPLUG_EVENT_OFFLINE,              // Device offline
};

// Send hotplug event
int device_send_hotplug_event(struct device *dev, enum hotplug_event_type type) {
    struct kobj_uevent_env *env;
    int ret;

    // Allocate uevent environment
    env = kzalloc(sizeof(*env), GFP_KERNEL);
    if (!env) {
        return -ENOMEM;
    }

    // Initialize environment
    ret = add_uevent_var(env, "ACTION=%s", hotplug_event_name(type));
    if (ret) {
        kfree(env);
        return ret;
    }

    // Add device information
    ret = add_uevent_var(env, "DEVPATH=%s", dev->kobj.name);
    if (ret) {
        kfree(env);
        return ret;
    }

    // Add subsystem information
    if (dev->bus) {
        ret = add_uevent_var(env, "SUBSYSTEM=%s", dev->bus->name);
        if (ret) {
            kfree(env);
            return ret;
        }
    }

    // Send uevent
    ret = kobject_uevent_env(&dev->kobj, KOBJ_CHANGE, env);

    kfree(env);
    return ret;
}

// Hotplug event handler
int hotplug_event_handler(struct device *dev, enum hotplug_event_type type) {
    int ret = 0;

    switch (type) {
    case HOTPLUG_EVENT_ADD:
        // Device added
        ret = device_add(dev);
        if (ret) {
            break;
        }

        // Try to bind driver
        device_attach(dev);
        break;

    case HOTPLUG_EVENT_REMOVE:
        // Device removed
        device_release_driver(dev);
        device_del(dev);
        break;

    case HOTPLUG_EVENT_CHANGE:
        // Device changed
        device_send_hotplug_event(dev, HOTPLUG_EVENT_CHANGE);
        break;

    case HOTPLUG_EVENT_ONLINE:
        // Device online
        ret = device_online(dev);
        break;

    case HOTPLUG_EVENT_OFFLINE:
        // Device offline
        ret = device_offline(dev);
        break;

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}
```

### Device Attachment and Detachment

```c
// Attach device to driver
int device_attach(struct device *dev) {
    int ret = 0;

    // Check if device is already bound
    if (dev->driver) {
        return -EBUSY;
    }

    // Try to find and bind driver
    ret = bus_for_each_drv(dev->bus, NULL, dev, __device_attach_driver);
    if (ret == 0) {
        // No driver found
        ret = -ENODEV;
    }

    return ret;
}

// Detach device from driver
void device_detach(struct device *dev) {
    // Check if device is bound
    if (!dev->driver) {
        return;
    }

    // Unbind device
    device_release_driver(dev);

    // Reset driver pointer
    dev->driver = NULL;
}

// Driver attachment callback
int __device_attach_driver(struct device_driver *drv, void *data) {
    struct device *dev = data;
    int ret;

    // Check if driver matches device
    ret = driver_match_device(drv, dev);
    if (!ret) {
        return 0; // No match
    }

    // Try to probe device
    ret = driver_probe_device(drv, dev);
    if (ret < 0) {
        return ret; // Probe failed
    }

    return 1; // Success
}
```

## Power Management

### Device Power States

```c
// Device power states
enum device_power_state {
    DPM_STATE_ON,                       // Device on
    DPM_STATE_LOW,                      // Low power state
    DPM_STATE_STANDBY,                  // Standby state
    DPM_STATE_SUSPEND,                  // Suspend state
    DPM_STATE_OFF,                      // Device off
};

// Power management information
struct dev_pm_info {
    pm_message_t power_state;           // Current power state
    unsigned int can_wakeup:1;          // Can wake up system
    unsigned int async_suspend:1;       // Asynchronous suspend
    bool is_prepared:1;                 // Prepared for suspend
    bool is_suspended:1;                // Currently suspended
    bool is_noirq_suspended:1;          // No-IRQ suspended
    bool is_late_suspended:1;           // Late suspended
    bool early_init:1;                  // Early initialization
    bool direct_complete:1;             // Direct complete
    spinlock_t lock;                    // Power management lock
    struct list_head entry;             // Power management list
    struct completion completion;       // Completion for async ops
    struct wakeup_source *wakeup;       // Wakeup source
    struct timer_list suspend_timer;    // Suspend timer
    unsigned long timer_expires;        // Timer expiration
    struct work_struct work;            // Power management work
    wait_queue_head_t wait_queue;       // Wait queue
    atomic_t usage_count;               // Usage count
    atomic_t child_count;               // Child count
    unsigned int disable_depth:3;       // Disable depth
    unsigned int idle_notification:1;   // Idle notification
    unsigned int request_pending:1;     // Request pending
    unsigned int deferred_resume:1;     // Deferred resume
    unsigned int run_wake:1;            // Runtime wake
    unsigned int runtime_auto:1;        // Runtime auto
    unsigned int no_callbacks:1;        // No callbacks
    unsigned int is_lpss_parent:1;      // LPSS parent
    unsigned int is_prepared:1;         // Prepared
    unsigned int is_suspended:1;        // Suspended
    unsigned int is_noirq_suspended:1;  // No-IRQ suspended
    unsigned int is_late_suspended:1;   // Late suspended
    unsigned int early_init:1;          // Early init
    unsigned int direct_complete:1;     // Direct complete
};

// Power management operations
struct dev_pm_ops {
    int (*prepare)(struct device *dev); // Prepare for suspend
    void (*complete)(struct device *dev); // Complete suspend
    int (*suspend)(struct device *dev); // Suspend device
    int (*resume)(struct device *dev);  // Resume device
    int (*freeze)(struct device *dev);  // Freeze device
    int (*thaw)(struct device *dev);    // Thaw device
    int (*poweroff)(struct device *dev); // Power off device
    int (*restore)(struct device *dev); // Restore device
    int (*suspend_late)(struct device *dev); // Late suspend
    int (*resume_early)(struct device *dev); // Early resume
    int (*freeze_late)(struct device *dev); // Late freeze
    int (*thaw_early)(struct device *dev); // Early thaw
    int (*poweroff_late)(struct device *dev); // Late power off
    int (*restore_early)(struct device *dev); // Early restore
    int (*suspend_noirq)(struct device *dev); // No-IRQ suspend
    int (*resume_noirq)(struct device *dev); // No-IRQ resume
    int (*freeze_noirq)(struct device *dev); // No-IRQ freeze
    int (*thaw_noirq)(struct device *dev); // No-IRQ thaw
    int (*poweroff_noirq)(struct device *dev); // No-IRQ power off
    int (*restore_noirq)(struct device *dev); // No-IRQ restore
    int (*runtime_suspend)(struct device *dev); // Runtime suspend
    int (*runtime_resume)(struct device *dev); // Runtime resume
    int (*runtime_idle)(struct device *dev); // Runtime idle
};
```

### Power Management Implementation

```c
// Suspend device
int device_suspend(struct device *dev, pm_message_t state) {
    int ret = 0;

    // Check if device supports suspend
    if (!dev->driver || !dev->driver->pm || !dev->driver->pm->suspend) {
        return 0;
    }

    // Prepare device for suspend
    if (dev->driver->pm->prepare) {
        ret = dev->driver->pm->prepare(dev);
        if (ret) {
            return ret;
        }
    }

    // Suspend device
    ret = dev->driver->pm->suspend(dev);
    if (ret) {
        // Complete suspend on failure
        if (dev->driver->pm->complete) {
            dev->driver->pm->complete(dev);
        }
        return ret;
    }

    // Update power state
    dev->power.power_state = state;

    return 0;
}

// Resume device
int device_resume(struct device *dev) {
    int ret = 0;

    // Check if device supports resume
    if (!dev->driver || !dev->driver->pm || !dev->driver->pm->resume) {
        return 0;
    }

    // Resume device
    ret = dev->driver->pm->resume(dev);
    if (ret) {
        return ret;
    }

    // Complete resume
    if (dev->driver->pm->complete) {
        dev->driver->pm->complete(dev);
    }

    // Update power state
    dev->power.power_state = PMSG_ON;

    return 0;
}

// Runtime suspend
int device_runtime_suspend(struct device *dev) {
    int ret = 0;

    // Check if device supports runtime suspend
    if (!dev->driver || !dev->driver->pm || !dev->driver->pm->runtime_suspend) {
        return 0;
    }

    // Runtime suspend device
    ret = dev->driver->pm->runtime_suspend(dev);
    if (ret) {
        return ret;
    }

    // Update runtime status
    pm_runtime_set_suspended(dev);

    return 0;
}

// Runtime resume
int device_runtime_resume(struct device *dev) {
    int ret = 0;

    // Check if device supports runtime resume
    if (!dev->driver || !dev->driver->pm || !dev->driver->pm->runtime_resume) {
        return 0;
    }

    // Runtime resume device
    ret = dev->driver->pm->runtime_resume(dev);
    if (ret) {
        return ret;
    }

    // Update runtime status
    pm_runtime_set_active(dev);

    return 0;
}
```

## Device Resources and Memory Management

### Device Resource Management

```c
// Device resource structure
struct resource {
    resource_size_t start;              // Start address
    resource_size_t end;                // End address
    const char *name;                   // Resource name
    unsigned long flags;                // Resource flags
    unsigned long desc;                 // Resource descriptor
    struct resource *parent;            // Parent resource
    struct resource *sibling;           // Sibling resource
    struct resource *child;             // Child resource
};

// Resource flags
#define IORESOURCE_IO       0x00000100  // I/O resource
#define IORESOURCE_MEM      0x00000200  // Memory resource
#define IORESOURCE_IRQ      0x00000400  // IRQ resource
#define IORESOURCE_DMA      0x00000800  // DMA resource
#define IORESOURCE_BUS      0x00001000  // Bus resource

// Request device resource
struct resource *request_resource(struct resource *root, struct resource *new) {
    struct resource *conflict;

    // Check for conflicts
    conflict = __request_resource(root, new);
    if (conflict) {
        return conflict;
    }

    // Add to resource tree
    __insert_resource(root, new);

    return NULL;
}

// Release device resource
void release_resource(struct resource *res) {
    // Remove from resource tree
    __release_resource(res);

    // Free resource structure
    kfree(res);
}

// Allocate device resource
struct resource *allocate_resource(struct resource *root, resource_size_t start,
                                  resource_size_t n, resource_size_t min,
                                  resource_size_t max, resource_size_t align,
                                  void (*alignf)(void *, struct resource *,
                                               resource_size_t, resource_size_t),
                                  void *alignf_data) {
    struct resource *res;
    int ret;

    // Allocate resource structure
    res = kzalloc(sizeof(*res), GFP_KERNEL);
    if (!res) {
        return NULL;
    }

    // Find free resource
    ret = find_resource(root, res, start, n, min, max, align, alignf, alignf_data);
    if (ret) {
        kfree(res);
        return NULL;
    }

    // Request resource
    if (__request_resource(root, res)) {
        kfree(res);
        return NULL;
    }

    // Insert into tree
    __insert_resource(root, res);

    return res;
}
```

### Device Memory Management

```c
// Device memory region
struct device_memory {
    phys_addr_t paddr;                  // Physical address
    void __iomem *vaddr;                // Virtual address
    size_t size;                        // Size
    unsigned long flags;                // Flags
    struct list_head list;              // Memory list
};

// Memory flags
#define DEVICE_MEM_MAPPED   (1 << 0)    // Memory is mapped
#define DEVICE_MEM_CACHED   (1 << 1)    // Memory is cached
#define DEVICE_MEM_IO       (1 << 2)    // I/O memory
#define DEVICE_MEM_DMA      (1 << 3)    // DMA memory

// Map device memory
void __iomem *devm_ioremap_resource(struct device *dev, struct resource *res) {
    void __iomem *ptr;
    struct device_memory *mem;

    // Check resource type
    if (!(res->flags & IORESOURCE_MEM)) {
        return IOMEM_ERR_PTR(-EINVAL);
    }

    // Allocate memory structure
    mem = devres_alloc(devm_ioremap_release, sizeof(*mem), GFP_KERNEL);
    if (!mem) {
        return IOMEM_ERR_PTR(-ENOMEM);
    }

    // Map memory
    ptr = ioremap(res->start, resource_size(res));
    if (!ptr) {
        devres_free(mem);
        return IOMEM_ERR_PTR(-ENOMEM);
    }

    // Initialize memory structure
    mem->paddr = res->start;
    mem->vaddr = ptr;
    mem->size = resource_size(res);
    mem->flags = DEVICE_MEM_MAPPED | DEVICE_MEM_IO;

    // Add to device resources
    devres_add(dev, mem);

    return ptr;
}

// Unmap device memory
void devm_iounmap(struct device *dev, void __iomem *addr) {
    struct device_memory *mem;

    // Find memory structure
    mem = devres_find(dev, devm_ioremap_release, NULL, addr);
    if (!mem) {
        return;
    }

    // Unmap memory
    iounmap(addr);

    // Remove from device resources
    devres_remove(dev, mem);
}

// Allocate coherent DMA memory
void *dmam_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle,
                         gfp_t gfp) {
    struct device_memory *mem;
    void *ptr;

    // Allocate memory structure
    mem = devres_alloc(dmam_coherent_release, sizeof(*mem), gfp);
    if (!mem) {
        return NULL;
    }

    // Allocate coherent memory
    ptr = dma_alloc_coherent(dev, size, dma_handle, gfp);
    if (!ptr) {
        devres_free(mem);
        return NULL;
    }

    // Initialize memory structure
    mem->vaddr = ptr;
    mem->size = size;
    mem->flags = DEVICE_MEM_MAPPED | DEVICE_MEM_DMA;

    // Add to device resources
    devres_add(dev, mem);

    return ptr;
}
```

## Device Classes and Interfaces

### Device Class Management

```c
// Device class structure
struct class {
    const char *name;                   // Class name
    struct module *owner;               // Owner module
    struct class_attribute *class_attrs; // Class attributes
    const struct attribute_group **class_groups; // Class attribute groups
    const struct attribute_group **dev_groups; // Device attribute groups
    const struct attribute_group **dev_kobj_groups; // Device kobject groups
    int (*dev_uevent)(struct device *dev, struct kobj_uevent_env *env); // Uevent
    char *(*devnode)(struct device *dev, umode_t *mode); // Devnode
    void (*class_release)(struct class *class); // Release
    void (*dev_release)(struct device *dev); // Device release
    int (*suspend)(struct device *dev, pm_message_t state); // Suspend
    int (*resume)(struct device *dev); // Resume
    const struct kobj_ns_type_operations *ns_type; // Namespace operations
    const void *(*namespace)(struct device *dev); // Namespace
    const struct dev_pm_ops *pm;        // Power management ops
    struct subsys_private *p;           // Private data
};

// Create device class
struct class *class_create(struct module *owner, const char *name) {
    struct class *cls;
    int ret;

    // Allocate class structure
    cls = kzalloc(sizeof(*cls), GFP_KERNEL);
    if (!cls) {
        return ERR_PTR(-ENOMEM);
    }

    // Initialize class
    cls->name = name;
    cls->owner = owner;

    // Create class kobject
    ret = class_register(cls);
    if (ret) {
        kfree(cls);
        return ERR_PTR(ret);
    }

    return cls;
}

// Destroy device class
void class_destroy(struct class *cls) {
    if (!cls) {
        return;
    }

    // Unregister class
    class_unregister(cls);

    // Free class structure
    kfree(cls);
}

// Add device to class
int class_add_device(struct class *cls, struct device *dev) {
    int ret;

    // Create device kobject
    ret = device_create_kobj(dev);
    if (ret) {
        return ret;
    }

    // Add to class device list
    ret = class_device_add(cls, dev);
    if (ret) {
        device_destroy_kobj(dev);
        return ret;
    }

    return 0;
}

// Remove device from class
void class_remove_device(struct class *cls, struct device *dev) {
    // Remove from class device list
    class_device_del(cls, dev);

    // Destroy device kobject
    device_destroy_kobj(dev);
}
```

### Device Interface Management

```c
// Device interface structure
struct device_interface {
    struct list_head node;              // Interface list node
    struct device *dev;                 // Associated device
    struct class *class;                // Device class
    const char *name;                   // Interface name
    int (*add_device)(struct device *dev); // Add device callback
    void (*remove_device)(struct device *dev); // Remove device callback
    struct list_head class_devices;     // Class devices
};

// Register device interface
int device_interface_register(struct device_interface *intf) {
    struct device *dev;
    int ret;

    // Initialize interface
    INIT_LIST_HEAD(&intf->class_devices);

    // Add to class interfaces
    ret = class_interface_register(intf);
    if (ret) {
        return ret;
    }

    // Add existing devices
    class_for_each_device(intf->class, NULL, intf, device_interface_add_device);

    return 0;
}

// Unregister device interface
void device_interface_unregister(struct device_interface *intf) {
    // Remove all devices
    class_for_each_device(intf->class, NULL, intf, device_interface_remove_device);

    // Remove from class interfaces
    class_interface_unregister(intf);
}

// Add device to interface
int device_interface_add_device(struct device *dev, void *data) {
    struct device_interface *intf = data;
    int ret;

    // Check if device matches interface
    if (!device_interface_matches(dev, intf)) {
        return 0;
    }

    // Add device to interface
    ret = intf->add_device(dev);
    if (ret) {
        return ret;
    }

    // Add to interface device list
    list_add_tail(&dev->interface_node, &intf->class_devices);

    return 0;
}

// Remove device from interface
void device_interface_remove_device(struct device *dev, void *data) {
    struct device_interface *intf = data;

    // Check if device is in interface
    if (!list_empty(&dev->interface_node)) {
        // Remove from interface device list
        list_del_init(&dev->interface_node);

        // Remove device from interface
        intf->remove_device(dev);
    }
}
```

## Future Enhancements

### Planned Features

- **Advanced Hotplug**: Enhanced hotplug support with device dependencies and ordering
- **Device Virtualization**: Support for virtual devices and device passthrough
- **Power Management 2.0**: Advanced power management with energy awareness
- **Device Security**: Hardware-backed device security and attestation
- **AI-Powered Device Management**: Machine learning-based device optimization
- **Edge Computing Support**: Optimized device drivers for edge computing scenarios
- **Quantum-Safe Device Communication**: Post-quantum cryptographic device protocols
- **Real-time Device Drivers**: Deterministic device driver operation for real-time systems

---

## Document Information

**CloudOS Device Driver Framework Guide**
*Comprehensive guide for device driver architecture, hotplug support, and power management*

