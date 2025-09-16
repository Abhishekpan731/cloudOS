#include "kernel/fs.h"
#include "kernel/device.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

static int devfs_mount(filesystem_t* fs, const char* device, const char* mountpoint);
static int devfs_unmount(filesystem_t* fs);
static vfs_node_t* devfs_create_node(filesystem_t* fs, const char* name, vfs_node_type_t type);
static int devfs_delete_node(filesystem_t* fs, vfs_node_t* node);
static int devfs_read(filesystem_t* fs, vfs_node_t* node, uint64_t offset, void* buffer, size_t size);
static int devfs_write(filesystem_t* fs, vfs_node_t* node, uint64_t offset, const void* buffer, size_t size);
static int devfs_sync(filesystem_t* fs);

static filesystem_ops_t devfs_ops = {
    .mount = devfs_mount,
    .unmount = devfs_unmount,
    .create_node = devfs_create_node,
    .delete_node = devfs_delete_node,
    .read = devfs_read,
    .write = devfs_write,
    .sync = devfs_sync
};

static filesystem_t devfs_template = {
    .type = FS_TYPE_DEVFS,
    .name = "devfs",
    .root = NULL,
    .ops = &devfs_ops,
    .private_data = NULL,
    .next = NULL
};

int devfs_init(void) {
    return fs_register(&devfs_template);
}

filesystem_t* devfs_create(void) {
    filesystem_t* fs = (filesystem_t*)kmalloc(sizeof(filesystem_t));
    if (!fs) return NULL;

    *fs = devfs_template;

    // Create root directory
    vfs_node_t* root = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (!root) {
        kfree(fs);
        return NULL;
    }

    root->name[0] = '/';
    root->name[1] = '\0';
    root->type = VFS_DIR;
    root->permissions = 0755;
    root->uid = 0;
    root->gid = 0;
    root->size = 0;
    root->inode = 1;
    root->create_time = 0;
    root->modify_time = 0;
    root->access_time = 0;
    root->parent = NULL;
    root->children = NULL;
    root->next_sibling = NULL;
    root->fs = fs;
    root->fs_data = NULL;

    fs->root = root;

    // Create device nodes for existing devices
    vfs_node_t* console_node = devfs_create_node(fs, "console", VFS_DEVICE);
    if (console_node) {
        console_node->fs_data = device_find_by_name("console");
        console_node->next_sibling = root->children;
        root->children = console_node;
        console_node->parent = root;
    }

    vfs_node_t* null_node = devfs_create_node(fs, "null", VFS_DEVICE);
    if (null_node) {
        null_node->fs_data = device_find_by_name("null");
        null_node->next_sibling = root->children;
        root->children = null_node;
        null_node->parent = root;
    }

    return fs;
}

static int devfs_mount(filesystem_t* fs, const char* device, const char* mountpoint) {
    (void)device;
    (void)mountpoint;
    (void)fs;
    return 0;
}

static int devfs_unmount(filesystem_t* fs) {
    (void)fs;
    return 0;
}

static vfs_node_t* devfs_create_node(filesystem_t* fs, const char* name, vfs_node_type_t type) {
    if (!fs) return NULL;

    vfs_node_t* node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (!node) return NULL;

    // Copy name
    int i;
    for (i = 0; i < FS_NAME_MAX && name[i]; i++) {
        node->name[i] = name[i];
    }
    node->name[i] = '\0';

    node->type = type;
    node->permissions = (type == VFS_DEVICE) ? 0666 : 0644;
    node->uid = 0;
    node->gid = 0;
    node->size = 0;
    node->inode = 0;
    node->create_time = 0;
    node->modify_time = 0;
    node->access_time = 0;
    node->parent = NULL;
    node->children = NULL;
    node->next_sibling = NULL;
    node->fs = fs;
    node->fs_data = NULL;

    return node;
}

static int devfs_delete_node(filesystem_t* fs, vfs_node_t* node) {
    (void)fs;

    if (node) {
        kfree(node);
    }
    return 0;
}

static int devfs_read(filesystem_t* fs, vfs_node_t* node, uint64_t offset, void* buffer, size_t size) {
    if (!fs || !node || node->type != VFS_DEVICE || !node->fs_data) {
        return -1;
    }

    device_t* dev = (device_t*)node->fs_data;
    return device_read(dev, buffer, size, offset);
}

static int devfs_write(filesystem_t* fs, vfs_node_t* node, uint64_t offset, const void* buffer, size_t size) {
    if (!fs || !node || node->type != VFS_DEVICE || !node->fs_data) {
        return -1;
    }

    device_t* dev = (device_t*)node->fs_data;
    return device_write(dev, buffer, size, offset);
}

static int devfs_sync(filesystem_t* fs) {
    // Device files don't need syncing
    (void)fs;
    return 0;
}
