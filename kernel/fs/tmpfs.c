#include "kernel/fs.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

typedef struct tmpfs_file {
    uint8_t* data;
    size_t allocated_size;
} tmpfs_file_t;

typedef struct tmpfs_data {
    size_t max_size;
    size_t used_size;
} tmpfs_data_t;

static int tmpfs_mount(filesystem_t* fs, const char* device, const char* mountpoint);
static int tmpfs_unmount(filesystem_t* fs);
static vfs_node_t* tmpfs_create_node(filesystem_t* fs, const char* name, vfs_node_type_t type);
static int tmpfs_delete_node(filesystem_t* fs, vfs_node_t* node);
static int tmpfs_read(filesystem_t* fs, vfs_node_t* node, uint64_t offset, void* buffer, size_t size);
static int tmpfs_write(filesystem_t* fs, vfs_node_t* node, uint64_t offset, const void* buffer, size_t size);
static int tmpfs_sync(filesystem_t* fs);

static filesystem_ops_t tmpfs_ops = {
    .mount = tmpfs_mount,
    .unmount = tmpfs_unmount,
    .create_node = tmpfs_create_node,
    .delete_node = tmpfs_delete_node,
    .read = tmpfs_read,
    .write = tmpfs_write,
    .sync = tmpfs_sync
};

static filesystem_t tmpfs_template = {
    .type = FS_TYPE_TMPFS,
    .name = "tmpfs",
    .root = NULL,
    .ops = &tmpfs_ops,
    .private_data = NULL,
    .next = NULL
};

int tmpfs_init(void) {
    return fs_register(&tmpfs_template);
}

filesystem_t* tmpfs_create(size_t max_size) {
    filesystem_t* fs = (filesystem_t*)kmalloc(sizeof(filesystem_t));
    if (!fs) return NULL;

    *fs = tmpfs_template;

    tmpfs_data_t* data = (tmpfs_data_t*)kmalloc(sizeof(tmpfs_data_t));
    if (!data) {
        kfree(fs);
        return NULL;
    }

    data->max_size = max_size;
    data->used_size = 0;
    fs->private_data = data;

    // Create root directory
    vfs_node_t* root = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (!root) {
        kfree(data);
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
    return fs;
}

static int tmpfs_mount(filesystem_t* fs, const char* device, const char* mountpoint) {
    (void)fs;
    (void)device;
    (void)mountpoint;
    return 0;
}

static int tmpfs_unmount(filesystem_t* fs) {
    if (!fs || !fs->private_data) return -1;

    // Free all memory used by tmpfs
    tmpfs_data_t* data = (tmpfs_data_t*)fs->private_data;
    kfree(data);
    fs->private_data = NULL;

    return 0;
}

static vfs_node_t* tmpfs_create_node(filesystem_t* fs, const char* name, vfs_node_type_t type) {
    if (!fs || !fs->private_data) return NULL;

    tmpfs_data_t* data = (tmpfs_data_t*)fs->private_data;
    (void)data; // TODO: Use data for proper tmpfs management

    vfs_node_t* node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (!node) return NULL;

    // Copy name
    int i;
    for (i = 0; i < FS_NAME_MAX && name[i]; i++) {
        node->name[i] = name[i];
    }
    node->name[i] = '\0';

    node->type = type;
    node->permissions = 0644;
    node->uid = 0;
    node->gid = 0;
    node->size = 0;
    node->inode = 0; // TODO: Proper inode allocation
    node->create_time = 0;
    node->modify_time = 0;
    node->access_time = 0;
    node->parent = NULL;
    node->children = NULL;
    node->next_sibling = NULL;
    node->fs = fs;

    if (type == VFS_FILE) {
        tmpfs_file_t* file_data = (tmpfs_file_t*)kmalloc(sizeof(tmpfs_file_t));
        if (!file_data) {
            kfree(node);
            return NULL;
        }
        file_data->data = NULL;
        file_data->allocated_size = 0;
        node->fs_data = file_data;
    } else {
        node->fs_data = NULL;
    }

    return node;
}

static int tmpfs_delete_node(filesystem_t* fs, vfs_node_t* node) {
    if (!fs || !node) return -1;

    tmpfs_data_t* data = (tmpfs_data_t*)fs->private_data;

    if (node->type == VFS_FILE && node->fs_data) {
        tmpfs_file_t* file_data = (tmpfs_file_t*)node->fs_data;
        if (file_data->data) {
            data->used_size -= file_data->allocated_size;
            kfree(file_data->data);
        }
        kfree(file_data);
    }

    kfree(node);
    return 0;
}

static int tmpfs_read(filesystem_t* fs, vfs_node_t* node, uint64_t offset, void* buffer, size_t size) {
    if (!fs || !node || node->type != VFS_FILE || !node->fs_data) return -1;

    tmpfs_file_t* file_data = (tmpfs_file_t*)node->fs_data;

    if (offset >= node->size) return 0;
    if (offset + size > node->size) {
        size = node->size - offset;
    }

    if (!file_data->data) return 0;

    uint8_t* buf = (uint8_t*)buffer;
    for (size_t i = 0; i < size; i++) {
        buf[i] = file_data->data[offset + i];
    }

    return size;
}

static int tmpfs_write(filesystem_t* fs, vfs_node_t* node, uint64_t offset, const void* buffer, size_t size) {
    if (!fs || !node || node->type != VFS_FILE) return -1;

    tmpfs_data_t* data = (tmpfs_data_t*)fs->private_data;
    tmpfs_file_t* file_data = (tmpfs_file_t*)node->fs_data;

    if (!file_data) return -1;

    // Check if we need to expand the file
    size_t required_size = offset + size;
    if (required_size > file_data->allocated_size) {
        // Round up to nearest page size
        size_t new_size = (required_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

        // Check if we have enough space
        if (data->used_size + (new_size - file_data->allocated_size) > data->max_size) {
            return -1; // Not enough space
        }

        uint8_t* new_data = (uint8_t*)kmalloc(new_size);
        if (!new_data) return -1;

        // Copy existing data
        if (file_data->data) {
            for (size_t i = 0; i < node->size; i++) {
                new_data[i] = file_data->data[i];
            }
            data->used_size -= file_data->allocated_size;
            kfree(file_data->data);
        }

        file_data->data = new_data;
        data->used_size += new_size;
        file_data->allocated_size = new_size;
    }

    // Write the data
    const uint8_t* buf = (const uint8_t*)buffer;
    for (size_t i = 0; i < size; i++) {
        file_data->data[offset + i] = buf[i];
    }

    // Update file size if we wrote beyond the end
    if (offset + size > node->size) {
        node->size = offset + size;
    }

    return size;
}

static int tmpfs_sync(filesystem_t* fs) {
    // tmpfs is already in memory, no need to sync
    (void)fs;
    return 0;
}
