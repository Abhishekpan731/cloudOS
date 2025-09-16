#include "kernel/fs.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

static file_descriptor_t file_table[MAX_OPEN_FILES];
static filesystem_t* filesystem_list = NULL;
static mount_point_t* mount_points = NULL;
static vfs_node_t* root_node = NULL;

void fs_init(void) {
    kprintf("File System: Initializing VFS...\n");

    // Initialize file descriptor table
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        file_table[i].node = NULL;
        file_table[i].offset = 0;
        file_table[i].flags = 0;
        file_table[i].ref_count = 0;
    }

    // Initialize file systems
    cloudfs_init();
    tmpfs_init();
    devfs_init();

    // Create root filesystem (tmpfs for now)
    filesystem_t* rootfs = tmpfs_create(1024 * 1024); // 1MB tmpfs
    if (rootfs) {
        fs_mount(NULL, "/", "tmpfs");

        // Create basic directory structure
        vfs_mkdir("/dev", S_IRUSR | S_IWUSR | S_IXUSR);
        vfs_mkdir("/tmp", S_IRUSR | S_IWUSR | S_IXUSR);
        vfs_mkdir("/proc", S_IRUSR | S_IWUSR | S_IXUSR);
    }

    kprintf("File System: VFS Ready\n");
}

int fs_register(filesystem_t* fs) {
    if (!fs) return -1;

    fs->next = filesystem_list;
    filesystem_list = fs;

    kprintf("File System: Registered %s\n", fs->name);
    return 0;
}

static filesystem_t* find_filesystem(const char* fstype) {
    filesystem_t* current = filesystem_list;

    while (current) {
        int match = 1;
        for (int i = 0; fstype[i] || current->name[i]; i++) {
            if (fstype[i] != current->name[i]) {
                match = 0;
                break;
            }
        }
        if (match) return current;
        current = current->next;
    }
    return NULL;
}

int fs_mount(const char* device, const char* mountpoint, const char* fstype) {
    filesystem_t* fs = find_filesystem(fstype);
    if (!fs) return -1;

    mount_point_t* mp = (mount_point_t*)kmalloc(sizeof(mount_point_t));
    if (!mp) return -1;

    // Copy mountpoint path
    int i;
    for (i = 0; i < FS_PATH_MAX - 1 && mountpoint[i]; i++) {
        mp->path[i] = mountpoint[i];
    }
    mp->path[i] = '\0';

    mp->fs = fs;
    mp->node = fs->root;

    if (fs->ops && fs->ops->mount) {
        if (fs->ops->mount(fs, device, mountpoint) != 0) {
            kfree(mp);
            return -1;
        }
    }

    mp->next = mount_points;
    mount_points = mp;

    // Set root node if mounting at /
    if (mountpoint[0] == '/' && mountpoint[1] == '\0') {
        root_node = fs->root;
    }

    kprintf("File System: Mounted %s at %s\n", fstype, mountpoint);
    return 0;
}

int fs_unmount(const char* mountpoint) {
    mount_point_t** current = &mount_points;

    while (*current) {
        int match = 1;
        for (int i = 0; mountpoint[i] || (*current)->path[i]; i++) {
            if (mountpoint[i] != (*current)->path[i]) {
                match = 0;
                break;
            }
        }

        if (match) {
            mount_point_t* to_remove = *current;

            if (to_remove->fs->ops && to_remove->fs->ops->unmount) {
                to_remove->fs->ops->unmount(to_remove->fs);
            }

            *current = (*current)->next;
            kfree(to_remove);

            kprintf("File System: Unmounted %s\n", mountpoint);
            return 0;
        }
        current = &(*current)->next;
    }
    return -1;
}

static vfs_node_t* resolve_path(const char* path) {
    if (!path || !root_node) return NULL;

    if (path[0] != '/') return NULL; // Relative paths not supported yet

    vfs_node_t* current = root_node;
    char component[FS_NAME_MAX + 1];
    int path_idx = 1; // Skip initial '/'

    while (path[path_idx] && current) {
        // Extract next path component
        int comp_idx = 0;
        while (path[path_idx] && path[path_idx] != '/' && comp_idx < FS_NAME_MAX) {
            component[comp_idx++] = path[path_idx++];
        }
        component[comp_idx] = '\0';

        if (comp_idx == 0) break; // Empty component

        // Skip '/' separator
        if (path[path_idx] == '/') path_idx++;

        // Find child with matching name
        vfs_node_t* child = current->children;
        while (child) {
            int match = 1;
            for (int i = 0; component[i] || child->name[i]; i++) {
                if (component[i] != child->name[i]) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                current = child;
                break;
            }
            child = child->next_sibling;
        }

        if (!child) return NULL; // Path component not found
    }

    return current;
}

vfs_node_t* vfs_lookup(const char* path) {
    return resolve_path(path);
}

int vfs_open(const char* path, uint32_t flags) {
    vfs_node_t* node = resolve_path(path);

    if (!node && (flags & O_CREAT)) {
        // Create file if it doesn't exist and O_CREAT is set
        if (vfs_create(path, VFS_FILE, S_IRUSR | S_IWUSR) == 0) {
            node = resolve_path(path);
        }
    }

    if (!node) return -1;

    // Find free file descriptor
    for (int i = 3; i < MAX_OPEN_FILES; i++) { // Reserve 0,1,2 for stdin,stdout,stderr
        if (file_table[i].node == NULL) {
            file_table[i].node = node;
            file_table[i].flags = flags;
            file_table[i].offset = (flags & O_APPEND) ? node->size : 0;
            file_table[i].ref_count = 1;

            if (flags & O_TRUNC) {
                node->size = 0;
            }

            return i;
        }
    }

    return -1; // No free file descriptors
}

int vfs_close(int fd) {
    if (fd < 0 || fd >= MAX_OPEN_FILES || file_table[fd].node == NULL) {
        return -1;
    }

    file_table[fd].ref_count--;
    if (file_table[fd].ref_count == 0) {
        file_table[fd].node = NULL;
        file_table[fd].offset = 0;
        file_table[fd].flags = 0;
    }

    return 0;
}

ssize_t vfs_read(int fd, void* buffer, size_t size) {
    if (fd < 0 || fd >= MAX_OPEN_FILES || file_table[fd].node == NULL) {
        return -1;
    }

    file_descriptor_t* file = &file_table[fd];
    vfs_node_t* node = file->node;

    if (!node->fs || !node->fs->ops || !node->fs->ops->read) {
        return -1;
    }

    ssize_t bytes_read = node->fs->ops->read(node->fs, node, file->offset, buffer, size);
    if (bytes_read > 0) {
        file->offset += bytes_read;
        node->access_time = 0; // TODO: Get actual timestamp
    }

    return bytes_read;
}

ssize_t vfs_write(int fd, const void* buffer, size_t size) {
    if (fd < 0 || fd >= MAX_OPEN_FILES || file_table[fd].node == NULL) {
        return -1;
    }

    file_descriptor_t* file = &file_table[fd];
    vfs_node_t* node = file->node;

    if (!(file->flags & (O_WRONLY | O_RDWR))) {
        return -1; // Not opened for writing
    }

    if (!node->fs || !node->fs->ops || !node->fs->ops->write) {
        return -1;
    }

    ssize_t bytes_written = node->fs->ops->write(node->fs, node, file->offset, buffer, size);
    if (bytes_written > 0) {
        file->offset += bytes_written;
        if (file->offset > node->size) {
            node->size = file->offset;
        }
        node->modify_time = 0; // TODO: Get actual timestamp
    }

    return bytes_written;
}

int vfs_create(const char* path, vfs_node_type_t type, uint32_t permissions) {
    // Find parent directory
    char parent_path[FS_PATH_MAX];
    char filename[FS_NAME_MAX + 1];

    // Extract parent path and filename
    int last_slash = -1;
    for (int i = 0; path[i]; i++) {
        if (path[i] == '/') last_slash = i;
    }

    if (last_slash == -1) return -1;

    // Copy parent path
    for (int i = 0; i < last_slash && i < FS_PATH_MAX - 1; i++) {
        parent_path[i] = path[i];
    }
    parent_path[last_slash == 0 ? 1 : last_slash] = '\0';
    if (last_slash == 0) {
        parent_path[0] = '/';
        parent_path[1] = '\0';
    }

    // Copy filename
    int j = 0;
    for (int i = last_slash + 1; path[i] && j < FS_NAME_MAX; i++, j++) {
        filename[j] = path[i];
    }
    filename[j] = '\0';

    vfs_node_t* parent = resolve_path(parent_path);
    if (!parent || parent->type != VFS_DIR) return -1;

    if (!parent->fs || !parent->fs->ops || !parent->fs->ops->create_node) {
        return -1;
    }

    vfs_node_t* new_node = parent->fs->ops->create_node(parent->fs, filename, type);
    if (!new_node) return -1;

    new_node->permissions = permissions;
    new_node->parent = parent;

    // Add to parent's children list
    new_node->next_sibling = parent->children;
    parent->children = new_node;

    return 0;
}

int vfs_delete(const char* path) {
    vfs_node_t* node = resolve_path(path);
    if (!node) return -1;

    if (!node->fs || !node->fs->ops || !node->fs->ops->delete_node) {
        return -1;
    }

    // Remove from parent's children list
    if (node->parent) {
        vfs_node_t** current = &node->parent->children;
        while (*current && *current != node) {
            current = &(*current)->next_sibling;
        }
        if (*current) {
            *current = node->next_sibling;
        }
    }

    return node->fs->ops->delete_node(node->fs, node);
}

int vfs_mkdir(const char* path, uint32_t permissions) {
    return vfs_create(path, VFS_DIR, permissions);
}
