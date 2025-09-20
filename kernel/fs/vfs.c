/*
 * Virtual File System (VFS) Layer
 * Provides unified interface for different file systems
 */

#include "kernel/fs.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"
#include "kernel/types.h"

// Simple memset implementation for kernel use
static void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    for (size_t i = 0; i < n; i++)
    {
        p[i] = (unsigned char)c;
    }
    return s;
}

// Simple strcmp implementation for kernel use
static int strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

// Simple strcpy implementation for kernel use
static char *strcpy(char *dest, const char *src)
{
    char *d = dest;
    while ((*d++ = *src++) != '\0')
        ;
    return dest;
}

// Additional types needed for VFS
typedef uint32_t mode_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;

// File descriptor table
#define MAX_FILE_DESCRIPTORS 1024
static file_descriptor_t *file_descriptors[MAX_FILE_DESCRIPTORS];
static uint32_t __attribute__((unused)) next_fd = 3; // 0, 1, 2 are reserved for stdin, stdout, stderr

// Registered filesystems
static filesystem_t *registered_filesystems = NULL;

// Mount points
static mount_point_t *mount_points = NULL;

// VFS operations mapping
static vfs_operations_t *vfs_ops = NULL;

// Initialize VFS
void fs_init(void)
{
    kprintf("VFS: Initializing...\n");

    // Clear file descriptor table
    memset(file_descriptors, 0, sizeof(file_descriptors));

    // Initialize VFS operations
    vfs_ops = (vfs_operations_t *)kmalloc(sizeof(vfs_operations_t));
    if (!vfs_ops)
    {
        kernel_panic("VFS: Failed to allocate VFS operations");
    }

    // Initialize with default operations (will be overridden by filesystems)
    vfs_ops->open = NULL;
    vfs_ops->close = NULL;
    vfs_ops->read = NULL;
    vfs_ops->write = NULL;
    vfs_ops->stat = NULL;

    kprintf("VFS: Initialized\n");
}

// Register a filesystem
int fs_register(filesystem_t *fs)
{
    if (!fs)
        return -1;

    // Add to registered filesystems list
    fs->next = registered_filesystems;
    registered_filesystems = fs;

    kprintf("VFS: Registered filesystem '%s'\n", fs->name);
    return 0;
}

// Mount a filesystem
int fs_mount(const char *device, const char *mountpoint, const char *fstype)
{
    if (!device || !mountpoint || !fstype)
        return -1;

    // Find the filesystem type
    filesystem_t *fs = registered_filesystems;
    while (fs)
    {
        if (strcmp(fs->name, fstype) == 0)
        {
            break;
        }
        fs = fs->next;
    }

    if (!fs)
    {
        kprintf("VFS: Unknown filesystem type '%s'\n", fstype);
        return -1;
    }

    // Create mount point
    mount_point_t *mp = (mount_point_t *)kmalloc(sizeof(mount_point_t));
    if (!mp)
    {
        kprintf("VFS: Failed to allocate mount point\n");
        return -1;
    }

    strcpy(mp->path, mountpoint);
    mp->fs = fs;
    mp->node = NULL; // Will be set by filesystem mount
    mp->next = mount_points;
    mount_points = mp;

    // Call filesystem mount operation
    if (fs->ops && fs->ops->mount)
    {
        int result = fs->ops->mount(fs, device, mountpoint);
        if (result != 0)
        {
            kprintf("VFS: Filesystem mount failed\n");
            kfree(mp);
            return result;
        }
    }

    // Update VFS operations to point to this filesystem
    vfs_ops = (vfs_operations_t *)fs->private_data;

    kprintf("VFS: Mounted %s on %s\n", fstype, mountpoint);
    return 0;
}

// Unmount a filesystem
int fs_unmount(const char *mountpoint)
{
    if (!mountpoint)
        return -1;

    // Find mount point
    mount_point_t *mp = mount_points;
    mount_point_t *prev = NULL;

    while (mp)
    {
        if (strcmp(mp->path, mountpoint) == 0)
        {
            break;
        }
        prev = mp;
        mp = mp->next;
    }

    if (!mp)
    {
        kprintf("VFS: Mount point not found: %s\n", mountpoint);
        return -1;
    }

    // Call filesystem unmount operation
    if (mp->fs->ops && mp->fs->ops->unmount)
    {
        int result = mp->fs->ops->unmount(mp->fs);
        if (result != 0)
        {
            kprintf("VFS: Filesystem unmount failed\n");
            return result;
        }
    }

    // Remove from mount points list
    if (prev)
    {
        prev->next = mp->next;
    }
    else
    {
        mount_points = mp->next;
    }

    kfree(mp);
    kprintf("VFS: Unmounted %s\n", mountpoint);
    return 0;
}

// Lookup a path in the VFS
vfs_node_t *vfs_lookup(const char *path)
{
    if (!path)
        return NULL;

    // For now, simple implementation - just return NULL
    // TODO: Implement proper path resolution
    (void)path;
    return NULL;
}

// Open a file
int vfs_open(const char *path, uint32_t flags)
{
    if (!path)
        return -1;

    // Find available file descriptor
    int fd = -1;
    for (int i = 0; i < MAX_FILE_DESCRIPTORS; i++)
    {
        if (!file_descriptors[i])
        {
            fd = i;
            break;
        }
    }

    if (fd == -1)
    {
        kprintf("VFS: No available file descriptors\n");
        return -1;
    }

    // Call filesystem open operation
    if (vfs_ops && vfs_ops->open)
    {
        int result = vfs_ops->open(path, flags, 0644); // Default permissions
        if (result < 0)
        {
            return result;
        }

        // Create file descriptor
        file_descriptors[fd] = (file_descriptor_t *)kmalloc(sizeof(file_descriptor_t));
        if (!file_descriptors[fd])
        {
            kprintf("VFS: Failed to allocate file descriptor\n");
            return -1;
        }

        // Initialize file descriptor
        file_descriptors[fd]->node = NULL; // TODO: Set to actual node
        file_descriptors[fd]->offset = 0;
        file_descriptors[fd]->flags = flags;
        file_descriptors[fd]->ref_count = 1;

        return fd;
    }

    return -1;
}

// Close a file
int vfs_close(int fd)
{
    if (fd < 0 || fd >= MAX_FILE_DESCRIPTORS || !file_descriptors[fd])
    {
        return -1;
    }

    // Decrease reference count
    file_descriptors[fd]->ref_count--;

    if (file_descriptors[fd]->ref_count == 0)
    {
        // Call filesystem close operation
        if (vfs_ops && vfs_ops->close)
        {
            vfs_ops->close(fd);
        }

        // Free file descriptor
        kfree(file_descriptors[fd]);
        file_descriptors[fd] = NULL;
    }

    return 0;
}

// Read from a file
ssize_t vfs_read(int fd, void *buffer, size_t size)
{
    if (fd < 0 || fd >= MAX_FILE_DESCRIPTORS || !file_descriptors[fd])
    {
        return -1;
    }

    if (!buffer || size == 0)
    {
        return -1;
    }

    // Call filesystem read operation
    if (vfs_ops && vfs_ops->read)
    {
        ssize_t result = vfs_ops->read(fd, buffer, size);
        if (result > 0)
        {
            file_descriptors[fd]->offset += result;
        }
        return result;
    }

    return -1;
}

// Write to a file
ssize_t vfs_write(int fd, const void *buffer, size_t size)
{
    if (fd < 0 || fd >= MAX_FILE_DESCRIPTORS || !file_descriptors[fd])
    {
        return -1;
    }

    if (!buffer || size == 0)
    {
        return -1;
    }

    // Call filesystem write operation
    if (vfs_ops && vfs_ops->write)
    {
        ssize_t result = vfs_ops->write(fd, buffer, size);
        if (result > 0)
        {
            file_descriptors[fd]->offset += result;
        }
        return result;
    }

    return -1;
}

// Get file status
int vfs_stat(const char *path, struct stat *st)
{
    if (!path || !st)
        return -1;

    // Call filesystem stat operation
    if (vfs_ops && vfs_ops->stat)
    {
        return vfs_ops->stat(path, st);
    }

    return -1;
}

// Create a file or directory
int vfs_create(const char *path, vfs_node_type_t type, uint32_t permissions)
{
    (void)path;
    (void)type;
    (void)permissions;
    // TODO: Implement file/directory creation
    return -1;
}

// Delete a file or directory
int vfs_delete(const char *path)
{
    (void)path;
    // TODO: Implement file/directory deletion
    return -1;
}

// Create a directory
int vfs_mkdir(const char *path, uint32_t permissions)
{
    return vfs_create(path, VFS_DIR, permissions);
}

// Register filesystem with VFS (compatibility function)
int vfs_register_filesystem(const char *name, vfs_operations_t *ops)
{
    if (!name || !ops)
        return -1;

    // Create a filesystem structure
    filesystem_t *fs = (filesystem_t *)kmalloc(sizeof(filesystem_t));
    if (!fs)
    {
        kprintf("VFS: Failed to allocate filesystem structure\n");
        return -1;
    }

    strcpy(fs->name, name);
    fs->type = FS_TYPE_CLOUDFS; // Default type
    fs->root = NULL;
    fs->ops = NULL;         // Not using the old ops structure
    fs->private_data = ops; // Store VFS operations here
    fs->next = NULL;

    // Register the filesystem
    return fs_register(fs);
}

// Get filesystem statistics
int vfs_statfs(const char *path, struct statvfs *st)
{
    (void)path;
    (void)st;
    // TODO: Implement filesystem statistics
    return -1;
}

// Seek in a file
off_t vfs_lseek(int fd, off_t offset, int whence)
{
    if (fd < 0 || fd >= MAX_FILE_DESCRIPTORS || !file_descriptors[fd])
    {
        return -1;
    }

    file_descriptor_t *fd_struct = file_descriptors[fd];

    switch (whence)
    {
    case 0: // SEEK_SET
        fd_struct->offset = offset;
        break;
    case 1: // SEEK_CUR
        fd_struct->offset += offset;
        break;
    case 2: // SEEK_END
        // TODO: Need file size for SEEK_END
        fd_struct->offset = offset; // Placeholder
        break;
    default:
        return -1;
    }

    return fd_struct->offset;
}

// Duplicate a file descriptor
int vfs_dup(int oldfd)
{
    if (oldfd < 0 || oldfd >= MAX_FILE_DESCRIPTORS || !file_descriptors[oldfd])
    {
        return -1;
    }

    // Find available file descriptor
    int newfd = -1;
    for (int i = 0; i < MAX_FILE_DESCRIPTORS; i++)
    {
        if (!file_descriptors[i])
        {
            newfd = i;
            break;
        }
    }

    if (newfd == -1)
    {
        return -1;
    }

    // Duplicate the file descriptor
    file_descriptors[newfd] = file_descriptors[oldfd];
    file_descriptors[newfd]->ref_count++;

    return newfd;
}

// Duplicate a file descriptor to a specific number
int vfs_dup2(int oldfd, int newfd)
{
    if (oldfd < 0 || oldfd >= MAX_FILE_DESCRIPTORS || !file_descriptors[oldfd])
    {
        return -1;
    }

    if (newfd < 0 || newfd >= MAX_FILE_DESCRIPTORS)
    {
        return -1;
    }

    // Close newfd if it's already open
    if (file_descriptors[newfd])
    {
        vfs_close(newfd);
    }

    // Duplicate the file descriptor
    file_descriptors[newfd] = file_descriptors[oldfd];
    file_descriptors[newfd]->ref_count++;

    return newfd;
}
