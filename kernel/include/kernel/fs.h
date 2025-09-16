#ifndef KERNEL_FS_H
#define KERNEL_FS_H

#include "types.h"

#define FS_NAME_MAX 255
#define FS_PATH_MAX 4096
#define MAX_OPEN_FILES 1024
#define BLOCK_SIZE 4096

typedef enum {
    VFS_FILE = 1,
    VFS_DIR = 2,
    VFS_SYMLINK = 3,
    VFS_DEVICE = 4
} vfs_node_type_t;

typedef enum {
    FS_TYPE_CLOUDFS = 1,
    FS_TYPE_TMPFS = 2,
    FS_TYPE_DEVFS = 3
} fs_type_t;

typedef struct vfs_node {
    char name[FS_NAME_MAX + 1];
    vfs_node_type_t type;
    uint32_t permissions;
    uint32_t uid, gid;
    uint64_t size;
    uint64_t inode;
    uint64_t create_time;
    uint64_t modify_time;
    uint64_t access_time;

    struct vfs_node* parent;
    struct vfs_node* children;
    struct vfs_node* next_sibling;

    void* fs_data;
    struct filesystem* fs;
} vfs_node_t;

typedef struct file_descriptor {
    vfs_node_t* node;
    uint64_t offset;
    uint32_t flags;
    uint32_t ref_count;
} file_descriptor_t;

typedef struct filesystem_ops {
    int (*mount)(struct filesystem* fs, const char* device, const char* mountpoint);
    int (*unmount)(struct filesystem* fs);
    vfs_node_t* (*create_node)(struct filesystem* fs, const char* name, vfs_node_type_t type);
    int (*delete_node)(struct filesystem* fs, vfs_node_t* node);
    int (*read)(struct filesystem* fs, vfs_node_t* node, uint64_t offset, void* buffer, size_t size);
    int (*write)(struct filesystem* fs, vfs_node_t* node, uint64_t offset, const void* buffer, size_t size);
    int (*sync)(struct filesystem* fs);
} filesystem_ops_t;

typedef struct filesystem {
    fs_type_t type;
    char name[32];
    vfs_node_t* root;
    filesystem_ops_t* ops;
    void* private_data;
    struct filesystem* next;
} filesystem_t;

typedef struct mount_point {
    char path[FS_PATH_MAX];
    filesystem_t* fs;
    vfs_node_t* node;
    struct mount_point* next;
} mount_point_t;

void fs_init(void);
int fs_register(filesystem_t* fs);
int fs_mount(const char* device, const char* mountpoint, const char* fstype);
int fs_unmount(const char* mountpoint);

vfs_node_t* vfs_lookup(const char* path);
int vfs_open(const char* path, uint32_t flags);
int vfs_close(int fd);
ssize_t vfs_read(int fd, void* buffer, size_t size);
ssize_t vfs_write(int fd, const void* buffer, size_t size);
int vfs_create(const char* path, vfs_node_type_t type, uint32_t permissions);
int vfs_delete(const char* path);
int vfs_mkdir(const char* path, uint32_t permissions);

// CloudFS specific
int cloudfs_init(void);
filesystem_t* cloudfs_create(const char* device);

// TmpFS for temporary storage
int tmpfs_init(void);
filesystem_t* tmpfs_create(size_t max_size);

// DevFS for device files
int devfs_init(void);
filesystem_t* devfs_create(void);

#define O_RDONLY    0x00000000
#define O_WRONLY    0x00000001
#define O_RDWR      0x00000002
#define O_CREAT     0x00000040
#define O_TRUNC     0x00000200
#define O_APPEND    0x00000400

#define S_IRUSR     0x00000100
#define S_IWUSR     0x00000080
#define S_IXUSR     0x00000040
#define S_IRGRP     0x00000020
#define S_IWGRP     0x00000010
#define S_IXGRP     0x00000008
#define S_IROTH     0x00000004
#define S_IWOTH     0x00000002
#define S_IXOTH     0x00000001

#endif
