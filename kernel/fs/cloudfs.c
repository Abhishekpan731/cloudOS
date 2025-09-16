#include "kernel/fs.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

#define CLOUDFS_MAGIC 0x434C4446  // "CLDF"
#define CLOUDFS_VERSION 1
#define CLOUDFS_BLOCK_SIZE 4096
#define CLOUDFS_MAX_NAME 255

typedef struct cloudfs_superblock {
    uint32_t magic;
    uint32_t version;
    uint32_t block_size;
    uint64_t total_blocks;
    uint64_t free_blocks;
    uint64_t inode_count;
    uint64_t free_inodes;
    uint64_t root_inode;
} cloudfs_superblock_t;

typedef struct cloudfs_inode {
    uint64_t size;
    uint32_t mode;
    uint32_t uid, gid;
    uint64_t create_time;
    uint64_t modify_time;
    uint64_t access_time;
    uint32_t link_count;
    uint32_t block_count;
    uint64_t direct_blocks[12];
    uint64_t indirect_block;
    uint64_t double_indirect;
} cloudfs_inode_t;

typedef struct cloudfs_dirent {
    uint64_t inode;
    uint16_t entry_size;
    uint8_t name_length;
    uint8_t type;
    char name[CLOUDFS_MAX_NAME + 1];
} cloudfs_dirent_t;

typedef struct cloudfs_data {
    cloudfs_superblock_t superblock;
    uint8_t* block_bitmap;
    uint8_t* inode_bitmap;
    cloudfs_inode_t* inode_table;
    uint8_t* data_blocks;
    uint64_t next_inode;
} cloudfs_data_t;

static int cloudfs_mount(filesystem_t* fs, const char* device, const char* mountpoint);
static int cloudfs_unmount(filesystem_t* fs);
static vfs_node_t* cloudfs_create_node(filesystem_t* fs, const char* name, vfs_node_type_t type);
static int cloudfs_delete_node(filesystem_t* fs, vfs_node_t* node);
static int cloudfs_read(filesystem_t* fs, vfs_node_t* node, uint64_t offset, void* buffer, size_t size);
static int cloudfs_write(filesystem_t* fs, vfs_node_t* node, uint64_t offset, const void* buffer, size_t size);
static int cloudfs_sync(filesystem_t* fs);

static filesystem_ops_t cloudfs_ops = {
    .mount = cloudfs_mount,
    .unmount = cloudfs_unmount,
    .create_node = cloudfs_create_node,
    .delete_node = cloudfs_delete_node,
    .read = cloudfs_read,
    .write = cloudfs_write,
    .sync = cloudfs_sync
};

static filesystem_t cloudfs_template = {
    .type = FS_TYPE_CLOUDFS,
    .name = "cloudfs",
    .root = NULL,
    .ops = &cloudfs_ops,
    .private_data = NULL,
    .next = NULL
};

int cloudfs_init(void) {
    return fs_register(&cloudfs_template);
}

static uint64_t cloudfs_alloc_block(cloudfs_data_t* data) {
    uint64_t total_blocks = data->superblock.total_blocks;

    for (uint64_t block = 0; block < total_blocks; block++) {
        uint64_t byte_offset = block / 8;
        uint8_t bit_offset = block % 8;

        if (!(data->block_bitmap[byte_offset] & (1 << bit_offset))) {
            data->block_bitmap[byte_offset] |= (1 << bit_offset);
            data->superblock.free_blocks--;
            return block;
        }
    }

    return 0; // No free blocks
}

static void cloudfs_free_block(cloudfs_data_t* data, uint64_t block) {
    uint64_t byte_offset = block / 8;
    uint8_t bit_offset = block % 8;

    data->block_bitmap[byte_offset] &= ~(1 << bit_offset);
    data->superblock.free_blocks++;
}

static uint64_t cloudfs_alloc_inode(cloudfs_data_t* data) {
    uint64_t inode_count = data->superblock.inode_count;

    for (uint64_t inode = 1; inode <= inode_count; inode++) {
        uint64_t byte_offset = (inode - 1) / 8;
        uint8_t bit_offset = (inode - 1) % 8;

        if (!(data->inode_bitmap[byte_offset] & (1 << bit_offset))) {
            data->inode_bitmap[byte_offset] |= (1 << bit_offset);
            data->superblock.free_inodes--;
            return inode;
        }
    }

    return 0; // No free inodes
}

static void cloudfs_free_inode(cloudfs_data_t* data, uint64_t inode) {
    uint64_t byte_offset = (inode - 1) / 8;
    uint8_t bit_offset = (inode - 1) % 8;

    data->inode_bitmap[byte_offset] &= ~(1 << bit_offset);
    data->superblock.free_inodes++;
}

static vfs_node_t* cloudfs_create_vfs_node(filesystem_t* fs, uint64_t inode_num) {
    cloudfs_data_t* data = (cloudfs_data_t*)fs->private_data;
    cloudfs_inode_t* inode = &data->inode_table[inode_num - 1];

    vfs_node_t* node = (vfs_node_t*)kmalloc(sizeof(vfs_node_t));
    if (!node) return NULL;

    node->type = (inode->mode & 0xF000) == 0x4000 ? VFS_DIR : VFS_FILE;
    node->permissions = inode->mode & 0x0FFF;
    node->uid = inode->uid;
    node->gid = inode->gid;
    node->size = inode->size;
    node->inode = inode_num;
    node->create_time = inode->create_time;
    node->modify_time = inode->modify_time;
    node->access_time = inode->access_time;

    node->parent = NULL;
    node->children = NULL;
    node->next_sibling = NULL;
    node->fs = fs;
    node->fs_data = (void*)inode_num;

    return node;
}

filesystem_t* cloudfs_create(const char* device) {
    (void)device; // TODO: Use actual device

    filesystem_t* fs = (filesystem_t*)kmalloc(sizeof(filesystem_t));
    if (!fs) return NULL;

    *fs = cloudfs_template;

    // Initialize CloudFS data
    cloudfs_data_t* data = (cloudfs_data_t*)kmalloc(sizeof(cloudfs_data_t));
    if (!data) {
        kfree(fs);
        return NULL;
    }

    // Initialize superblock
    data->superblock.magic = CLOUDFS_MAGIC;
    data->superblock.version = CLOUDFS_VERSION;
    data->superblock.block_size = CLOUDFS_BLOCK_SIZE;
    data->superblock.total_blocks = 1024; // 4MB filesystem
    data->superblock.free_blocks = 1024 - 64; // Reserve some blocks for metadata
    data->superblock.inode_count = 256;
    data->superblock.free_inodes = 255; // Reserve inode 1 for root
    data->superblock.root_inode = 1;

    // Allocate bitmaps and tables
    data->block_bitmap = (uint8_t*)kmalloc((data->superblock.total_blocks + 7) / 8);
    data->inode_bitmap = (uint8_t*)kmalloc((data->superblock.inode_count + 7) / 8);
    data->inode_table = (cloudfs_inode_t*)kmalloc(data->superblock.inode_count * sizeof(cloudfs_inode_t));
    data->data_blocks = (uint8_t*)kmalloc(data->superblock.total_blocks * CLOUDFS_BLOCK_SIZE);

    if (!data->block_bitmap || !data->inode_bitmap || !data->inode_table || !data->data_blocks) {
        kfree(data->block_bitmap);
        kfree(data->inode_bitmap);
        kfree(data->inode_table);
        kfree(data->data_blocks);
        kfree(data);
        kfree(fs);
        return NULL;
    }

    // Initialize bitmaps
    for (uint64_t i = 0; i < (data->superblock.total_blocks + 7) / 8; i++) {
        data->block_bitmap[i] = 0;
    }
    for (uint64_t i = 0; i < (data->superblock.inode_count + 7) / 8; i++) {
        data->inode_bitmap[i] = 0;
    }

    // Mark root inode as used
    data->inode_bitmap[0] |= 1;

    // Initialize root inode
    cloudfs_inode_t* root_inode = &data->inode_table[0];
    root_inode->size = 0;
    root_inode->mode = 0x4000 | 0x0755; // Directory with 755 permissions
    root_inode->uid = 0;
    root_inode->gid = 0;
    root_inode->create_time = 0;
    root_inode->modify_time = 0;
    root_inode->access_time = 0;
    root_inode->link_count = 2; // . and ..
    root_inode->block_count = 0;

    for (int i = 0; i < 12; i++) {
        root_inode->direct_blocks[i] = 0;
    }
    root_inode->indirect_block = 0;
    root_inode->double_indirect = 0;

    data->next_inode = 2;
    fs->private_data = data;

    // Create root VFS node
    fs->root = cloudfs_create_vfs_node(fs, 1);
    if (fs->root) {
        for (int i = 0; fs->root->name[i] = "/"[i]; i++);
    }

    return fs;
}

static int cloudfs_mount(filesystem_t* fs, const char* device, const char* mountpoint) {
    (void)device;
    (void)mountpoint;

    if (!fs || !fs->private_data) return -1;

    return 0;
}

static int cloudfs_unmount(filesystem_t* fs) {
    if (!fs || !fs->private_data) return -1;

    cloudfs_sync(fs);
    return 0;
}

static vfs_node_t* cloudfs_create_node(filesystem_t* fs, const char* name, vfs_node_type_t type) {
    if (!fs || !fs->private_data) return NULL;

    cloudfs_data_t* data = (cloudfs_data_t*)fs->private_data;

    uint64_t inode_num = cloudfs_alloc_inode(data);
    if (inode_num == 0) return NULL;

    cloudfs_inode_t* inode = &data->inode_table[inode_num - 1];
    inode->size = 0;
    inode->mode = (type == VFS_DIR ? 0x4000 : 0x8000) | 0x0644;
    inode->uid = 0;
    inode->gid = 0;
    inode->create_time = 0; // TODO: Get actual timestamp
    inode->modify_time = 0;
    inode->access_time = 0;
    inode->link_count = (type == VFS_DIR) ? 2 : 1;
    inode->block_count = 0;

    for (int i = 0; i < 12; i++) {
        inode->direct_blocks[i] = 0;
    }
    inode->indirect_block = 0;
    inode->double_indirect = 0;

    vfs_node_t* node = cloudfs_create_vfs_node(fs, inode_num);
    if (node) {
        // Copy name
        int i;
        for (i = 0; i < FS_NAME_MAX && name[i]; i++) {
            node->name[i] = name[i];
        }
        node->name[i] = '\0';
    }

    return node;
}

static int cloudfs_delete_node(filesystem_t* fs, vfs_node_t* node) {
    if (!fs || !node || !fs->private_data) return -1;

    cloudfs_data_t* data = (cloudfs_data_t*)fs->private_data;
    uint64_t inode_num = (uint64_t)node->fs_data;

    cloudfs_inode_t* inode = &data->inode_table[inode_num - 1];

    // Free all data blocks
    for (int i = 0; i < 12 && inode->direct_blocks[i]; i++) {
        cloudfs_free_block(data, inode->direct_blocks[i]);
    }

    // TODO: Handle indirect blocks

    // Free inode
    cloudfs_free_inode(data, inode_num);

    kfree(node);
    return 0;
}

static int cloudfs_read(filesystem_t* fs, vfs_node_t* node, uint64_t offset, void* buffer, size_t size) {
    if (!fs || !node || !fs->private_data) return -1;

    cloudfs_data_t* data = (cloudfs_data_t*)fs->private_data;
    uint64_t inode_num = (uint64_t)node->fs_data;
    cloudfs_inode_t* inode = &data->inode_table[inode_num - 1];

    if (offset >= inode->size) return 0;
    if (offset + size > inode->size) {
        size = inode->size - offset;
    }

    uint8_t* buf = (uint8_t*)buffer;
    size_t bytes_read = 0;

    while (bytes_read < size) {
        uint64_t block_num = (offset + bytes_read) / CLOUDFS_BLOCK_SIZE;
        uint64_t block_offset = (offset + bytes_read) % CLOUDFS_BLOCK_SIZE;

        if (block_num >= 12) {
            // TODO: Handle indirect blocks
            break;
        }

        if (inode->direct_blocks[block_num] == 0) {
            break; // Sparse file - return zeros
        }

        uint8_t* block_data = &data->data_blocks[inode->direct_blocks[block_num] * CLOUDFS_BLOCK_SIZE];
        size_t copy_size = CLOUDFS_BLOCK_SIZE - block_offset;
        if (copy_size > size - bytes_read) {
            copy_size = size - bytes_read;
        }

        for (size_t i = 0; i < copy_size; i++) {
            buf[bytes_read + i] = block_data[block_offset + i];
        }

        bytes_read += copy_size;
    }

    return bytes_read;
}

static int cloudfs_write(filesystem_t* fs, vfs_node_t* node, uint64_t offset, const void* buffer, size_t size) {
    if (!fs || !node || !fs->private_data) return -1;

    cloudfs_data_t* data = (cloudfs_data_t*)fs->private_data;
    uint64_t inode_num = (uint64_t)node->fs_data;
    cloudfs_inode_t* inode = &data->inode_table[inode_num - 1];

    const uint8_t* buf = (const uint8_t*)buffer;
    size_t bytes_written = 0;

    while (bytes_written < size) {
        uint64_t block_num = (offset + bytes_written) / CLOUDFS_BLOCK_SIZE;
        uint64_t block_offset = (offset + bytes_written) % CLOUDFS_BLOCK_SIZE;

        if (block_num >= 12) {
            // TODO: Handle indirect blocks
            break;
        }

        // Allocate block if needed
        if (inode->direct_blocks[block_num] == 0) {
            uint64_t new_block = cloudfs_alloc_block(data);
            if (new_block == 0) break; // No free blocks

            inode->direct_blocks[block_num] = new_block;
            inode->block_count++;

            // Clear the new block
            uint8_t* block_data = &data->data_blocks[new_block * CLOUDFS_BLOCK_SIZE];
            for (size_t i = 0; i < CLOUDFS_BLOCK_SIZE; i++) {
                block_data[i] = 0;
            }
        }

        uint8_t* block_data = &data->data_blocks[inode->direct_blocks[block_num] * CLOUDFS_BLOCK_SIZE];
        size_t copy_size = CLOUDFS_BLOCK_SIZE - block_offset;
        if (copy_size > size - bytes_written) {
            copy_size = size - bytes_written;
        }

        for (size_t i = 0; i < copy_size; i++) {
            block_data[block_offset + i] = buf[bytes_written + i];
        }

        bytes_written += copy_size;
    }

    // Update file size if we wrote beyond the end
    if (offset + bytes_written > inode->size) {
        inode->size = offset + bytes_written;
        node->size = inode->size;
    }

    return bytes_written;
}

static int cloudfs_sync(filesystem_t* fs) {
    if (!fs || !fs->private_data) return -1;

    // In a real implementation, this would write data to disk
    // For now, data is already in memory

    return 0;
}
