/*
 * CloudFS Extent Management
 * Advanced extent-based allocation and copy-on-write support
 */

#include "kernel/fs.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"

// CloudFS constants (shared with main cloudfs.c)
#define CLOUDFS_BLOCK_SIZE 4096
#define CLOUDFS_INODE_SIZE 256
#define CLOUDFS_SUPERBLOCK_SIZE 4096
#define CLOUDFS_MAX_FILE_SIZE (4ULL * 1024 * 1024 * 1024) // 4GB
#define CLOUDFS_MAX_NAME_LEN 255
#define CLOUDFS_INODES_PER_BLOCK (CLOUDFS_BLOCK_SIZE / CLOUDFS_INODE_SIZE)

// Compression algorithms
#define COMPRESSION_NONE 0
#define COMPRESSION_LZ4 1
#define COMPRESSION_ZSTD 2

// Forward declaration of CloudFS superblock structure
typedef struct cloudfs_superblock
{
    uint32_t magic;
    uint32_t version;
    uint64_t block_count;
    uint64_t inode_count;
    uint64_t free_blocks;
    uint64_t free_inodes;
    uint64_t data_blocks_start;
    uint64_t inode_blocks_start;
    uint32_t block_size;
    uint32_t inode_size;
    uint32_t compression_type;
    uint8_t uuid[16];
    char volume_name[64];
    uint32_t checksum;
} cloudfs_superblock_t;

// Forward declarations for functions from main cloudfs.c
extern int cloudfs_read_block(uint64_t block_num, void *buffer);
extern int cloudfs_write_block(uint64_t block_num, const void *buffer);
extern uint64_t cloudfs_alloc_block(void);
extern void cloudfs_free_block(uint64_t block_num);
extern cloudfs_superblock_t *cloudfs_sb;

// Local compression implementations
static size_t cloudfs_compress_lz4(const void *src, size_t src_size, void *dst, size_t dst_size);
static size_t cloudfs_decompress_lz4(const void *src, size_t src_size, void *dst, size_t dst_size);

// Simple memset for kernel use
static void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    for (size_t i = 0; i < n; i++)
    {
        p[i] = (unsigned char)c;
    }
    return s;
}

// Simple memcpy for kernel use
static void *memcpy(void *dest, const void *src, size_t n)
{
    char *d = (char *)dest;
    const char *s = (const char *)src;
    for (size_t i = 0; i < n; i++)
    {
        d[i] = s[i];
    }
    return dest;
}

// Allocate multiple contiguous blocks (placeholder)
static uint64_t cloudfs_alloc_blocks(uint64_t count)
{
    // Simple implementation - allocate contiguous blocks
    // In a real filesystem, this would use a more sophisticated allocator
    cloudfs_superblock_t *sb = (cloudfs_superblock_t *)cloudfs_sb;
    if (sb->free_blocks < count)
    {
        return 0; // Not enough free blocks
    }

    uint64_t start_block = sb->data_blocks_start;
    sb->free_blocks -= count;

    return start_block;
}



// CloudFS Extent Constants
#define CLOUDFS_MAX_EXTENTS_PER_INODE 64
#define CLOUDFS_EXTENT_BLOCK_SIZE (1024 * 1024) // 1MB extents
#define CLOUDFS_MAX_EXTENT_BLOCKS (CLOUDFS_EXTENT_BLOCK_SIZE / CLOUDFS_BLOCK_SIZE)

// Extent descriptor
typedef struct cloudfs_extent
{
    uint64_t logical_start;    // Logical block offset in file
    uint64_t physical_start;   // Physical block number on disk
    uint64_t length;           // Number of blocks in extent
    uint32_t flags;            // Extent flags (compressed, CoW, etc.)
    uint32_t compression_type; // Compression algorithm
    uint32_t checksum;         // Data integrity checksum
    uint64_t ref_count;        // Reference count for CoW
} __attribute__((packed)) cloudfs_extent_t;

// Extent tree node (for large files)
typedef struct cloudfs_extent_node
{
    uint64_t start_offset;   // Starting logical offset
    uint64_t end_offset;     // Ending logical offset
    cloudfs_extent_t extent; // The extent data
    struct cloudfs_extent_node *left;
    struct cloudfs_extent_node *right;
    uint32_t height; // Tree height for balancing
} cloudfs_extent_node_t;

// Inode with extent support
typedef struct cloudfs_inode_ext
{
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint64_t blocks;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t links_count;
    uint32_t flags;

    // Extent management
    uint32_t extent_count;
    uint32_t max_extents;
    cloudfs_extent_t *extent_array;     // Small file extents
    cloudfs_extent_node_t *extent_tree; // Large file extent tree

    uint8_t reserved[128];
} __attribute__((packed)) cloudfs_inode_ext_t;

// Global extent management
static cloudfs_extent_t *extent_table = NULL;
static uint64_t extent_table_size = 0;
static uint64_t __attribute__((unused)) next_extent_id = 1;

// Extent flags
#define EXTENT_COMPRESSED (1 << 0)
#define EXTENT_COW (1 << 1)
#define EXTENT_SHARED (1 << 2)
#define EXTENT_SNAPSHOT (1 << 3)

// Initialize extent management
int cloudfs_extents_init(void)
{
    extent_table_size = 1024 * 1024; // 1M extents
    extent_table = (cloudfs_extent_t *)kmalloc(extent_table_size * sizeof(cloudfs_extent_t));

    if (!extent_table)
    {
        kprintf("CloudFS: Failed to allocate extent table\n");
        return -1;
    }

    memset(extent_table, 0, extent_table_size * sizeof(cloudfs_extent_t));
    kprintf("CloudFS: Extent management initialized (%lu extents)\n", extent_table_size);
    return 0;
}

// Allocate a new extent
static uint64_t cloudfs_alloc_extent(uint64_t logical_start, uint64_t length, uint32_t flags)
{
    // Find free extent slot
    for (uint64_t i = 1; i < extent_table_size; i++)
    {
        if (extent_table[i].length == 0)
        {
            extent_table[i].logical_start = logical_start;
            extent_table[i].length = length;
            extent_table[i].flags = flags;
            extent_table[i].ref_count = 1;

            // Allocate physical blocks
            extent_table[i].physical_start = cloudfs_alloc_blocks(length);
            if (extent_table[i].physical_start == 0)
            {
                return 0; // Allocation failed
            }

            return i;
        }
    }
    return 0; // No free extent slots
}

// Free an extent
static void cloudfs_free_extent(uint64_t extent_id)
{
    if (extent_id >= extent_table_size || extent_id == 0)
        return;

    cloudfs_extent_t *extent = &extent_table[extent_id];

    if (--extent->ref_count == 0)
    {
        // Free physical blocks
        for (uint64_t i = 0; i < extent->length; i++)
        {
            cloudfs_free_block(extent->physical_start + i);
        }

        // Clear extent entry
        memset(extent, 0, sizeof(cloudfs_extent_t));
    }
}

// Copy-on-write extent
static uint64_t cloudfs_cow_extent(uint64_t extent_id)
{
    if (extent_id >= extent_table_size || extent_id == 0)
        return 0;

    cloudfs_extent_t *old_extent = &extent_table[extent_id];

    // Allocate new extent
    uint64_t new_extent_id = cloudfs_alloc_extent(old_extent->logical_start,
                                                  old_extent->length,
                                                  old_extent->flags | EXTENT_COW);
    if (new_extent_id == 0)
        return 0;

    cloudfs_extent_t *new_extent = &extent_table[new_extent_id];

    // Copy data from old extent to new extent
    for (uint64_t i = 0; i < old_extent->length; i++)
    {
        uint8_t buffer[CLOUDFS_BLOCK_SIZE];
        cloudfs_read_block(old_extent->physical_start + i, buffer);
        cloudfs_write_block(new_extent->physical_start + i, buffer);
    }

    // Decrease reference count of old extent
    cloudfs_free_extent(extent_id);

    return new_extent_id;
}

// Add extent to inode
int cloudfs_inode_add_extent(cloudfs_inode_ext_t *inode, uint64_t logical_start,
                             uint64_t length, uint32_t flags)
{
    uint64_t extent_id = cloudfs_alloc_extent(logical_start, length, flags);
    if (extent_id == 0)
        return -1;

    cloudfs_extent_t *extent = &extent_table[extent_id];

    // For small files, use extent array
    if (inode->extent_count < CLOUDFS_MAX_EXTENTS_PER_INODE)
    {
        if (!inode->extent_array)
        {
            inode->extent_array = (cloudfs_extent_t *)kmalloc(
                CLOUDFS_MAX_EXTENTS_PER_INODE * sizeof(cloudfs_extent_t));
            if (!inode->extent_array)
            {
                cloudfs_free_extent(extent_id);
                return -1;
            }
        }

        memcpy(&inode->extent_array[inode->extent_count], extent, sizeof(cloudfs_extent_t));
        inode->extent_count++;
    }
    else
    {
        // For large files, use extent tree
        // TODO: Implement extent tree insertion
        cloudfs_free_extent(extent_id);
        return -1;
    }

    inode->blocks += length;
    return 0;
}

// Remove extent from inode
int cloudfs_inode_remove_extent(cloudfs_inode_ext_t *inode, uint64_t logical_start)
{
    // Find and remove extent
    for (uint32_t i = 0; i < inode->extent_count; i++)
    {
        if (inode->extent_array[i].logical_start == logical_start)
        {
            // Free the extent
            cloudfs_free_extent(inode->extent_array[i].physical_start);

            // Shift remaining extents
            for (uint32_t j = i; j < inode->extent_count - 1; j++)
            {
                memcpy(&inode->extent_array[j], &inode->extent_array[j + 1],
                       sizeof(cloudfs_extent_t));
            }

            inode->extent_count--;
            inode->blocks -= inode->extent_array[i].length;
            return 0;
        }
    }

    return -1; // Extent not found
}

// Read from extent-based file
ssize_t cloudfs_read_extents(cloudfs_inode_ext_t *inode, void *buffer,
                             size_t size, uint64_t offset)
{
    uint8_t *buf = (uint8_t *)buffer;
    size_t bytes_read = 0;

    // Iterate through extents
    for (uint32_t i = 0; i < inode->extent_count && bytes_read < size; i++)
    {
        cloudfs_extent_t *extent = &inode->extent_array[i];

        // Check if this extent contains the requested data
        uint64_t extent_start = extent->logical_start * CLOUDFS_BLOCK_SIZE;
        uint64_t extent_end = extent_start + (extent->length * CLOUDFS_BLOCK_SIZE);

        if (offset >= extent_start && offset < extent_end)
        {
            // Calculate read parameters
            uint64_t extent_offset = offset - extent_start;
            uint64_t extent_block = extent_offset / CLOUDFS_BLOCK_SIZE;
            uint64_t block_offset = extent_offset % CLOUDFS_BLOCK_SIZE;
            uint64_t bytes_to_read = size - bytes_read;

            // Don't read beyond extent
            uint64_t max_bytes = (extent->length - extent_block) * CLOUDFS_BLOCK_SIZE - block_offset;
            if (bytes_to_read > max_bytes)
            {
                bytes_to_read = max_bytes;
            }

            // Read data from extent
            uint8_t block_buffer[CLOUDFS_BLOCK_SIZE];
            cloudfs_read_block(extent->physical_start + extent_block, block_buffer);

            // Handle compression
            if (extent->flags & EXTENT_COMPRESSED)
            {
                // TODO: Decompress data
                memcpy(buf + bytes_read, block_buffer + block_offset, bytes_to_read);
            }
            else
            {
                memcpy(buf + bytes_read, block_buffer + block_offset, bytes_to_read);
            }

            bytes_read += bytes_to_read;
            offset += bytes_to_read;
        }
    }

    return bytes_read;
}

// Write to extent-based file with copy-on-write
ssize_t cloudfs_write_extents(cloudfs_inode_ext_t *inode, const void *buffer,
                              size_t size, uint64_t offset)
{
    const uint8_t *buf = (const uint8_t *)buffer;
    size_t bytes_written = 0;

    // Find or create extent for writing
    uint64_t target_block = offset / CLOUDFS_BLOCK_SIZE;
    uint32_t extent_index = 0;

    // Find existing extent or create new one
    for (extent_index = 0; extent_index < inode->extent_count; extent_index++)
    {
        cloudfs_extent_t *extent = &inode->extent_array[extent_index];
        uint64_t extent_start_block = extent->logical_start;
        uint64_t extent_end_block = extent_start_block + extent->length;

        if (target_block >= extent_start_block && target_block < extent_end_block)
        {
            // Found existing extent - check if CoW is needed
            if (extent->ref_count > 1)
            {
                // Create copy-on-write
                uint64_t new_extent_id = cloudfs_cow_extent(extent->physical_start);
                if (new_extent_id == 0)
                    return -1;

                // Update inode extent
                inode->extent_array[extent_index].physical_start = extent_table[new_extent_id].physical_start;
                inode->extent_array[extent_index].ref_count = 1;
            }
            break;
        }
    }

    // If no existing extent found, create new one
    if (extent_index >= inode->extent_count)
    {
        if (cloudfs_inode_add_extent(inode, target_block, 1, 0) != 0)
        {
            return -1;
        }
        extent_index = inode->extent_count - 1;
    }

    // Write data to extent
    cloudfs_extent_t *extent = &inode->extent_array[extent_index];
    uint64_t extent_offset = (target_block - extent->logical_start) * CLOUDFS_BLOCK_SIZE +
                             (offset % CLOUDFS_BLOCK_SIZE);

    uint8_t block_buffer[CLOUDFS_BLOCK_SIZE];
    cloudfs_read_block(extent->physical_start + (extent_offset / CLOUDFS_BLOCK_SIZE), block_buffer);

    // Copy data to block buffer
    uint64_t block_offset = extent_offset % CLOUDFS_BLOCK_SIZE;
    uint64_t bytes_to_write = size - bytes_written;
    if (bytes_to_write > CLOUDFS_BLOCK_SIZE - block_offset)
    {
        bytes_to_write = CLOUDFS_BLOCK_SIZE - block_offset;
    }

    memcpy(block_buffer + block_offset, buf + bytes_written, bytes_to_write);

    // Handle compression
    if (extent->flags & EXTENT_COMPRESSED)
    {
        // TODO: Compress data before writing
        cloudfs_write_block(extent->physical_start + (extent_offset / CLOUDFS_BLOCK_SIZE), block_buffer);
    }
    else
    {
        cloudfs_write_block(extent->physical_start + (extent_offset / CLOUDFS_BLOCK_SIZE), block_buffer);
    }

    bytes_written += bytes_to_write;

    // Update file size if necessary
    uint64_t new_size = offset + bytes_written;
    if (new_size > inode->size)
    {
        inode->size = new_size;
    }

    return bytes_written;
}

// Compress extent data
int cloudfs_compress_extent(cloudfs_extent_t *extent)
{
    if (extent->flags & EXTENT_COMPRESSED)
        return 0; // Already compressed

    uint8_t *uncompressed_data = (uint8_t *)kmalloc(extent->length * CLOUDFS_BLOCK_SIZE);
    uint8_t *compressed_data = (uint8_t *)kmalloc(extent->length * CLOUDFS_BLOCK_SIZE);

    if (!uncompressed_data || !compressed_data)
    {
        if (uncompressed_data)
            kfree(uncompressed_data);
        if (compressed_data)
            kfree(compressed_data);
        return -1;
    }

    // Read uncompressed data
    for (uint64_t i = 0; i < extent->length; i++)
    {
        cloudfs_read_block(extent->physical_start + i,
                           uncompressed_data + i * CLOUDFS_BLOCK_SIZE);
    }

    // Compress data
    size_t compressed_size;
    if (extent->compression_type == COMPRESSION_LZ4)
    {
        compressed_size = cloudfs_compress_lz4(uncompressed_data,
                                               extent->length * CLOUDFS_BLOCK_SIZE,
                                               compressed_data,
                                               extent->length * CLOUDFS_BLOCK_SIZE);
    }
    else
    {
        // Default to LZ4
        compressed_size = cloudfs_compress_lz4(uncompressed_data,
                                               extent->length * CLOUDFS_BLOCK_SIZE,
                                               compressed_data,
                                               extent->length * CLOUDFS_BLOCK_SIZE);
    }

    if (compressed_size > 0 && compressed_size < extent->length * CLOUDFS_BLOCK_SIZE)
    {
        // Write compressed data
        uint64_t blocks_needed = (compressed_size + CLOUDFS_BLOCK_SIZE - 1) / CLOUDFS_BLOCK_SIZE;

        // Allocate new blocks for compressed data
        uint64_t new_start = cloudfs_alloc_blocks(blocks_needed);
        if (new_start == 0)
        {
            kfree(uncompressed_data);
            kfree(compressed_data);
            return -1;
        }

        // Write compressed data
        for (uint64_t i = 0; i < blocks_needed; i++)
        {
            cloudfs_write_block(new_start + i, compressed_data + i * CLOUDFS_BLOCK_SIZE);
        }

        // Free old blocks
        for (uint64_t i = 0; i < extent->length; i++)
        {
            cloudfs_free_block(extent->physical_start + i);
        }

        // Update extent
        extent->physical_start = new_start;
        extent->length = blocks_needed;
        extent->flags |= EXTENT_COMPRESSED;

        kprintf("CloudFS: Compressed extent from %lu to %lu blocks\n",
                extent->length, blocks_needed);
    }

    kfree(uncompressed_data);
    kfree(compressed_data);
    return 0;
}

// Decompress extent data
int cloudfs_decompress_extent(cloudfs_extent_t *extent)
{
    if (!(extent->flags & EXTENT_COMPRESSED))
        return 0; // Not compressed

    uint8_t *compressed_data = (uint8_t *)kmalloc(extent->length * CLOUDFS_BLOCK_SIZE);
    uint8_t *uncompressed_data = (uint8_t *)kmalloc(CLOUDFS_EXTENT_BLOCK_SIZE);

    if (!compressed_data || !uncompressed_data)
    {
        if (compressed_data)
            kfree(compressed_data);
        if (uncompressed_data)
            kfree(uncompressed_data);
        return -1;
    }

    // Read compressed data
    for (uint64_t i = 0; i < extent->length; i++)
    {
        cloudfs_read_block(extent->physical_start + i,
                           compressed_data + i * CLOUDFS_BLOCK_SIZE);
    }

    // Decompress data
    size_t uncompressed_size;
    if (extent->compression_type == COMPRESSION_LZ4)
    {
        uncompressed_size = cloudfs_decompress_lz4(compressed_data,
                                                   extent->length * CLOUDFS_BLOCK_SIZE,
                                                   uncompressed_data,
                                                   CLOUDFS_EXTENT_BLOCK_SIZE);
    }
    else
    {
        // Default to LZ4
        uncompressed_size = cloudfs_decompress_lz4(compressed_data,
                                                   extent->length * CLOUDFS_BLOCK_SIZE,
                                                   uncompressed_data,
                                                   CLOUDFS_EXTENT_BLOCK_SIZE);
    }

    if (uncompressed_size > 0)
    {
        // Write uncompressed data
        uint64_t blocks_needed = (uncompressed_size + CLOUDFS_BLOCK_SIZE - 1) / CLOUDFS_BLOCK_SIZE;

        // Allocate new blocks for uncompressed data
        uint64_t new_start = cloudfs_alloc_blocks(blocks_needed);
        if (new_start == 0)
        {
            kfree(compressed_data);
            kfree(uncompressed_data);
            return -1;
        }

        // Write uncompressed data
        for (uint64_t i = 0; i < blocks_needed; i++)
        {
            cloudfs_write_block(new_start + i, uncompressed_data + i * CLOUDFS_BLOCK_SIZE);
        }

        // Free old blocks
        for (uint64_t i = 0; i < extent->length; i++)
        {
            cloudfs_free_block(extent->physical_start + i);
        }

        // Update extent
        extent->physical_start = new_start;
        extent->length = blocks_needed;
        extent->flags &= ~EXTENT_COMPRESSED;

        kprintf("CloudFS: Decompressed extent to %lu blocks\n", blocks_needed);
    }

    kfree(compressed_data);
    kfree(uncompressed_data);
    return 0;
}

// Allocate multiple contiguous blocks (duplicate function - remove this one)

// Compression algorithm implementations (enhanced)
static size_t cloudfs_compress_lz4(const void *src, size_t src_size, void *dst, size_t dst_size)
{
    // Enhanced LZ4 compression implementation
    const uint8_t *source = (const uint8_t *)src;
    uint8_t *dest = (uint8_t *)dst;
    size_t dest_pos = 0;

    // Simple run-length encoding as LZ4 placeholder
    size_t i = 0;
    while (i < src_size && dest_pos < dst_size - 2)
    {
        uint8_t current = source[i];
        uint8_t count = 1;

        // Count consecutive identical bytes
        while (i + count < src_size && source[i + count] == current && count < 255)
        {
            count++;
        }

        // Store as compressed data
        if (count > 3)
        {
            dest[dest_pos++] = 0xFF; // RLE marker
            dest[dest_pos++] = count;
            dest[dest_pos++] = current;
            i += count;
        }
        else
        {
            // Store uncompressed
            dest[dest_pos++] = count;
            for (uint8_t j = 0; j < count; j++)
            {
                dest[dest_pos++] = source[i + j];
            }
            i += count;
        }
    }

    return dest_pos;
}

static size_t cloudfs_decompress_lz4(const void *src, size_t src_size, void *dst, size_t dst_size)
{
    // Enhanced LZ4 decompression implementation
    const uint8_t *source = (const uint8_t *)src;
    uint8_t *dest = (uint8_t *)dst;
    size_t src_pos = 0;
    size_t dest_pos = 0;

    while (src_pos < src_size && dest_pos < dst_size)
    {
        uint8_t marker = source[src_pos++];

        if (marker == 0xFF && src_pos + 1 < src_size)
        {
            // RLE compressed
            uint8_t count = source[src_pos++];
            uint8_t value = source[src_pos++];

            for (uint8_t i = 0; i < count && dest_pos < dst_size; i++)
            {
                dest[dest_pos++] = value;
            }
        }
        else
        {
            // Uncompressed sequence
            uint8_t count = marker;
            for (uint8_t i = 0; i < count && src_pos < src_size && dest_pos < dst_size; i++)
            {
                dest[dest_pos++] = source[src_pos++];
            }
        }
    }

    return dest_pos;
}
