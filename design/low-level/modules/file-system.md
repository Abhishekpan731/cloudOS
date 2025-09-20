# File System Module - Low-Level Design

## Module Overview

The file system module provides a Virtual File System (VFS) layer with multiple concrete file system implementations optimized for cloud workloads. It includes CloudFS (cloud-optimized), tmpfs (in-memory), and devfs (device abstraction) with support for advanced features like journaling, compression, and distributed storage.

## File Structure

```
kernel/fs/
├── vfs.c          - Virtual file system layer (334 lines)
├── cloudfs.c      - Cloud-optimized file system (242 lines)
├── tmpfs.c        - Temporary in-memory file system (184 lines)
├── devfs.c        - Device file system (119 lines)
└── include/
    ├── vfs.h      - VFS interface definitions
    ├── cloudfs.h  - CloudFS specific structures
    └── fs_types.h - Common file system types
```

## Core Data Structures

### VFS Layer Structures

```c
// Virtual File System node (inode equivalent)
typedef struct vfs_node {
    ino_t inode;              // Inode number
    char name[VFS_NAME_MAX];  // File name
    file_type_t type;         // FILE, DIRECTORY, SYMLINK, etc.
    mode_t mode;              // File permissions and type
    uid_t uid;                // Owner user ID
    gid_t gid;                // Owner group ID
    off_t size;               // File size in bytes

    // Timestamps
    time_t atime;             // Last access time
    time_t mtime;             // Last modification time
    time_t ctime;             // Last status change time

    // Links and references
    nlink_t nlinks;           // Number of hard links
    dev_t device;             // Device ID (for device files)

    // VFS operations
    struct vfs_operations* ops; // File operations

    // File system specific data
    void* fs_data;            // Private file system data
    struct super_block* sb;   // Superblock reference

    // Directory entries (if directory)
    struct vfs_node* first_child;  // First child (if directory)
    struct vfs_node* next_sibling; // Next sibling
    struct vfs_node* parent;       // Parent directory

    // Synchronization
    rwlock_t lock;            // Node read-write lock
    atomic_t ref_count;       // Reference counter

    // Caching and buffering
    struct page_cache* cache; // Page cache for file data
    bool dirty;              // Dirty flag for writeback
} vfs_node_t;

// File operations structure
typedef struct vfs_operations {
    ssize_t (*read)(vfs_node_t* node, void* buffer, size_t size, off_t offset);
    ssize_t (*write)(vfs_node_t* node, const void* buffer, size_t size, off_t offset);
    int (*open)(vfs_node_t* node, int flags);
    int (*close)(vfs_node_t* node);
    int (*ioctl)(vfs_node_t* node, unsigned long cmd, void* arg);
    vfs_node_t* (*lookup)(vfs_node_t* dir, const char* name);
    int (*create)(vfs_node_t* dir, const char* name, mode_t mode);
    int (*mkdir)(vfs_node_t* dir, const char* name, mode_t mode);
    int (*unlink)(vfs_node_t* dir, const char* name);
    int (*rmdir)(vfs_node_t* dir, const char* name);
    int (*rename)(vfs_node_t* old_dir, const char* old_name,
                  vfs_node_t* new_dir, const char* new_name);
    int (*truncate)(vfs_node_t* node, off_t size);
    int (*sync)(vfs_node_t* node);
} vfs_operations_t;

// Superblock structure
typedef struct super_block {
    dev_t device;             // Device identifier
    char fs_type[16];         // File system type name
    uint64_t block_size;      // Block size in bytes
    uint64_t total_blocks;    // Total blocks in file system
    uint64_t free_blocks;     // Free blocks available
    uint64_t total_inodes;    // Total inodes
    uint64_t free_inodes;     // Free inodes available

    vfs_node_t* root;         // Root directory node
    struct fs_operations* ops; // File system operations
    void* fs_info;            // File system specific info

    // Mount information
    char mount_point[PATH_MAX]; // Mount point path
    int mount_flags;          // Mount flags

    spinlock_t lock;          // Superblock lock
} super_block_t;

// File descriptor structure
typedef struct file_descriptor {
    vfs_node_t* node;         // Associated VFS node
    off_t offset;             // Current file offset
    int flags;                // Open flags (O_RDONLY, O_WRONLY, etc.)
    mode_t mode;              // File mode
    atomic_t ref_count;       // Reference count
    spinlock_t lock;          // File descriptor lock
} file_descriptor_t;

// File table for process
typedef struct file_table {
    file_descriptor_t** files; // Array of file descriptors
    int max_files;            // Maximum file descriptors
    int num_open;             // Number of open files
    spinlock_t lock;          // File table lock
} file_table_t;
```

### CloudFS Structures

```c
// CloudFS superblock information
typedef struct cloudfs_sb_info {
    uint64_t magic;           // CloudFS magic number
    uint32_t version;         // File system version
    uint64_t block_count;     // Total blocks
    uint64_t inode_count;     // Total inodes
    uint32_t block_size;      // Block size (typically 4KB)

    // Cloud-specific features
    bool compression_enabled; // Compression support
    bool encryption_enabled;  // Encryption support
    bool deduplication;       // Block-level deduplication

    // B+ tree roots
    uint64_t inode_tree_root; // Inode B+ tree root
    uint64_t block_tree_root; // Block allocation B+ tree root

    // Journal information
    uint64_t journal_start;   // Journal start block
    uint64_t journal_size;    // Journal size in blocks
    uint32_t transaction_id;  // Current transaction ID

    // Statistics
    uint64_t files_created;   // Total files created
    uint64_t bytes_written;   // Total bytes written
    uint64_t bytes_read;      // Total bytes read
} cloudfs_sb_info_t;

// CloudFS inode structure
typedef struct cloudfs_inode {
    ino_t inode_num;          // Inode number
    file_type_t type;         // File type
    mode_t mode;              // Permissions
    uid_t uid;                // Owner
    gid_t gid;                // Group
    nlink_t nlinks;           // Hard link count

    uint64_t size;            // File size
    uint32_t block_count;     // Number of blocks allocated

    // Timestamps
    time_t atime, mtime, ctime;

    // Block pointers (extent-based allocation)
    struct cloudfs_extent direct_extents[CLOUDFS_DIRECT_EXTENTS];
    uint64_t indirect_block;  // Indirect block pointer
    uint64_t double_indirect; // Double indirect block pointer

    // Cloud features
    uint32_t compression_type; // Compression algorithm
    uint32_t encryption_key_id; // Encryption key identifier
    uint64_t checksum;        // File content checksum

    // Extended attributes
    uint64_t xattr_block;     // Extended attributes block
} cloudfs_inode_t;

// Extent structure for efficient block allocation
typedef struct cloudfs_extent {
    uint64_t start_block;     // Starting block number
    uint32_t length;          // Length in blocks
    uint32_t flags;           // Extent flags
} cloudfs_extent_t;
```

### TmpFS Structures

```c
// TmpFS node (in-memory only)
typedef struct tmpfs_node {
    vfs_node_t vfs_node;      // Base VFS node
    void* data;               // File data (directly in memory)
    size_t allocated_size;    // Allocated memory size
    struct tmpfs_node* hash_next; // Hash table linkage
} tmpfs_node_t;

// TmpFS superblock
typedef struct tmpfs_sb_info {
    uint64_t max_size;        // Maximum file system size
    uint64_t current_size;    // Current usage
    uint32_t max_inodes;      // Maximum inodes
    uint32_t current_inodes;  // Current inode count

    // Hash table for fast inode lookup
    tmpfs_node_t* inode_hash[TMPFS_HASH_SIZE];
    ino_t next_inode;         // Next inode number

    spinlock_t lock;          // TmpFS lock
} tmpfs_sb_info_t;
```

## Core Algorithms

### VFS Path Resolution

```c
// Path resolution algorithm (handles . .. symlinks etc.)
vfs_node_t* vfs_resolve_path(const char* path, vfs_node_t* base) {
    if (!path || !base) return NULL;

    // Handle absolute vs relative paths
    vfs_node_t* current = (*path == '/') ? vfs_root : base;
    char* path_copy = kstrdup(path);
    char* token;
    char* saveptr;

    // Tokenize path and traverse
    token = strtok_r(path_copy, "/", &saveptr);
    while (token != NULL) {
        if (strcmp(token, ".") == 0) {
            // Current directory - do nothing
        } else if (strcmp(token, "..") == 0) {
            // Parent directory
            if (current->parent) {
                current = current->parent;
            }
        } else {
            // Regular directory/file name
            vfs_node_t* next = vfs_lookup_child(current, token);
            if (!next) {
                kfree(path_copy);
                return NULL; // Path not found
            }

            // Handle symbolic links
            if (next->type == VFS_SYMLINK) {
                char link_target[PATH_MAX];
                ssize_t link_len = vfs_readlink(next, link_target, sizeof(link_target));
                if (link_len > 0) {
                    link_target[link_len] = '\0';
                    vfs_node_t* link_resolved = vfs_resolve_path(link_target, current);
                    if (link_resolved) {
                        current = link_resolved;
                    } else {
                        kfree(path_copy);
                        return NULL;
                    }
                }
            } else {
                current = next;
            }
        }

        token = strtok_r(NULL, "/", &saveptr);
    }

    kfree(path_copy);
    return current;
}

// Child lookup in directory
vfs_node_t* vfs_lookup_child(vfs_node_t* dir, const char* name) {
    if (dir->type != VFS_DIRECTORY) return NULL;

    read_lock(&dir->lock);

    // Use file system specific lookup if available
    if (dir->ops && dir->ops->lookup) {
        vfs_node_t* result = dir->ops->lookup(dir, name);
        read_unlock(&dir->lock);
        return result;
    }

    // Fallback: linear search through children
    for (vfs_node_t* child = dir->first_child; child; child = child->next_sibling) {
        if (strcmp(child->name, name) == 0) {
            read_unlock(&dir->lock);
            return child;
        }
    }

    read_unlock(&dir->lock);
    return NULL;
}
```

### CloudFS B+ Tree Implementation

```c
// B+ tree node for CloudFS indexing
typedef struct btree_node {
    bool is_leaf;             // Leaf node flag
    uint16_t key_count;       // Number of keys in node
    uint64_t keys[BTREE_MAX_KEYS];     // Keys array
    uint64_t values[BTREE_MAX_KEYS];   // Values (for leaf) or child pointers
    struct btree_node* next;  // Next leaf node (leaf nodes only)
    struct btree_node* parent; // Parent node
} btree_node_t;

// B+ tree search algorithm
btree_node_t* btree_search(btree_node_t* root, uint64_t key, uint64_t* value) {
    btree_node_t* current = root;

    // Traverse from root to leaf
    while (current && !current->is_leaf) {
        int i = 0;

        // Find appropriate child
        while (i < current->key_count && key >= current->keys[i]) {
            i++;
        }

        // Move to child node
        current = (btree_node_t*)current->values[i];
    }

    // Search in leaf node
    if (current) {
        for (int i = 0; i < current->key_count; i++) {
            if (current->keys[i] == key) {
                *value = current->values[i];
                return current;
            }
        }
    }

    return NULL; // Key not found
}

// B+ tree insertion with splitting
int btree_insert(btree_node_t** root, uint64_t key, uint64_t value) {
    if (!*root) {
        // Create root node
        *root = create_btree_node(true); // Create as leaf
        (*root)->keys[0] = key;
        (*root)->values[0] = value;
        (*root)->key_count = 1;
        return 0;
    }

    btree_node_t* leaf = btree_find_leaf(*root, key);

    // Check if key already exists
    for (int i = 0; i < leaf->key_count; i++) {
        if (leaf->keys[i] == key) {
            leaf->values[i] = value; // Update existing
            return 0;
        }
    }

    // Insert in leaf node
    if (leaf->key_count < BTREE_MAX_KEYS) {
        // Simple insertion - no split needed
        btree_insert_in_leaf(leaf, key, value);
        return 0;
    }

    // Leaf is full - need to split
    btree_node_t* new_leaf = btree_split_leaf(leaf, key, value);
    uint64_t split_key = new_leaf->keys[0];

    // Propagate split up the tree
    return btree_insert_internal(*root, split_key, new_leaf);
}

// Efficient block allocation using B+ tree
uint64_t cloudfs_alloc_block(super_block_t* sb) {
    cloudfs_sb_info_t* cfs_sb = (cloudfs_sb_info_t*)sb->fs_info;
    uint64_t block_num = 0;

    // Search for free block in allocation tree
    if (btree_search(cfs_sb->block_tree_root, FREE_BLOCK_KEY, &block_num)) {
        // Mark block as allocated
        btree_delete(cfs_sb->block_tree_root, block_num);
        cfs_sb->block_count--;
        return block_num;
    }

    // Allocate new block at end of file system
    block_num = cfs_sb->block_count;
    cfs_sb->block_count++;

    return block_num;
}
```

### Page Cache Implementation

```c
// Page cache for file data
typedef struct page_cache {
    struct page** pages;      // Array of cached pages
    uint32_t page_count;      // Number of pages cached
    uint32_t capacity;        // Cache capacity

    // LRU management
    struct list_head lru_list; // LRU list head
    spinlock_t lru_lock;      // LRU list lock

    // Hash table for fast lookup
    struct hlist_head hash[PAGE_CACHE_HASH_SIZE];
    spinlock_t hash_lock;     // Hash table lock
} page_cache_t;

// Page cache lookup
struct page* page_cache_lookup(page_cache_t* cache, off_t offset) {
    uint32_t hash_key = offset / PAGE_SIZE;
    uint32_t hash_idx = hash_key % PAGE_CACHE_HASH_SIZE;

    spin_lock(&cache->hash_lock);

    struct hlist_node* node;
    struct page* page;

    hlist_for_each_entry(page, node, &cache->hash[hash_idx], hash_list) {
        if (page->offset == (offset & PAGE_MASK)) {
            // Move to front of LRU list
            spin_lock(&cache->lru_lock);
            list_move(&page->lru, &cache->lru_list);
            spin_unlock(&cache->lru_lock);

            spin_unlock(&cache->hash_lock);
            return page;
        }
    }

    spin_unlock(&cache->hash_lock);
    return NULL; // Page not in cache
}

// Read-ahead algorithm for sequential access
void page_cache_readahead(vfs_node_t* node, off_t offset, size_t size) {
    page_cache_t* cache = node->cache;
    off_t start_page = offset & PAGE_MASK;
    off_t end_page = (offset + size + PAGE_SIZE - 1) & PAGE_MASK;

    // Detect sequential access pattern
    static off_t last_offset = 0;
    static vfs_node_t* last_node = NULL;

    bool sequential = (node == last_node && offset == last_offset + PAGE_SIZE);

    if (sequential) {
        // Aggressive read-ahead for sequential access
        end_page += READAHEAD_PAGES * PAGE_SIZE;
    }

    // Read pages into cache
    for (off_t page_offset = start_page; page_offset < end_page; page_offset += PAGE_SIZE) {
        if (!page_cache_lookup(cache, page_offset)) {
            // Page not in cache - trigger async read
            schedule_async_read(node, page_offset);
        }
    }

    last_offset = offset;
    last_node = node;
}
```

### Journal and Transaction Support

```c
// Journal entry for CloudFS
typedef struct journal_entry {
    uint32_t transaction_id;  // Transaction identifier
    journal_op_type_t type;   // Operation type
    uint32_t length;          // Entry length
    uint64_t timestamp;       // Transaction timestamp

    union {
        struct {
            ino_t inode;      // Inode number
            off_t offset;     // Offset in file
            size_t size;      // Data size
            char data[];      // Variable length data
        } write_op;

        struct {
            ino_t inode;      // Inode number
            cloudfs_inode_t old_inode; // Old inode data
            cloudfs_inode_t new_inode; // New inode data
        } inode_op;

        struct {
            uint64_t block;   // Block number
            char data[BLOCK_SIZE]; // Block data
        } block_op;
    };
} journal_entry_t;

// Transaction commit algorithm
int cloudfs_commit_transaction(super_block_t* sb, uint32_t transaction_id) {
    cloudfs_sb_info_t* cfs_sb = (cloudfs_sb_info_t*)sb->fs_info;

    // Write journal entries to disk
    int result = write_journal_entries(sb, transaction_id);
    if (result != 0) {
        return result;
    }

    // Write commit record
    journal_entry_t commit_entry = {
        .transaction_id = transaction_id,
        .type = JOURNAL_COMMIT,
        .length = sizeof(journal_entry_t),
        .timestamp = get_system_time()
    };

    result = write_journal_entry(sb, &commit_entry);
    if (result != 0) {
        return result;
    }

    // Force write to disk
    sync_journal(sb);

    // Apply changes to main file system structures
    result = apply_journal_transaction(sb, transaction_id);

    // Update superblock with new transaction ID
    cfs_sb->transaction_id = transaction_id;
    write_superblock(sb);

    return result;
}

// Journal recovery on mount
int cloudfs_recover_journal(super_block_t* sb) {
    cloudfs_sb_info_t* cfs_sb = (cloudfs_sb_info_t*)sb->fs_info;
    uint32_t last_transaction = cfs_sb->transaction_id;

    // Scan journal for uncommitted transactions
    journal_entry_t* entries = read_journal_entries(sb);

    for (journal_entry_t* entry = entries; entry; entry = next_journal_entry(entry)) {
        if (entry->transaction_id > last_transaction) {
            // Find corresponding commit record
            if (find_commit_record(sb, entry->transaction_id)) {
                // Transaction committed but not applied - apply it
                apply_journal_transaction(sb, entry->transaction_id);
                cfs_sb->transaction_id = entry->transaction_id;
            } else {
                // Uncommitted transaction - rollback
                rollback_journal_transaction(sb, entry->transaction_id);
            }
        }
    }

    // Clean up journal
    truncate_journal(sb);

    return 0;
}
```

## File System Operations

### File I/O Implementation

```c
// Generic file read operation
ssize_t vfs_read(file_descriptor_t* fd, void* buffer, size_t size) {
    vfs_node_t* node = fd->node;

    if (!(fd->flags & O_READ)) {
        return -EBADF; // File not open for reading
    }

    if (fd->offset >= node->size) {
        return 0; // EOF
    }

    // Limit read size to available data
    size_t bytes_to_read = min(size, node->size - fd->offset);

    ssize_t bytes_read;

    // Use page cache for regular files
    if (node->type == VFS_FILE && node->cache) {
        bytes_read = page_cache_read(node, buffer, bytes_to_read, fd->offset);
    } else {
        // Direct file system read
        bytes_read = node->ops->read(node, buffer, bytes_to_read, fd->offset);
    }

    if (bytes_read > 0) {
        fd->offset += bytes_read;
        node->atime = get_system_time(); // Update access time
    }

    return bytes_read;
}

// Generic file write operation
ssize_t vfs_write(file_descriptor_t* fd, const void* buffer, size_t size) {
    vfs_node_t* node = fd->node;

    if (!(fd->flags & O_WRITE)) {
        return -EBADF; // File not open for writing
    }

    // Handle append mode
    if (fd->flags & O_APPEND) {
        fd->offset = node->size;
    }

    ssize_t bytes_written;

    // Use page cache for regular files
    if (node->type == VFS_FILE && node->cache) {
        bytes_written = page_cache_write(node, buffer, size, fd->offset);
    } else {
        // Direct file system write
        bytes_written = node->ops->write(node, buffer, size, fd->offset);
    }

    if (bytes_written > 0) {
        fd->offset += bytes_written;

        // Update file size if we wrote past EOF
        if (fd->offset > node->size) {
            node->size = fd->offset;
        }

        // Update timestamps
        node->mtime = get_system_time();
        node->ctime = node->mtime;
        node->dirty = true;
    }

    return bytes_written;
}

// Directory listing operation
int vfs_readdir(file_descriptor_t* fd, struct dirent* dirp, size_t count) {
    vfs_node_t* dir = fd->node;

    if (dir->type != VFS_DIRECTORY) {
        return -ENOTDIR;
    }

    read_lock(&dir->lock);

    vfs_node_t* current = dir->first_child;
    int entries_read = 0;
    size_t offset = 0;

    // Skip entries based on current offset
    while (current && offset < fd->offset) {
        current = current->next_sibling;
        offset++;
    }

    // Read directory entries
    while (current && (offset + sizeof(struct dirent)) <= count) {
        struct dirent* entry = (struct dirent*)((char*)dirp + entries_read * sizeof(struct dirent));

        entry->d_ino = current->inode;
        entry->d_type = vfs_type_to_dirent_type(current->type);
        strncpy(entry->d_name, current->name, sizeof(entry->d_name));

        entries_read++;
        fd->offset++;
        current = current->next_sibling;
    }

    read_unlock(&dir->lock);

    return entries_read;
}
```

## Performance Characteristics

### Algorithm Complexity

| Operation | Time Complexity | Space Complexity | Notes |
|-----------|----------------|------------------|-------|
| Path Resolution | O(d) | O(1) | d = path depth |
| File Read/Write | O(1) | O(1) | With page cache |
| Directory Lookup | O(n) | O(1) | Linear search fallback |
| B+ Tree Search | O(log n) | O(1) | CloudFS indexing |
| B+ Tree Insert | O(log n) | O(1) | May require splits |
| Page Cache Lookup | O(1) | O(1) | Hash table based |
| Journal Write | O(1) | O(1) | Sequential append |

### Performance Targets

- **File Open Latency**: <50μs for cached inodes
- **Sequential Read**: >1GB/s with proper caching
- **Random Read**: >100MB/s with SSD storage
- **Directory Lookup**: <10μs for small directories
- **Journal Commit**: <1ms for typical transactions
- **Cache Hit Ratio**: >90% for typical workloads

## Implementation Status

### VFS Layer ✅
- ✅ Path resolution and mounting
- ✅ File descriptor management
- ✅ Generic file operations
- ✅ Directory operations
- ✅ Symbolic link handling

### CloudFS ✅
- ✅ B+ tree indexing
- ✅ Extent-based allocation
- ✅ Journal and transactions
- ✅ Compression support
- ✅ Cloud storage integration

### TmpFS ✅
- ✅ In-memory file storage
- ✅ Fast allocation/deallocation
- ✅ Memory pressure handling
- ✅ POSIX compliance

### DevFS ✅
- ✅ Device file abstraction
- ✅ Character and block devices
- ✅ Dynamic device registration
- ✅ Special file support

### Key Functions Summary

| Function | Purpose | Location | Lines | Status |
|----------|---------|----------|-------|--------|
| `vfs_init()` | Initialize VFS layer | vfs.c:15 | 28 | ✅ |
| `vfs_mount()` | Mount file system | vfs.c:44 | 52 | ✅ |
| `vfs_open()` | Open file/directory | vfs.c:97 | 45 | ✅ |
| `vfs_read()` | Read from file | vfs.c:143 | 38 | ✅ |
| `vfs_write()` | Write to file | vfs.c:182 | 41 | ✅ |
| `cloudfs_mkfs()` | Create CloudFS | cloudfs.c:22 | 67 | ✅ |
| `tmpfs_alloc()` | Allocate tmpfs node | tmpfs.c:35 | 24 | ✅ |

---
*File System Module v1.0 - Cloud-Optimized Multi-Layer Architecture*