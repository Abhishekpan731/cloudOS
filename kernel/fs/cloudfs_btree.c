/*
 * CloudFS B-Tree Indexing System
 * High-performance directory indexing with balanced tree structure
 */

#include "kernel/fs.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"

// Simple string functions for kernel use
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

static void *memcpy(void *dest, const void *src, size_t n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

static void *memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    for (size_t i = 0; i < n; i++) {
        p[i] = (unsigned char)c;
    }
    return s;
}

// B-Tree constants
#define CLOUDFS_BTREE_ORDER 32
#define CLOUDFS_BTREE_MIN_KEYS ((CLOUDFS_BTREE_ORDER - 1) / 2)
#define CLOUDFS_MAX_KEY_LENGTH 255

// B-Tree node types
typedef enum
{
    BTREE_LEAF_NODE = 0,
    BTREE_INTERNAL_NODE = 1
} btree_node_type_t;

// B-Tree key structure
typedef struct cloudfs_btree_key
{
    uint64_t hash;                        // Hash of the key for fast comparison
    char key[CLOUDFS_MAX_KEY_LENGTH + 1]; // The actual key (filename)
    uint64_t inode_num;                   // Associated inode number
} __attribute__((packed)) cloudfs_btree_key_t;

// B-Tree node structure
typedef struct cloudfs_btree_node
{
    btree_node_type_t type; // Node type (leaf or internal)
    uint32_t num_keys;      // Number of keys in this node
    uint64_t parent_block;  // Parent node block number (0 for root)
    uint64_t next_block;    // Next leaf node (for leaf nodes only)

    // Keys and children
    cloudfs_btree_key_t keys[CLOUDFS_BTREE_ORDER - 1];
    uint64_t children[CLOUDFS_BTREE_ORDER]; // Child block numbers

    // Padding for alignment
    uint8_t padding[256];
} __attribute__((packed)) cloudfs_btree_node_t;

// B-Tree structure
typedef struct cloudfs_btree
{
    uint64_t root_block;  // Root node block number
    uint32_t height;      // Tree height
    uint64_t num_entries; // Total number of entries
    uint64_t first_leaf;  // First leaf node block
    uint64_t last_leaf;   // Last leaf node block
} cloudfs_btree_t;

// Directory cache entry
typedef struct cloudfs_dir_cache
{
    uint64_t inode_num;     // Directory inode number
    cloudfs_btree_t *btree; // Associated B-tree
    uint64_t last_access;   // Last access time
    struct cloudfs_dir_cache *next;
} cloudfs_dir_cache_t;

// Global B-tree state
static cloudfs_dir_cache_t *dir_cache = NULL;
static uint32_t dir_cache_size = 0;
static const uint32_t __attribute__((unused)) MAX_DIR_CACHE = 1000;

// Forward declarations
static cloudfs_btree_node_t *cloudfs_btree_read_node(uint64_t block_num);
static int cloudfs_btree_write_node(uint64_t block_num, cloudfs_btree_node_t *node);
static uint64_t cloudfs_btree_alloc_node(void);
static void cloudfs_btree_free_node(uint64_t block_num);
static int cloudfs_btree_split_node(cloudfs_btree_node_t *node, uint64_t node_block);
static int cloudfs_btree_insert_nonfull(cloudfs_btree_node_t *node, uint64_t node_block,
                                        const char *key, uint64_t inode_num);
static int cloudfs_btree_insert_into_leaf(cloudfs_btree_node_t *leaf, uint64_t leaf_block,
                                          const char *key, uint64_t inode_num);
static cloudfs_btree_node_t *cloudfs_btree_find_leaf(const char *key, uint64_t *leaf_block);
static uint64_t cloudfs_btree_search(cloudfs_btree_t *btree, const char *key);
static int cloudfs_btree_update(cloudfs_btree_t *btree, const char *key, uint64_t inode_num);

// Hash function for keys
static uint64_t cloudfs_btree_hash_key(const char *key)
{
    uint64_t hash = 0;
    const char *ptr = key;

    // Simple djb2 hash
    while (*ptr)
    {
        hash = ((hash << 5) + hash) + *ptr; // hash * 33 + c
        ptr++;
    }

    return hash;
}

// Compare keys
static int __attribute__((unused)) cloudfs_btree_compare_keys(const cloudfs_btree_key_t *a, const cloudfs_btree_key_t *b)
{
    // First compare hash for speed
    if (a->hash < b->hash)
        return -1;
    if (a->hash > b->hash)
        return 1;

    // If hashes are equal, compare strings
    return strcmp(a->key, b->key);
}

// Initialize B-tree for a directory
cloudfs_btree_t *cloudfs_btree_create(void)
{
    cloudfs_btree_t *btree = (cloudfs_btree_t *)kmalloc(sizeof(cloudfs_btree_t));
    if (!btree)
        return NULL;

    // Create root node
    uint64_t root_block = cloudfs_btree_alloc_node();
    if (root_block == 0)
    {
        kfree(btree);
        return NULL;
    }

    // Initialize root node
    cloudfs_btree_node_t *root = cloudfs_btree_read_node(root_block);
    if (!root)
    {
        cloudfs_btree_free_node(root_block);
        kfree(btree);
        return NULL;
    }

    root->type = BTREE_LEAF_NODE;
    root->num_keys = 0;
    root->parent_block = 0;
    root->next_block = 0;

    if (cloudfs_btree_write_node(root_block, root) != 0)
    {
        cloudfs_btree_free_node(root_block);
        kfree(btree);
        kfree(root);
        return NULL;
    }

    kfree(root);

    // Initialize B-tree structure
    btree->root_block = root_block;
    btree->height = 1;
    btree->num_entries = 0;
    btree->first_leaf = root_block;
    btree->last_leaf = root_block;

    return btree;
}

// Destroy B-tree
void cloudfs_btree_destroy(cloudfs_btree_t *btree)
{
    if (!btree)
        return;

    // TODO: Implement recursive node deletion
    // For now, just mark root as free
    cloudfs_btree_free_node(btree->root_block);
    kfree(btree);
}

// Insert key-value pair into B-tree
int cloudfs_btree_insert(cloudfs_btree_t *btree, const char *key, uint64_t inode_num)
{
    if (!btree || !key)
        return -1;

    // Check if key already exists
    if (cloudfs_btree_search(btree, key) != 0)
    {
        // Key exists, update inode number
        return cloudfs_btree_update(btree, key, inode_num);
    }

    cloudfs_btree_node_t *root = cloudfs_btree_read_node(btree->root_block);
    if (!root)
        return -1;

    // If root is full, split it first
    if (root->num_keys == CLOUDFS_BTREE_ORDER - 1)
    {
        uint64_t new_root_block = cloudfs_btree_alloc_node();
        if (new_root_block == 0)
        {
            kfree(root);
            return -1;
        }

        cloudfs_btree_node_t *new_root = cloudfs_btree_read_node(new_root_block);
        if (!new_root)
        {
            cloudfs_btree_free_node(new_root_block);
            kfree(root);
            return -1;
        }

        // Make old root a child of new root
        new_root->type = BTREE_INTERNAL_NODE;
        new_root->num_keys = 0;
        new_root->parent_block = 0;
        new_root->children[0] = btree->root_block;

        // Split the old root
        if (cloudfs_btree_split_node(root, btree->root_block) != 0)
        {
            cloudfs_btree_free_node(new_root_block);
            kfree(new_root);
            kfree(root);
            return -1;
        }

        // Update tree structure
        btree->root_block = new_root_block;
        btree->height++;

        cloudfs_btree_write_node(new_root_block, new_root);
        kfree(new_root);

        // Retry insertion with new root
        root = cloudfs_btree_read_node(btree->root_block);
        if (!root)
            return -1;
    }

    // Insert into non-full root
    int result = cloudfs_btree_insert_nonfull(root, btree->root_block, key, inode_num);
    kfree(root);

    if (result == 0)
    {
        btree->num_entries++;
    }

    return result;
}

// Search for a key in B-tree
uint64_t cloudfs_btree_search(cloudfs_btree_t *btree, const char *key)
{
    if (!btree || !key)
        return 0;

    uint64_t leaf_block;
    cloudfs_btree_node_t *leaf = cloudfs_btree_find_leaf(key, &leaf_block);
    if (!leaf)
        return 0;

    // Search within the leaf node
    uint64_t search_hash = cloudfs_btree_hash_key(key);
    for (uint32_t i = 0; i < leaf->num_keys; i++)
    {
        if (leaf->keys[i].hash == search_hash &&
            strcmp(leaf->keys[i].key, key) == 0)
        {
            uint64_t inode_num = leaf->keys[i].inode_num;
            kfree(leaf);
            return inode_num;
        }
    }

    kfree(leaf);
    return 0; // Key not found
}

// Update existing key
int cloudfs_btree_update(cloudfs_btree_t *btree, const char *key, uint64_t inode_num)
{
    if (!btree || !key)
        return -1;

    uint64_t leaf_block;
    cloudfs_btree_node_t *leaf = cloudfs_btree_find_leaf(key, &leaf_block);
    if (!leaf)
        return -1;

    // Find and update the key
    uint64_t search_hash = cloudfs_btree_hash_key(key);
    for (uint32_t i = 0; i < leaf->num_keys; i++)
    {
        if (leaf->keys[i].hash == search_hash &&
            strcmp(leaf->keys[i].key, key) == 0)
        {
            leaf->keys[i].inode_num = inode_num;
            cloudfs_btree_write_node(leaf_block, leaf);
            kfree(leaf);
            return 0;
        }
    }

    kfree(leaf);
    return -1; // Key not found
}

// Delete a key from B-tree
int cloudfs_btree_delete(cloudfs_btree_t *btree, const char *key)
{
    if (!btree || !key)
        return -1;

    // TODO: Implement B-tree deletion
    // This is a complex operation that requires careful handling
    // of underflow and redistribution
    (void)btree;
    (void)key;

    return -1; // Not implemented yet
}

// Find the leaf node that should contain the key
static cloudfs_btree_node_t *cloudfs_btree_find_leaf(const char *key, uint64_t *leaf_block)
{
    if (!key)
        return NULL;

    uint64_t current_block = 0; // TODO: Get from btree structure
    cloudfs_btree_node_t *current = cloudfs_btree_read_node(current_block);

    if (!current)
        return NULL;

    uint64_t search_hash = cloudfs_btree_hash_key(key);

    // Traverse down to leaf
    while (current->type == BTREE_INTERNAL_NODE)
    {
        uint32_t i = 0;

        // Find the child to follow
        for (i = 0; i < current->num_keys; i++)
        {
            if (search_hash < current->keys[i].hash ||
                (search_hash == current->keys[i].hash &&
                 strcmp(key, current->keys[i].key) < 0))
            {
                break;
            }
        }

        uint64_t next_block = current->children[i];
        kfree(current);
        current = cloudfs_btree_read_node(next_block);
        current_block = next_block;

        if (!current)
            return NULL;
    }

    *leaf_block = current_block;
    return current;
}

// Insert into a non-full node
static int cloudfs_btree_insert_nonfull(cloudfs_btree_node_t *node, uint64_t node_block,
                                        const char *key, uint64_t inode_num)
{
    if (node->type == BTREE_LEAF_NODE)
    {
        // Insert into leaf node
        return cloudfs_btree_insert_into_leaf(node, node_block, key, inode_num);
    }
    else
    {
        // Find child to insert into
        uint64_t search_hash = cloudfs_btree_hash_key(key);
        uint32_t i = 0;

        for (i = 0; i < node->num_keys; i++)
        {
            if (search_hash < node->keys[i].hash ||
                (search_hash == node->keys[i].hash &&
                 strcmp(key, node->keys[i].key) < 0))
            {
                break;
            }
        }

        uint64_t child_block = node->children[i];
        cloudfs_btree_node_t *child = cloudfs_btree_read_node(child_block);

        if (!child)
            return -1;

        // If child is full, split it
        if (child->num_keys == CLOUDFS_BTREE_ORDER - 1)
        {
            if (cloudfs_btree_split_node(child, child_block) != 0)
            {
                kfree(child);
                return -1;
            }

            // Re-read child after split
            kfree(child);
            child = cloudfs_btree_read_node(child_block);
            if (!child)
                return -1;

            // Find correct child after split
            if (search_hash > node->keys[i].hash ||
                (search_hash == node->keys[i].hash &&
                 strcmp(key, node->keys[i].key) > 0))
            {
                kfree(child);
                child = cloudfs_btree_read_node(node->children[i + 1]);
                if (!child)
                    return -1;
            }
        }

        // Recursively insert into child
        int result = cloudfs_btree_insert_nonfull(child, child_block, key, inode_num);
        kfree(child);

        return result;
    }
}

// Insert into leaf node
static int cloudfs_btree_insert_into_leaf(cloudfs_btree_node_t *leaf, uint64_t leaf_block,
                                          const char *key, uint64_t inode_num)
{
    // Find insertion position
    uint64_t search_hash = cloudfs_btree_hash_key(key);
    uint32_t i = 0;

    for (i = 0; i < leaf->num_keys; i++)
    {
        if (search_hash < leaf->keys[i].hash ||
            (search_hash == leaf->keys[i].hash &&
             strcmp(key, leaf->keys[i].key) < 0))
        {
            break;
        }
    }

    // Shift keys to make room
    for (uint32_t j = leaf->num_keys; j > i; j--)
    {
        memcpy(&leaf->keys[j], &leaf->keys[j - 1], sizeof(cloudfs_btree_key_t));
    }

    // Insert new key
    leaf->keys[i].hash = search_hash;
    strcpy(leaf->keys[i].key, key);
    leaf->keys[i].inode_num = inode_num;
    leaf->num_keys++;

    return cloudfs_btree_write_node(leaf_block, leaf);
}

// Split a node
static int cloudfs_btree_split_node(cloudfs_btree_node_t *node, uint64_t node_block)
{
    uint64_t new_node_block = cloudfs_btree_alloc_node();
    if (new_node_block == 0)
        return -1;

    cloudfs_btree_node_t *new_node = cloudfs_btree_read_node(new_node_block);
    if (!new_node)
    {
        cloudfs_btree_free_node(new_node_block);
        return -1;
    }

    // Copy node type and initialize
    new_node->type = node->type;
    new_node->parent_block = node->parent_block;

    uint32_t split_point = CLOUDFS_BTREE_ORDER / 2;

    if (node->type == BTREE_LEAF_NODE)
    {
        // Split leaf node
        new_node->num_keys = node->num_keys - split_point;

        // Copy keys to new node
        for (uint32_t i = 0; i < new_node->num_keys; i++)
        {
            memcpy(&new_node->keys[i], &node->keys[split_point + i],
                   sizeof(cloudfs_btree_key_t));
        }

        // Update node count
        node->num_keys = split_point;

        // Update leaf links
        new_node->next_block = node->next_block;
        node->next_block = new_node_block;
    }
    else
    {
        // Split internal node
        new_node->num_keys = node->num_keys - split_point - 1;

        // Copy keys to new node
        for (uint32_t i = 0; i < new_node->num_keys; i++)
        {
            memcpy(&new_node->keys[i], &node->keys[split_point + 1 + i],
                   sizeof(cloudfs_btree_key_t));
        }

        // Copy children to new node
        for (uint32_t i = 0; i <= new_node->num_keys; i++)
        {
            new_node->children[i] = node->children[split_point + 1 + i];
        }

        // Update node count
        node->num_keys = split_point;
    }

    // Write both nodes
    int result = cloudfs_btree_write_node(node_block, node);
    if (result == 0)
    {
        result = cloudfs_btree_write_node(new_node_block, new_node);
    }

    kfree(new_node);
    return result;
}

// Read node from disk
static cloudfs_btree_node_t *cloudfs_btree_read_node(uint64_t block_num)
{
    (void)block_num; // TODO: Use block_num parameter
    cloudfs_btree_node_t *node = (cloudfs_btree_node_t *)kmalloc(sizeof(cloudfs_btree_node_t));
    if (!node)
        return NULL;

    // TODO: Read from actual disk blocks
    // For now, this is a placeholder
    memset(node, 0, sizeof(cloudfs_btree_node_t));

    return node;
}

// Write node to disk
static int cloudfs_btree_write_node(uint64_t block_num, cloudfs_btree_node_t *node)
{
    // TODO: Write to actual disk blocks
    // For now, this is a placeholder
    (void)block_num;
    (void)node;
    return 0;
}

// Allocate a new node block
static uint64_t cloudfs_btree_alloc_node(void)
{
    // TODO: Allocate from filesystem block pool
    return 0;
}

// Free a node block
static void cloudfs_btree_free_node(uint64_t block_num)
{
    // TODO: Return to filesystem block pool
    (void)block_num;
}

// Directory cache management
cloudfs_btree_t *cloudfs_btree_get_cache(uint64_t inode_num)
{
    cloudfs_dir_cache_t *entry = dir_cache;

    while (entry)
    {
        if (entry->inode_num == inode_num)
        {
            entry->last_access = 0; // TODO: Get current time
            return entry->btree;
        }
        entry = entry->next;
    }

    return NULL;
}

int cloudfs_btree_put_cache(uint64_t inode_num, cloudfs_btree_t *btree)
{
    // Find existing entry or create new one
    cloudfs_dir_cache_t *entry = dir_cache;
    cloudfs_dir_cache_t *prev = NULL;

    while (entry)
    {
        if (entry->inode_num == inode_num)
        {
            // Update existing entry
            entry->btree = btree;
            entry->last_access = 0; // TODO: Get current time
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }

    // Create new entry
    entry = (cloudfs_dir_cache_t *)kmalloc(sizeof(cloudfs_dir_cache_t));
    if (!entry)
        return -1;

    entry->inode_num = inode_num;
    entry->btree = btree;
    entry->last_access = 0; // TODO: Get current time
    entry->next = NULL;

    if (prev)
    {
        prev->next = entry;
    }
    else
    {
        dir_cache = entry;
    }

    dir_cache_size++;
    return 0;
}

// Clean up directory cache (LRU eviction)
void cloudfs_btree_cleanup_cache(void)
{
    // TODO: Implement LRU cache cleanup
    // Remove least recently used entries when cache is full
}
