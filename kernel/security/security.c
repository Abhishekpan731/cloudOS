#include "kernel/security.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"
#include "kernel/process.h"

static user_t* users = NULL;
static group_t* groups = NULL;
static auth_session_t* sessions = NULL;
static crypto_key_t* crypto_keys = NULL;
static security_policy_t* current_policy = NULL;
static audit_entry_t* audit_log = NULL;
static uint32_t next_session_id = 1;
static uint32_t next_key_id = 1;

// Default security policy
static security_policy_t default_policy = {
    .policy_id = 1,
    .name = "default",
    .mandatory_access_control = false,
    .capability_based_security = true,
    .audit_enabled = true,
    .password_min_length = 8,
    .session_timeout = 3600, // 1 hour
    .next = NULL
};

void security_init(void) {
    kprintf("Security: Initializing framework...\n");

    current_policy = &default_policy;

    // Create root user
    security_create_user("root", "admin123", 0, 0);

    // Create basic groups
    security_create_group("root", 0);
    security_create_group("users", 100);
    security_create_group("wheel", 1);

    kprintf("Security: Framework ready\n");
}

// Password hashing using simple hash (in production would use bcrypt/scrypt)
static void hash_password(const char* password, const uint8_t* salt,
                         uint8_t* hash) {
    // Simple hash implementation (NOT cryptographically secure)
    uint32_t h = 5381;

    // Hash salt + password
    for (int i = 0; i < SALT_SIZE; i++) {
        h = ((h << 5) + h) + salt[i];
    }

    for (int i = 0; password[i]; i++) {
        h = ((h << 5) + h) + password[i];
    }

    // Fill hash buffer (simplified)
    for (int i = 0; i < PASSWORD_HASH_SIZE; i++) {
        hash[i] = (h >> (i % 32)) & 0xFF;
        h = h * 1103515245 + 12345; // Linear congruential generator
    }
}

static void generate_salt(uint8_t* salt) {
    // Simple random salt generation
    static uint32_t seed = 12345;
    for (int i = 0; i < SALT_SIZE; i++) {
        seed = seed * 1103515245 + 12345;
        salt[i] = seed & 0xFF;
    }
}

int security_create_user(const char* username, const char* password,
                        uint32_t uid, uint32_t gid) {
    if (!username || !password) return -1;

    // Check if user already exists
    if (security_find_user(username)) return -1;

    user_t* user = (user_t*)kmalloc(sizeof(user_t));
    if (!user) return -1;

    user->uid = uid;

    // Copy username
    int i;
    for (i = 0; i < USERNAME_MAX - 1 && username[i]; i++) {
        user->username[i] = username[i];
    }
    user->username[i] = '\0';

    // Generate salt and hash password
    generate_salt(user->salt);
    hash_password(password, user->salt, user->password_hash);

    user->primary_gid = gid;
    user->locked = false;

    // Set default directories
    if (uid == 0) {
        for (i = 0; "/root"[i]; i++) {
            user->home_dir[i] = "/root"[i];
        }
        user->home_dir[i] = '\0';

        for (i = 0; "/bin/sh"[i]; i++) {
            user->shell[i] = "/bin/sh"[i];
        }
        user->shell[i] = '\0';
    } else {
        for (i = 0; "/home/"[i]; i++) {
            user->home_dir[i] = "/home/"[i];
        }
        for (int j = 0; username[j] && i < 255; j++, i++) {
            user->home_dir[i] = username[j];
        }
        user->home_dir[i] = '\0';

        for (i = 0; "/bin/sh"[i]; i++) {
            user->shell[i] = "/bin/sh"[i];
        }
        user->shell[i] = '\0';
    }

    // Add to user list
    user->next = users;
    users = user;

    audit_log_event(0, 0, "USER_CREATE", username, true);
    return 0;
}

int security_delete_user(const char* username) {
    if (!username) return -1;

    user_t** current = &users;
    while (*current) {
        bool match = true;
        for (int i = 0; username[i] || (*current)->username[i]; i++) {
            if (username[i] != (*current)->username[i]) {
                match = false;
                break;
            }
        }

        if (match) {
            user_t* to_delete = *current;
            *current = (*current)->next;
            kfree(to_delete);

            audit_log_event(0, 0, "USER_DELETE", username, true);
            return 0;
        }
        current = &(*current)->next;
    }

    return -1;
}

user_t* security_find_user(const char* username) {
    if (!username) return NULL;

    user_t* current = users;
    while (current) {
        bool match = true;
        for (int i = 0; username[i] || current->username[i]; i++) {
            if (username[i] != current->username[i]) {
                match = false;
                break;
            }
        }
        if (match) return current;
        current = current->next;
    }

    return NULL;
}

user_t* security_find_user_by_uid(uint32_t uid) {
    user_t* current = users;
    while (current) {
        if (current->uid == uid) return current;
        current = current->next;
    }
    return NULL;
}

int security_create_group(const char* groupname, uint32_t gid) {
    if (!groupname) return -1;

    // Check if group already exists
    if (security_find_group(groupname)) return -1;

    group_t* group = (group_t*)kmalloc(sizeof(group_t));
    if (!group) return -1;

    group->gid = gid;

    // Copy groupname
    int i;
    for (i = 0; i < USERNAME_MAX - 1 && groupname[i]; i++) {
        group->groupname[i] = groupname[i];
    }
    group->groupname[i] = '\0';

    group->members = NULL;
    group->member_count = 0;

    // Add to group list
    group->next = groups;
    groups = group;

    audit_log_event(0, 0, "GROUP_CREATE", groupname, true);
    return 0;
}

group_t* security_find_group(const char* groupname) {
    if (!groupname) return NULL;

    group_t* current = groups;
    while (current) {
        bool match = true;
        for (int i = 0; groupname[i] || current->groupname[i]; i++) {
            if (groupname[i] != current->groupname[i]) {
                match = false;
                break;
            }
        }
        if (match) return current;
        current = current->next;
    }

    return NULL;
}

uint32_t security_authenticate(const char* username, const char* password,
                              const char* remote_addr) {
    if (!username || !password) return 0;

    user_t* user = security_find_user(username);
    if (!user || user->locked) {
        audit_log_event(user ? user->uid : 0, 0, "AUTH_FAILED", username, false);
        return 0;
    }

    // Verify password
    uint8_t computed_hash[PASSWORD_HASH_SIZE];
    hash_password(password, user->salt, computed_hash);

    bool password_match = true;
    for (int i = 0; i < PASSWORD_HASH_SIZE; i++) {
        if (computed_hash[i] != user->password_hash[i]) {
            password_match = false;
            break;
        }
    }

    if (!password_match) {
        audit_log_event(user->uid, 0, "AUTH_FAILED", username, false);
        return 0;
    }

    // Create session
    auth_session_t* session = (auth_session_t*)kmalloc(sizeof(auth_session_t));
    if (!session) return 0;

    session->session_id = next_session_id++;
    session->uid = user->uid;
    session->login_time = 0; // TODO: Get actual timestamp
    session->last_activity = session->login_time;
    session->valid = true;

    // Copy remote address
    if (remote_addr) {
        int i;
        for (i = 0; i < 63 && remote_addr[i]; i++) {
            session->remote_addr[i] = remote_addr[i];
        }
        session->remote_addr[i] = '\0';
    } else {
        session->remote_addr[0] = '\0';
    }

    // Add to session list
    session->next = sessions;
    sessions = session;

    audit_log_event(user->uid, 0, "AUTH_SUCCESS", username, true);
    return session->session_id;
}

bool security_check_permission(security_context_t* ctx, uint32_t owner_uid,
                              uint32_t owner_gid, uint32_t permissions,
                              uint32_t requested_access) {
    if (!ctx) return false;

    // Root can do anything
    if (ctx->euid == 0) return true;

    // Check owner permissions
    if (ctx->euid == owner_uid) {
        return (permissions & (requested_access << 6)) != 0;
    }

    // Check group permissions
    if (ctx->egid == owner_gid) {
        return (permissions & (requested_access << 3)) != 0;
    }

    // Check if user is in the owner group
    for (size_t i = 0; i < ctx->group_count; i++) {
        if (ctx->groups[i] == owner_gid) {
            return (permissions & (requested_access << 3)) != 0;
        }
    }

    // Check other permissions
    return (permissions & requested_access) != 0;
}

bool security_has_capability(security_context_t* ctx, capability_t cap) {
    if (!ctx || cap >= CAP_LAST) return false;

    return (ctx->capabilities.effective & (1ULL << cap)) != 0;
}

security_context_t* security_create_context(uint32_t uid, uint32_t gid) {
    security_context_t* ctx = (security_context_t*)kmalloc(sizeof(security_context_t));
    if (!ctx) return NULL;

    ctx->uid = uid;
    ctx->gid = gid;
    ctx->euid = uid;
    ctx->egid = gid;
    ctx->groups = NULL;
    ctx->group_count = 0;

    // Set default capabilities for root
    if (uid == 0) {
        ctx->capabilities.effective = 0xFFFFFFFFFFFFFFFFULL;
        ctx->capabilities.permitted = 0xFFFFFFFFFFFFFFFFULL;
        ctx->capabilities.inheritable = 0;
    } else {
        ctx->capabilities.effective = 0;
        ctx->capabilities.permitted = 0;
        ctx->capabilities.inheritable = 0;
    }

    ctx->security_label[0] = '\0';

    return ctx;
}

void security_free_context(security_context_t* ctx) {
    if (ctx) {
        kfree(ctx->groups);
        kfree(ctx);
    }
}

int audit_log_event(uint32_t uid, uint32_t pid, const char* event_type,
                   const char* description, bool success) {
    audit_entry_t* entry = (audit_entry_t*)kmalloc(sizeof(audit_entry_t));
    if (!entry) return -1;

    entry->timestamp = 0; // TODO: Get actual timestamp
    entry->uid = uid;
    entry->pid = pid;
    entry->success = success;

    // Copy event type
    int i;
    for (i = 0; i < 31 && event_type[i]; i++) {
        entry->event_type[i] = event_type[i];
    }
    entry->event_type[i] = '\0';

    // Copy description
    for (i = 0; i < 255 && description[i]; i++) {
        entry->description[i] = description[i];
    }
    entry->description[i] = '\0';

    // Add to audit log
    entry->next = audit_log;
    audit_log = entry;

    return 0;
}

void* secure_malloc(size_t size) {
    void* ptr = kmalloc(size);
    if (ptr) {
        // Clear allocated memory
        secure_memzero(ptr, size);
    }
    return ptr;
}

void secure_free(void* ptr, size_t size) {
    if (ptr) {
        // Clear memory before freeing
        secure_memzero(ptr, size);
        kfree(ptr);
    }
}

void secure_memzero(void* ptr, size_t size) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}

int secure_memcmp(const void* s1, const void* s2, size_t n) {
    const volatile uint8_t* p1 = (const volatile uint8_t*)s1;
    const volatile uint8_t* p2 = (const volatile uint8_t*)s2;
    volatile int result = 0;

    // Constant-time comparison
    for (size_t i = 0; i < n; i++) {
        result |= p1[i] ^ p2[i];
    }

    return result;
}
