# Security Module - Low-Level Design

## Module Overview

The security module provides comprehensive security framework with authentication, authorization, audit logging, and cryptographic services. It implements mandatory access control (MAC), discretionary access control (DAC), capabilities, and container security isolation with support for modern security standards.

## File Structure

```
kernel/security/
├── security.c         - Core security framework (428 lines)
└── include/
    ├── security.h     - Security interface definitions
    ├── auth.h         - Authentication structures
    ├── audit.h        - Audit logging framework
    └── crypto.h       - Cryptographic functions
```

## Core Data Structures

### Security Context

```c
// Security context for processes and objects
typedef struct security_context {
    // User and group identification
    uid_t uid;                   // Real user ID
    uid_t euid;                  // Effective user ID
    uid_t suid;                  // Saved user ID
    gid_t gid;                   // Real group ID
    gid_t egid;                  // Effective group ID
    gid_t sgid;                  // Saved group ID

    // Supplementary groups
    gid_t* groups;               // Supplementary group list
    int ngroups;                 // Number of supplementary groups

    // Capabilities
    capability_set_t caps_effective;   // Effective capabilities
    capability_set_t caps_permitted;   // Permitted capabilities
    capability_set_t caps_inheritable; // Inheritable capabilities
    capability_set_t caps_bounding;    // Bounding set

    // SELinux-style labels
    security_label_t* subject_label;   // Subject security label
    security_label_t* object_label;    // Object security label

    // Container security
    container_id_t container_id;       // Container identifier
    security_namespace_t* sec_ns;      // Security namespace

    // Audit context
    audit_context_t* audit_ctx;        // Audit context

    // Session information
    session_id_t session_id;           // Login session ID
    pid_t login_pid;                   // Login process PID
    char tty[TTY_NAME_MAX];           // Terminal name

    // Security flags
    uint32_t flags;                    // Security flags

    spinlock_t lock;                   // Context protection
    atomic_t ref_count;                // Reference count
} security_context_t;

// Capability set representation
typedef struct capability_set {
    uint64_t cap_mask[2];        // 128 capability bits
} capability_set_t;

// Security label (MAC)
typedef struct security_label {
    char type[SEC_LABEL_MAX];    // Security type
    char role[SEC_LABEL_MAX];    // Security role
    char user[SEC_LABEL_MAX];    // Security user
    char level[SEC_LABEL_MAX];   // Security level (MLS)
    uint32_t hash;               // Label hash for fast comparison
} security_label_t;

// Security namespace for containers
typedef struct security_namespace {
    uint32_t id;                 // Namespace ID
    char name[NS_NAME_MAX];      // Namespace name

    // User/group mapping for containers
    uid_mapping_t* uid_map;      // UID mapping table
    gid_mapping_t* gid_map;      // GID mapping table

    // Namespace-specific policies
    security_policy_t* policies; // Security policies

    atomic_t ref_count;          // Reference count
} security_namespace_t;

// User/Group ID mapping for containers
typedef struct uid_mapping {
    uid_t inside_uid;            // UID inside container
    uid_t outside_uid;           // UID outside container
    uint32_t range;              // Range of mapped UIDs
    struct uid_mapping* next;    // Next mapping
} uid_mapping_t;

typedef struct gid_mapping {
    gid_t inside_gid;            // GID inside container
    gid_t outside_gid;           // GID outside container
    uint32_t range;              // Range of mapped GIDs
    struct gid_mapping* next;    // Next mapping
} gid_mapping_t;
```

### Authentication Framework

```c
// User account information
typedef struct user_account {
    uid_t uid;                   // User ID
    char username[USER_NAME_MAX]; // Username
    char shell[PATH_MAX];        // Default shell
    char home_dir[PATH_MAX];     // Home directory

    // Password information
    char password_hash[HASH_MAX]; // Hashed password
    hash_algorithm_t hash_alg;    // Hash algorithm used
    char salt[SALT_MAX];         // Password salt

    // Account status
    time_t last_login;           // Last login time
    time_t passwd_changed;       // Password change time
    time_t account_expires;      // Account expiration
    bool account_locked;         // Account lock status

    // Login restrictions
    uint32_t failed_attempts;   // Failed login attempts
    time_t lockout_time;         // Account lockout time

    // Groups membership
    gid_t primary_gid;           // Primary group
    gid_t* groups;               // Group memberships
    int ngroups;                 // Number of groups

    // Security attributes
    security_label_t* sec_label; // Security label
    capability_set_t default_caps; // Default capabilities

    spinlock_t lock;             // Account protection
} user_account_t;

// Authentication token
typedef struct auth_token {
    token_type_t type;           // PASSWORD, CERTIFICATE, BIOMETRIC
    uid_t uid;                   // Associated user ID
    time_t issued;               // Token issue time
    time_t expires;              // Token expiration

    union {
        struct {
            char hash[HASH_MAX]; // Password hash
            char salt[SALT_MAX]; // Salt value
        } password;

        struct {
            uint8_t* cert_data;  // Certificate data
            size_t cert_len;     // Certificate length
            uint8_t* key_data;   // Private key data
            size_t key_len;      // Key length
        } certificate;

        struct {
            uint8_t* bio_template; // Biometric template
            size_t template_len;   // Template length
            bio_type_t bio_type;   // Biometric type
        } biometric;
    };

    // Token validation
    bool validated;              // Validation status
    validation_method_t method;  // Validation method used

    atomic_t ref_count;          // Reference count
} auth_token_t;

// Session management
typedef struct login_session {
    session_id_t id;             // Session identifier
    uid_t uid;                   // User ID
    pid_t login_pid;             // Login process

    time_t start_time;           // Session start
    time_t last_activity;        // Last activity
    time_t max_idle;             // Maximum idle time

    char tty[TTY_NAME_MAX];      // Terminal
    char remote_host[HOST_MAX];  // Remote host (if applicable)
    uint32_t remote_addr;        // Remote IP address

    // Session security
    security_context_t* sec_ctx; // Security context
    encryption_key_t* session_key; // Session encryption key

    // Session state
    session_state_t state;       // ACTIVE, IDLE, EXPIRED
    uint32_t flags;              // Session flags

    spinlock_t lock;             // Session protection
} login_session_t;
```

### Access Control Lists

```c
// Access Control Entry
typedef struct acl_entry {
    acl_tag_t tag;               // USER, GROUP, MASK, OTHER
    union {
        uid_t uid;               // User ID (for USER tag)
        gid_t gid;               // Group ID (for GROUP tag)
    };

    access_mode_t perms;         // Read, Write, Execute permissions
    uint32_t flags;              // Entry flags

    struct acl_entry* next;      // Next ACL entry
} acl_entry_t;

// Access Control List
typedef struct access_control_list {
    uint32_t entry_count;        // Number of entries
    acl_entry_t* entries;        // ACL entries

    // Default ACL (for directories)
    uint32_t default_count;      // Default ACL entry count
    acl_entry_t* default_entries; // Default ACL entries

    uint32_t revision;           // ACL revision number
    spinlock_t lock;             // ACL protection
} access_control_list_t;

// Access permission check result
typedef struct access_result {
    bool allowed;                // Access allowed/denied
    access_mode_t granted;       // Granted permissions
    access_reason_t reason;      // Reason for decision
    security_label_t* subject;   // Subject label
    security_label_t* object;    // Object label
} access_result_t;
```

### Audit Framework

```c
// Audit event record
typedef struct audit_record {
    audit_event_t event_type;    // Event type
    uint64_t event_id;           // Unique event ID
    time_t timestamp;            // Event timestamp
    uint32_t serial;             // Serial number

    // Subject information
    uid_t uid;                   // User ID
    pid_t pid;                   // Process ID
    session_id_t session_id;     // Session ID
    char exe[PATH_MAX];          // Executable path
    char comm[TASK_COMM_LEN];    // Command name

    // Object information
    char path[PATH_MAX];         // Object path
    mode_t mode;                 // Object mode
    uid_t obj_uid;               // Object owner
    gid_t obj_gid;               // Object group

    // Event details
    int result;                  // Operation result
    char* msg;                   // Event message
    size_t msg_len;              // Message length

    // Security context
    security_label_t* subj_label; // Subject label
    security_label_t* obj_label;  // Object label

    struct audit_record* next;   // Next record in queue
} audit_record_t;

// Audit configuration
typedef struct audit_config {
    bool enabled;                // Audit enabled/disabled
    audit_level_t level;         // Audit level
    uint32_t rate_limit;         // Events per second limit
    size_t buffer_size;          // Audit buffer size

    // Event filters
    audit_filter_t* filters;     // Audit filters
    uint32_t filter_count;       // Number of filters

    // Output configuration
    char log_file[PATH_MAX];     // Audit log file
    bool remote_logging;         // Remote logging enabled
    char remote_host[HOST_MAX];  // Remote log server
    uint16_t remote_port;        // Remote log port

    spinlock_t lock;             // Configuration lock
} audit_config_t;

// Audit filter
typedef struct audit_filter {
    audit_filter_type_t type;    // INCLUDE, EXCLUDE
    audit_event_t event_mask;    // Event type mask
    uid_t uid;                   // User filter (-1 for any)
    gid_t gid;                   // Group filter (-1 for any)
    char path_pattern[PATH_MAX]; // Path pattern filter

    struct audit_filter* next;   // Next filter
} audit_filter_t;
```

## Core Algorithms

### Access Control Decision Algorithm

```c
// Comprehensive access control check
access_result_t security_check_access(security_context_t* subject,
                                     vfs_node_t* object,
                                     access_mode_t requested) {
    access_result_t result = {0};

    // 1. Check DAC permissions first
    if (!dac_check_access(subject, object, requested)) {
        result.allowed = false;
        result.reason = ACCESS_DENIED_DAC;
        goto audit_and_return;
    }

    // 2. Check capabilities
    if (!capability_check(subject, object, requested)) {
        result.allowed = false;
        result.reason = ACCESS_DENIED_CAPABILITY;
        goto audit_and_return;
    }

    // 3. Check MAC (Mandatory Access Control)
    if (!mac_check_access(subject->subject_label,
                         object->security_label, requested)) {
        result.allowed = false;
        result.reason = ACCESS_DENIED_MAC;
        goto audit_and_return;
    }

    // 4. Check ACLs if present
    if (object->acl) {
        if (!acl_check_access(subject, object->acl, requested)) {
            result.allowed = false;
            result.reason = ACCESS_DENIED_ACL;
            goto audit_and_return;
        }
    }

    // 5. Container-specific checks
    if (subject->container_id != SYSTEM_CONTAINER_ID) {
        if (!container_security_check(subject, object, requested)) {
            result.allowed = false;
            result.reason = ACCESS_DENIED_CONTAINER;
            goto audit_and_return;
        }
    }

    // Access granted
    result.allowed = true;
    result.granted = requested;
    result.reason = ACCESS_GRANTED;

audit_and_return:
    // Audit the access decision
    audit_access_decision(&result, subject, object, requested);

    return result;
}

// Discretionary Access Control (traditional UNIX permissions)
bool dac_check_access(security_context_t* ctx, vfs_node_t* node,
                     access_mode_t mode) {
    mode_t file_mode = node->mode;
    mode_t perms = 0;

    // Owner permissions
    if (ctx->euid == node->uid) {
        perms = (file_mode & S_IRWXU) >> 6;
    }
    // Group permissions
    else if (ctx->egid == node->gid || is_group_member(ctx, node->gid)) {
        perms = (file_mode & S_IRWXG) >> 3;
    }
    // Other permissions
    else {
        perms = file_mode & S_IRWXO;
    }

    // Check if requested mode is granted
    if (mode & ACCESS_READ && !(perms & S_IRUSR)) return false;
    if (mode & ACCESS_WRITE && !(perms & S_IWUSR)) return false;
    if (mode & ACCESS_EXEC && !(perms & S_IXUSR)) return false;

    return true;
}

// Capability-based access control
bool capability_check(security_context_t* ctx, vfs_node_t* node,
                     access_mode_t mode) {
    // Root bypass (CAP_DAC_OVERRIDE)
    if (capability_has(ctx, CAP_DAC_OVERRIDE)) {
        return true;
    }

    // Specific capability checks
    if (mode & ACCESS_READ) {
        if (node->mode & S_IRUSR || capability_has(ctx, CAP_DAC_READ_SEARCH)) {
            // Read access granted
        } else {
            return false;
        }
    }

    if (mode & ACCESS_WRITE) {
        if (ctx->euid == node->uid || capability_has(ctx, CAP_FOWNER)) {
            // Write access granted
        } else {
            return false;
        }
    }

    if (mode & ACCESS_EXEC) {
        // Execute requires specific capability for some files
        if (node->flags & VFS_SETUID && !capability_has(ctx, CAP_SETUID)) {
            return false;
        }
    }

    return true;
}

// Mandatory Access Control (MAC) - simplified SELinux-style
bool mac_check_access(security_label_t* subject, security_label_t* object,
                     access_mode_t mode) {
    if (!subject || !object) {
        return true; // No MAC if labels not present
    }

    // Type enforcement
    if (!type_enforcement_check(subject->type, object->type, mode)) {
        return false;
    }

    // Role-based access control
    if (!rbac_check(subject->role, object->type, mode)) {
        return false;
    }

    // Multi-Level Security (MLS)
    if (!mls_check(subject->level, object->level, mode)) {
        return false;
    }

    return true;
}
```

### Authentication Algorithm

```c
// User authentication process
int authenticate_user(const char* username, auth_token_t* token,
                     login_session_t** session) {
    user_account_t* account = find_user_account(username);
    if (!account) {
        audit_log(AUDIT_LOGIN_FAILED, "Unknown user: %s", username);
        return -ENOENT;
    }

    // Check account status
    if (account->account_locked) {
        audit_log(AUDIT_LOGIN_FAILED, "Account locked: %s", username);
        return -EACCES;
    }

    if (account->account_expires > 0 &&
        get_system_time() > account->account_expires) {
        audit_log(AUDIT_LOGIN_FAILED, "Account expired: %s", username);
        return -EACCES;
    }

    // Check for too many failed attempts
    if (account->failed_attempts >= MAX_LOGIN_ATTEMPTS) {
        time_t lockout_end = account->lockout_time + LOCKOUT_DURATION;
        if (get_system_time() < lockout_end) {
            audit_log(AUDIT_LOGIN_FAILED, "Account temporarily locked: %s", username);
            return -EACCES;
        } else {
            // Reset failed attempts after lockout period
            account->failed_attempts = 0;
        }
    }

    // Validate authentication token
    bool auth_valid = false;
    switch (token->type) {
        case AUTH_PASSWORD:
            auth_valid = validate_password(account, &token->password);
            break;
        case AUTH_CERTIFICATE:
            auth_valid = validate_certificate(account, &token->certificate);
            break;
        case AUTH_BIOMETRIC:
            auth_valid = validate_biometric(account, &token->biometric);
            break;
        default:
            return -EINVAL;
    }

    if (!auth_valid) {
        account->failed_attempts++;
        if (account->failed_attempts >= MAX_LOGIN_ATTEMPTS) {
            account->lockout_time = get_system_time();
        }
        audit_log(AUDIT_LOGIN_FAILED, "Authentication failed: %s", username);
        return -EACCES;
    }

    // Authentication successful
    account->failed_attempts = 0;
    account->last_login = get_system_time();

    // Create login session
    *session = create_login_session(account);
    if (!*session) {
        return -ENOMEM;
    }

    audit_log(AUDIT_LOGIN_SUCCESS, "User logged in: %s", username);
    return 0;
}

// Password validation with secure hash comparison
bool validate_password(user_account_t* account,
                      struct password_auth* pwd_auth) {
    char computed_hash[HASH_MAX];

    // Compute hash of provided password with stored salt
    int result = hash_password(pwd_auth->plaintext, account->salt,
                              account->hash_alg, computed_hash, sizeof(computed_hash));
    if (result != 0) {
        return false;
    }

    // Secure comparison to prevent timing attacks
    return secure_memcmp(computed_hash, account->password_hash, HASH_MAX) == 0;
}

// Timing-attack resistant memory comparison
int secure_memcmp(const void* a, const void* b, size_t len) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    unsigned char result = 0;

    // Always compare all bytes to prevent timing attacks
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }

    return result;
}
```

### Cryptographic Services

```c
// Cryptographic context
typedef struct crypto_context {
    cipher_algorithm_t algorithm; // AES, ChaCha20, etc.
    cipher_mode_t mode;          // CBC, GCM, etc.
    key_size_t key_size;         // 128, 192, 256 bits

    uint8_t* key;                // Encryption key
    uint8_t* iv;                 // Initialization vector
    size_t iv_len;               // IV length

    // Algorithm-specific context
    union {
        struct aes_context aes;
        struct chacha20_context chacha20;
        struct rsa_context rsa;
    };

    // State tracking
    bool initialized;            // Context initialized
    operation_mode_t op_mode;    // ENCRYPT, DECRYPT

    spinlock_t lock;             // Context protection
} crypto_context_t;

// Symmetric encryption (AES-GCM)
int crypto_encrypt_aes_gcm(const uint8_t* plaintext, size_t plain_len,
                          const uint8_t* key, size_t key_len,
                          const uint8_t* iv, size_t iv_len,
                          uint8_t* ciphertext, size_t cipher_len,
                          uint8_t* tag, size_t tag_len) {
    if (!plaintext || !key || !iv || !ciphertext || !tag) {
        return -EINVAL;
    }

    if (cipher_len < plain_len || tag_len < AES_GCM_TAG_SIZE) {
        return -EINVAL;
    }

    // Initialize AES-GCM context
    struct aes_gcm_context ctx;
    int result = aes_gcm_init(&ctx, key, key_len);
    if (result != 0) {
        return result;
    }

    // Set IV
    result = aes_gcm_set_iv(&ctx, iv, iv_len);
    if (result != 0) {
        goto cleanup;
    }

    // Encrypt data
    result = aes_gcm_encrypt(&ctx, plaintext, plain_len, ciphertext);
    if (result != 0) {
        goto cleanup;
    }

    // Generate authentication tag
    result = aes_gcm_finish(&ctx, tag, tag_len);

cleanup:
    aes_gcm_cleanup(&ctx);
    return result;
}

// Hash function (SHA-256)
int crypto_hash_sha256(const uint8_t* data, size_t data_len,
                      uint8_t* hash, size_t hash_len) {
    if (!data || !hash || hash_len < SHA256_DIGEST_SIZE) {
        return -EINVAL;
    }

    struct sha256_context ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, hash);

    return 0;
}

// Digital signature (RSA-PSS)
int crypto_sign_rsa_pss(const uint8_t* message, size_t msg_len,
                       const struct rsa_private_key* key,
                       uint8_t* signature, size_t sig_len) {
    if (!message || !key || !signature) {
        return -EINVAL;
    }

    // Hash message with SHA-256
    uint8_t hash[SHA256_DIGEST_SIZE];
    int result = crypto_hash_sha256(message, msg_len, hash, sizeof(hash));
    if (result != 0) {
        return result;
    }

    // Apply RSA-PSS padding
    uint8_t padded[RSA_MAX_SIZE];
    result = rsa_pss_pad(hash, sizeof(hash), padded, key->size, SALT_LEN_HASH);
    if (result != 0) {
        return result;
    }

    // RSA signature
    return rsa_private_decrypt(padded, key->size, signature, sig_len, key);
}
```

### Container Security Isolation

```c
// Container security policy
typedef struct container_security_policy {
    container_id_t container_id;  // Container identifier

    // Capability restrictions
    capability_set_t allowed_caps; // Allowed capabilities
    capability_set_t dropped_caps;  // Dropped capabilities

    // File system restrictions
    char* allowed_paths;          // Allowed file paths (JSON array)
    char* readonly_paths;         // Read-only paths
    char* masked_paths;           // Masked paths

    // Network restrictions
    bool network_isolated;        // Network isolation
    uint32_t* allowed_ports;      // Allowed port list
    size_t num_allowed_ports;     // Number of allowed ports

    // System call filtering
    bool seccomp_enabled;         // Seccomp filtering enabled
    uint32_t* allowed_syscalls;   // Allowed system calls
    size_t num_allowed_syscalls;  // Number of allowed syscalls

    // Resource limits
    uint64_t max_memory;          // Maximum memory usage
    uint32_t max_processes;       // Maximum number of processes
    uint32_t max_files;           // Maximum open files

    // SELinux context
    security_label_t* container_label; // Container security label

    spinlock_t lock;              // Policy lock
} container_security_policy_t;

// Container security enforcement
bool container_security_check(security_context_t* ctx, vfs_node_t* object,
                             access_mode_t mode) {
    container_security_policy_t* policy = find_container_policy(ctx->container_id);
    if (!policy) {
        // Default restrictive policy for unknown containers
        return false;
    }

    // Check file system access
    if (!is_path_allowed(policy, object->full_path)) {
        return false;
    }

    // Check if path is read-only
    if ((mode & ACCESS_WRITE) && is_path_readonly(policy, object->full_path)) {
        return false;
    }

    // Check masked paths
    if (is_path_masked(policy, object->full_path)) {
        return false;
    }

    return true;
}

// System call filtering (seccomp)
bool seccomp_check_syscall(security_context_t* ctx, int syscall_nr) {
    container_security_policy_t* policy = find_container_policy(ctx->container_id);
    if (!policy || !policy->seccomp_enabled) {
        return true; // No filtering
    }

    // Check if syscall is in allowed list
    for (size_t i = 0; i < policy->num_allowed_syscalls; i++) {
        if (policy->allowed_syscalls[i] == syscall_nr) {
            return true;
        }
    }

    // System call not allowed
    audit_log(AUDIT_SECCOMP_VIOLATION,
             "Container %d attempted blocked syscall %d",
             ctx->container_id, syscall_nr);

    return false;
}
```

## Performance Characteristics

### Algorithm Complexity

| Operation | Time Complexity | Space Complexity | Notes |
|-----------|----------------|------------------|-------|
| Access Control Check | O(n) | O(1) | n = ACL entries |
| User Authentication | O(1) | O(1) | Hash table lookup |
| Capability Check | O(1) | O(1) | Bitmask operation |
| Audit Log Write | O(1) | O(1) | Append operation |
| Crypto Encryption | O(n) | O(1) | n = data size |
| Container Policy Check | O(m) | O(1) | m = policy rules |

### Performance Targets

- **Access Control Decision**: <10μs for typical cases
- **User Authentication**: <1ms including hash computation
- **Audit Log Throughput**: >100K events/sec
- **Encryption Performance**: >1GB/s with AES-NI
- **Container Policy Check**: <5μs per access
- **Security Context Switch**: <1μs additional overhead

## Implementation Status

### Core Security Framework ✅

- ✅ Security contexts and labels
- ✅ Access control decision engine
- ✅ Capability-based security
- ✅ Discretionary access control (DAC)
- ✅ Mandatory access control (MAC)

### Authentication & Authorization ✅

- ✅ User account management
- ✅ Password-based authentication
- ✅ Login session management
- ✅ Access control lists (ACLs)
- ✅ Role-based access control

### Audit Framework ✅

- ✅ Comprehensive audit logging
- ✅ Event filtering and configuration
- ✅ Security event correlation
- ✅ Audit log integrity protection
- ✅ Remote audit logging support

### Cryptographic Services ✅

- ✅ Symmetric encryption (AES-GCM)
- ✅ Hash functions (SHA-256, SHA-512)
- ✅ Digital signatures (RSA, ECDSA)
- ✅ Key derivation (PBKDF2, scrypt)
- ✅ Secure random number generation

### Container Security ✅

- ✅ Container security policies
- ✅ Namespace-based isolation
- ✅ Capability dropping and filtering
- ✅ System call filtering (seccomp)
- ✅ File system access control

### Key Functions Summary

| Function | Purpose | Location | Lines | Status |
|----------|---------|----------|-------|--------|
| `security_init()` | Initialize security framework | security.c:25 | 45 | ✅ |
| `security_check_access()` | Access control decision | security.c:71 | 89 | ✅ |
| `authenticate_user()` | User authentication | security.c:161 | 76 | ✅ |
| `audit_log()` | Audit event logging | security.c:238 | 52 | ✅ |
| `crypto_encrypt()` | Data encryption | security.c:291 | 68 | ✅ |
| `container_security_check()` | Container access control | security.c:360 | 67 | ✅ |

---
*Security Module v1.0 - Comprehensive Multi-Layer Security Framework*