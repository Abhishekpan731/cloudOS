#ifndef KERNEL_SECURITY_H
#define KERNEL_SECURITY_H

#include "types.h"

#define MAX_USERS 1024
#define MAX_GROUPS 256
#define USERNAME_MAX 32
#define PASSWORD_HASH_SIZE 32
#define SALT_SIZE 16

// User and Group Management
typedef struct user {
    uint32_t uid;
    char username[USERNAME_MAX];
    uint8_t password_hash[PASSWORD_HASH_SIZE];
    uint8_t salt[SALT_SIZE];
    uint32_t primary_gid;
    char home_dir[256];
    char shell[256];
    bool locked;
    struct user* next;
} user_t;

typedef struct group {
    uint32_t gid;
    char groupname[USERNAME_MAX];
    uint32_t* members;
    size_t member_count;
    struct group* next;
} group_t;

// Capabilities
typedef enum {
    CAP_CHOWN = 0,
    CAP_DAC_OVERRIDE = 1,
    CAP_DAC_READ_SEARCH = 2,
    CAP_FOWNER = 3,
    CAP_FSETID = 4,
    CAP_KILL = 5,
    CAP_SETGID = 6,
    CAP_SETUID = 7,
    CAP_SETPCAP = 8,
    CAP_LINUX_IMMUTABLE = 9,
    CAP_NET_BIND_SERVICE = 10,
    CAP_NET_BROADCAST = 11,
    CAP_NET_ADMIN = 12,
    CAP_NET_RAW = 13,
    CAP_IPC_LOCK = 14,
    CAP_IPC_OWNER = 15,
    CAP_SYS_MODULE = 16,
    CAP_SYS_RAWIO = 17,
    CAP_SYS_CHROOT = 18,
    CAP_SYS_PTRACE = 19,
    CAP_SYS_PACCT = 20,
    CAP_SYS_ADMIN = 21,
    CAP_SYS_BOOT = 22,
    CAP_SYS_NICE = 23,
    CAP_SYS_RESOURCE = 24,
    CAP_SYS_TIME = 25,
    CAP_SYS_TTY_CONFIG = 26,
    CAP_LAST = 27
} capability_t;

typedef struct capability_set {
    uint64_t effective;
    uint64_t permitted;
    uint64_t inheritable;
} capability_set_t;

// Security Context
typedef struct security_context {
    uint32_t uid;
    uint32_t gid;
    uint32_t euid;
    uint32_t egid;
    uint32_t* groups;
    size_t group_count;
    capability_set_t capabilities;
    char security_label[256];
} security_context_t;

// Authentication
typedef struct auth_session {
    uint32_t session_id;
    uint32_t uid;
    uint64_t login_time;
    uint64_t last_activity;
    char remote_addr[64];
    bool valid;
    struct auth_session* next;
} auth_session_t;

// Cryptographic Services
typedef enum {
    CRYPTO_AES_128 = 1,
    CRYPTO_AES_256 = 2,
    CRYPTO_SHA256 = 3,
    CRYPTO_SHA512 = 4,
    CRYPTO_RSA_2048 = 5,
    CRYPTO_RSA_4096 = 6
} crypto_algorithm_t;

typedef struct crypto_key {
    uint32_t key_id;
    crypto_algorithm_t algorithm;
    uint8_t* key_data;
    size_t key_size;
    bool is_private;
    struct crypto_key* next;
} crypto_key_t;

// Security Policy
typedef struct security_policy {
    uint32_t policy_id;
    char name[64];
    bool mandatory_access_control;
    bool capability_based_security;
    bool audit_enabled;
    uint32_t password_min_length;
    uint32_t session_timeout;
    struct security_policy* next;
} security_policy_t;

// Audit Log Entry
typedef struct audit_entry {
    uint64_t timestamp;
    uint32_t uid;
    uint32_t pid;
    char event_type[32];
    char description[256];
    bool success;
    struct audit_entry* next;
} audit_entry_t;

// Security Initialization
void security_init(void);

// User Management
int security_create_user(const char* username, const char* password,
                        uint32_t uid, uint32_t gid);
int security_delete_user(const char* username);
user_t* security_find_user(const char* username);
user_t* security_find_user_by_uid(uint32_t uid);
int security_change_password(const char* username, const char* old_password,
                            const char* new_password);
int security_lock_user(const char* username);
int security_unlock_user(const char* username);

// Group Management
int security_create_group(const char* groupname, uint32_t gid);
int security_delete_group(const char* groupname);
group_t* security_find_group(const char* groupname);
group_t* security_find_group_by_gid(uint32_t gid);
int security_add_user_to_group(uint32_t uid, uint32_t gid);
int security_remove_user_from_group(uint32_t uid, uint32_t gid);

// Authentication
uint32_t security_authenticate(const char* username, const char* password,
                              const char* remote_addr);
int security_validate_session(uint32_t session_id);
int security_logout(uint32_t session_id);

// Authorization
bool security_check_permission(security_context_t* ctx, uint32_t owner_uid,
                              uint32_t owner_gid, uint32_t permissions,
                              uint32_t requested_access);
bool security_has_capability(security_context_t* ctx, capability_t cap);
int security_set_capability(security_context_t* ctx, capability_t cap, bool value);

// Security Context Management
security_context_t* security_get_context(uint32_t pid);
int security_set_context(uint32_t pid, security_context_t* ctx);
security_context_t* security_create_context(uint32_t uid, uint32_t gid);
void security_free_context(security_context_t* ctx);

// Cryptographic Services
int crypto_generate_key(crypto_algorithm_t algorithm, uint32_t key_size);
crypto_key_t* crypto_get_key(uint32_t key_id);
int crypto_encrypt(uint32_t key_id, const void* plaintext, size_t plaintext_len,
                  void* ciphertext, size_t* ciphertext_len);
int crypto_decrypt(uint32_t key_id, const void* ciphertext, size_t ciphertext_len,
                  void* plaintext, size_t* plaintext_len);
int crypto_hash(crypto_algorithm_t algorithm, const void* data, size_t data_len,
               void* hash, size_t hash_len);
int crypto_random_bytes(void* buffer, size_t size);

// Security Policy Management
int security_load_policy(const char* policy_file);
security_policy_t* security_get_policy(void);
int security_set_policy_option(const char* option, const char* value);

// Audit System
int audit_log_event(uint32_t uid, uint32_t pid, const char* event_type,
                   const char* description, bool success);
audit_entry_t* audit_get_logs(uint64_t start_time, uint64_t end_time);
int audit_export_logs(const char* filename);

// Secure Memory Management
void* secure_malloc(size_t size);
void secure_free(void* ptr, size_t size);
int secure_memcmp(const void* s1, const void* s2, size_t n);
void secure_memzero(void* ptr, size_t size);

// System Call Filtering
typedef enum {
    SYSCALL_ALLOW = 0,
    SYSCALL_DENY = 1,
    SYSCALL_AUDIT = 2
} syscall_action_t;

int security_set_syscall_filter(uint32_t syscall_num, syscall_action_t action);
syscall_action_t security_check_syscall(uint32_t pid, uint32_t syscall_num);

// MAC (Mandatory Access Control) Labels
#define MAC_LABEL_MAX 64

typedef struct mac_label {
    char label[MAC_LABEL_MAX];
    uint32_t level;
    uint32_t categories;
} mac_label_t;

int mac_set_process_label(uint32_t pid, const char* label);
int mac_set_file_label(const char* path, const char* label);
bool mac_check_access(const char* subject_label, const char* object_label,
                     const char* access_type);

#endif
