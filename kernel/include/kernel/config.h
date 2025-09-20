/*
 * Configuration Management Header
 * YAML-based configuration system for CloudOS
 */

#ifndef KERNEL_CONFIG_H
#define KERNEL_CONFIG_H

#include "types.h"

// YAML Value Types
typedef enum {
    CONFIG_TYPE_NULL = 0,
    CONFIG_TYPE_BOOL = 1,
    CONFIG_TYPE_INT = 2,
    CONFIG_TYPE_FLOAT = 3,
    CONFIG_TYPE_STRING = 4,
    CONFIG_TYPE_ARRAY = 5,
    CONFIG_TYPE_OBJECT = 6
} config_value_type_t;

// Forward declarations
typedef struct config_value config_value_t;
typedef struct config_array config_array_t;
typedef struct config_object config_object_t;

// Configuration Value Structure
typedef struct config_value {
    config_value_type_t type;
    union {
        bool bool_val;
        int64_t int_val;
        double float_val;
        char *string_val;
        config_array_t *array_val;
        config_object_t *object_val;
    } value;
} config_value_t;

// Configuration Array Structure
typedef struct config_array {
    config_value_t **items;
    size_t count;
    size_t capacity;
} config_array_t;

// Configuration Object Structure
typedef struct config_object {
    char *key;
    config_value_t *value;
    struct config_object *next;
} config_object_t;

// Service Structure
typedef struct service {
    char name[64];
    char description[256];
    char exec_path[256];
    char *args[16];
    int arg_count;

    uint32_t state;        // 0=stopped, 1=starting, 2=running, 3=stopping, 4=failed
    uint32_t pid;
    uint64_t start_time;
    uint64_t restart_count;

    bool auto_start;
    uint32_t restart_delay;
    uint32_t max_restarts;

    char **dependencies;
    int dep_count;

    struct service *next;
} service_t;

// System State Structure
typedef struct system_state {
    char hostname[64];
    uint32_t runlevel;
    uint64_t boot_time;
    uint64_t uptime;

    // Network configuration
    char ip_address[16];
    char netmask[16];
    char gateway[16];
    char dns_server[16];

    // Service states
    service_t *services;

    // Configuration
    config_value_t *config;
} system_state_t;

// Configuration Functions
int config_init(void);
int config_load_file(const char *filename);
int config_save_file(const char *filename);
config_value_t *config_get_value(const char *path);
int config_set_value(const char *path, config_value_t *value);
void config_free_value(config_value_t *value);

// Service Management Functions
int service_init(void);
int service_register(const char *name, const char *exec_path, const char **args, int arg_count);
int service_start(const char *name);
int service_stop(const char *name);
int service_restart(const char *name);
uint32_t service_get_status(const char *name);
int service_list_services(service_t **services, int *count);
int service_add_dependency(const char *service_name, const char *dependency);

// System State Management Functions
int state_init(void);
int state_load_from_file(const char *filename);
int state_save_to_file(const char *filename);
system_state_t *state_get_current(void);
int state_update_hostname(const char *hostname);
int state_update_network(const char *ip, const char *netmask, const char *gateway);
int state_update_runlevel(uint32_t runlevel);

// YAML Parsing Functions (simplified)
int yaml_parse_file(const char *filename, config_value_t **root);
int yaml_parse_string(const char *yaml_string, config_value_t **root);
int yaml_write_file(const char *filename, config_value_t *root);

// Utility Functions
config_value_t *config_create_null(void);
config_value_t *config_create_bool(bool value);
config_value_t *config_create_int(int64_t value);
config_value_t *config_create_float(double value);
config_value_t *config_create_string(const char *value);
config_value_t *config_create_array(void);
config_value_t *config_create_object(void);

// Array manipulation functions
int config_array_add(config_array_t *array, config_value_t *value);
config_value_t *config_array_get(config_array_t *array, size_t index);
size_t config_array_size(config_array_t *array);

// Object manipulation functions
int config_object_set(config_object_t *object, const char *key, config_value_t *value);
config_value_t *config_object_get(config_object_t *object, const char *key);
int config_object_remove(config_object_t *object, const char *key);

// Path-based access functions
int config_get_bool(const char *path, bool *value);
int config_get_int(const char *path, int64_t *value);
int config_get_float(const char *path, double *value);
int config_get_string(const char *path, char **value);

// Boot and initialization functions
int config_load_boot_config(void);
int config_apply_boot_config(void);
int config_validate_configuration(void);

// Hot reload functionality
int config_reload_configuration(void);
int config_check_for_changes(void);

// Configuration validation
int config_validate_service_config(const char *service_name);
int config_validate_network_config(void);
int config_validate_system_config(void);

#endif
