/*
 * System Monitoring and Metrics Header
 * Comprehensive system monitoring for CloudOS
 */

#ifndef KERNEL_MONITORING_H
#define KERNEL_MONITORING_H

#include "types.h"

// System Metrics Structure
typedef struct system_metrics {
    // CPU Metrics
    uint64_t cpu_user_time;
    uint64_t cpu_system_time;
    uint64_t cpu_idle_time;
    uint32_t cpu_usage_percent;

    // Memory Metrics
    uint64_t memory_total;
    uint64_t memory_used;
    uint64_t memory_free;
    uint32_t memory_usage_percent;

    // I/O Metrics
    uint64_t io_read_bytes;
    uint64_t io_write_bytes;
    uint32_t io_read_ops;
    uint32_t io_write_ops;

    // Network Metrics
    uint64_t net_rx_bytes;
    uint64_t net_tx_bytes;
    uint32_t net_rx_packets;
    uint32_t net_tx_packets;

    // Process Metrics
    uint32_t process_count;
    uint32_t thread_count;
    uint64_t context_switches;

    // File System Metrics
    uint64_t fs_total_space;
    uint64_t fs_used_space;
    uint32_t fs_usage_percent;

    uint64_t timestamp;
} system_metrics_t;

// Health Check Structure
typedef struct health_check {
    char name[64];
    int (*check_function)(void);
    uint32_t interval_seconds;
    uint32_t last_check;
    bool last_result;
    char last_message[256];
    struct health_check *next;
} health_check_t;

// Alert Rule Structure
typedef struct alert_rule {
    char name[64];
    char metric[64];
    char condition[32]; // ">", "<", "==", "!="
    uint64_t threshold;
    char action[128];
    bool enabled;
    uint32_t trigger_count;
    uint64_t last_triggered;
    struct alert_rule *next;
} alert_rule_t;

// Performance Statistics
typedef struct perf_stats {
    uint64_t collection_count;
    uint64_t avg_collection_time;
    uint64_t max_collection_time;
    uint64_t min_collection_time;
    uint64_t error_count;
} perf_stats_t;

// Monitoring Functions
int monitoring_init(void);
int monitoring_collect_metrics(system_metrics_t *metrics);
int monitoring_get_current_metrics(system_metrics_t *metrics);
int monitoring_get_historical_metrics(system_metrics_t **metrics, uint32_t count, uint64_t start_time);

// Health Check Functions
int monitoring_add_health_check(const char *name, int (*check_func)(void), uint32_t interval);
int monitoring_remove_health_check(const char *name);
int monitoring_run_health_checks(void);
int monitoring_get_health_status(const char *name, bool *status, char *message, size_t msg_size);

// Alert Management Functions
int monitoring_add_alert_rule(const char *name, const char *metric, const char *condition,
                             uint64_t threshold, const char *action);
int monitoring_remove_alert_rule(const char *name);
int monitoring_enable_alert_rule(const char *name);
int monitoring_disable_alert_rule(const char *name);
int monitoring_check_alerts(void);

// Performance Monitoring
perf_stats_t *monitoring_get_performance_stats(void);
int monitoring_reset_performance_stats(void);

// System Status Functions
int monitoring_get_system_status(void);
int monitoring_get_uptime(uint64_t *uptime);
int monitoring_get_load_average(double *load1, double *load5, double *load15);

// Utility Functions
uint64_t monitoring_get_timestamp(void);
int monitoring_format_metrics(const system_metrics_t *metrics, char *buffer, size_t size);

// Built-in Health Checks
int health_check_cpu_usage(void);
int health_check_memory_usage(void);
int health_check_disk_space(void);
int health_check_network_interfaces(void);
int health_check_kernel_modules(void);

#endif
