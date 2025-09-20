/*
 * System Monitoring and Metrics Implementation
 * Comprehensive system monitoring for CloudOS
 */

#include "kernel/monitoring.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"
#include "kernel/process.h"
#include "kernel/time.h"

// Global monitoring state
static system_metrics_t *current_metrics = NULL;
static system_metrics_t *metrics_history = NULL;
static uint32_t metrics_history_count = 0;
static uint32_t metrics_history_max = 100;

static health_check_t *health_checks = NULL;
static alert_rule_t *alert_rules = NULL;
static perf_stats_t performance_stats = {0};

// Simple memcpy for kernel use
static void *memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

// Simple string comparison for kernel use
static int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2) {
            return *s1 - *s2;
        }
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

// Simple memset for kernel use
static void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)c;
    }
    return s;
}

// Forward declarations
static int ksprintf(char *buffer, const char *format, ...);

// Initialize monitoring system
int monitoring_init(void) {
    kprintf("Monitoring: Initializing system monitoring...\n");

    // Allocate current metrics structure
    current_metrics = (system_metrics_t *)kmalloc(sizeof(system_metrics_t));
    if (!current_metrics) {
        kprintf("Monitoring: Failed to allocate metrics structure\n");
        return -1;
    }

    memset(current_metrics, 0, sizeof(system_metrics_t));

    // Add built-in health checks
    monitoring_add_health_check("cpu_usage", health_check_cpu_usage, 60);
    monitoring_add_health_check("memory_usage", health_check_memory_usage, 60);
    monitoring_add_health_check("disk_space", health_check_disk_space, 300);
    monitoring_add_health_check("network", health_check_network_interfaces, 60);

    // Add default alert rules
    monitoring_add_alert_rule("high_cpu", "cpu_usage_percent", ">", 90, "log_warning");
    monitoring_add_alert_rule("high_memory", "memory_usage_percent", ">", 95, "log_critical");
    monitoring_add_alert_rule("low_disk", "fs_usage_percent", ">", 90, "log_warning");

    kprintf("Monitoring: System initialized with %d health checks and %d alert rules\n",
           4, 3);

    return 0;
}

// Collect CPU metrics
static int collect_cpu_metrics(system_metrics_t *metrics) {
    // Simplified CPU metrics collection
    // In a real implementation, this would read from /proc/stat or hardware counters

    static uint64_t prev_user = 0, prev_system = 0, prev_idle = 0;

    // Simulate CPU time collection (replace with actual hardware counters)
    uint64_t user_time = prev_user + 1000;    // Simulate user time
    uint64_t system_time = prev_system + 200;  // Simulate system time
    uint64_t idle_time = prev_idle + 800;     // Simulate idle time

    uint64_t total_diff = (user_time - prev_user) + (system_time - prev_system) + (idle_time - prev_idle);

    if (total_diff > 0) {
        metrics->cpu_usage_percent = (uint32_t)((100 * (total_diff - (idle_time - prev_idle))) / total_diff);
    }

    metrics->cpu_user_time = user_time;
    metrics->cpu_system_time = system_time;
    metrics->cpu_idle_time = idle_time;

    prev_user = user_time;
    prev_system = system_time;
    prev_idle = idle_time;

    return 0;
}

// Collect memory metrics
static int collect_memory_metrics(system_metrics_t *metrics) {
    // Simplified memory metrics collection
    // In a real implementation, this would read from /proc/meminfo

    // Simulate memory values (replace with actual system calls)
    metrics->memory_total = 8 * 1024 * 1024 * 1024ULL; // 8GB total
    metrics->memory_used = 4 * 1024 * 1024 * 1024ULL;  // 4GB used
    metrics->memory_free = metrics->memory_total - metrics->memory_used;

    if (metrics->memory_total > 0) {
        metrics->memory_usage_percent = (uint32_t)((metrics->memory_used * 100) / metrics->memory_total);
    }

    return 0;
}

// Collect I/O metrics
static int collect_io_metrics(system_metrics_t *metrics) {
    // Simplified I/O metrics collection
    // In a real implementation, this would read from /proc/diskstats

    static uint64_t prev_read = 0, prev_write = 0;

    // Simulate I/O statistics
    metrics->io_read_bytes = prev_read + 1024 * 1024;     // 1MB read
    metrics->io_write_bytes = prev_write + 512 * 1024;    // 512KB written
    metrics->io_read_ops = 100;
    metrics->io_write_ops = 50;

    prev_read = metrics->io_read_bytes;
    prev_write = metrics->io_write_bytes;

    return 0;
}

// Collect network metrics
static int collect_network_metrics(system_metrics_t *metrics) {
    // Simplified network metrics collection
    // In a real implementation, this would read from /proc/net/dev

    static uint64_t prev_rx = 0, prev_tx = 0;

    // Simulate network statistics
    metrics->net_rx_bytes = prev_rx + 10 * 1024 * 1024;   // 10MB received
    metrics->net_tx_bytes = prev_tx + 5 * 1024 * 1024;    // 5MB transmitted
    metrics->net_rx_packets = 10000;
    metrics->net_tx_packets = 5000;

    prev_rx = metrics->net_rx_bytes;
    prev_tx = metrics->net_tx_bytes;

    return 0;
}

// Collect process metrics
static int collect_process_metrics(system_metrics_t *metrics) {
    // Simplified process metrics collection
    // In a real implementation, this would enumerate running processes

    // Simulate process statistics
    metrics->process_count = 50;     // 50 processes
    metrics->thread_count = 150;     // 150 threads
    metrics->context_switches = 10000;

    return 0;
}

// Collect filesystem metrics
static int collect_filesystem_metrics(system_metrics_t *metrics) {
    // Simplified filesystem metrics collection
    // In a real implementation, this would read from statvfs()

    // Simulate filesystem statistics
    metrics->fs_total_space = 100 * 1024 * 1024 * 1024ULL; // 100GB total
    metrics->fs_used_space = 60 * 1024 * 1024 * 1024ULL;   // 60GB used

    if (metrics->fs_total_space > 0) {
        metrics->fs_usage_percent = (uint32_t)((metrics->fs_used_space * 100) / metrics->fs_total_space);
    }

    return 0;
}

// Main metrics collection function
int monitoring_collect_metrics(system_metrics_t *metrics) {
    if (!metrics) return -1;

    uint64_t start_time = monitoring_get_timestamp();

    // Collect all metrics
    int result = 0;
    result |= collect_cpu_metrics(metrics);
    result |= collect_memory_metrics(metrics);
    result |= collect_io_metrics(metrics);
    result |= collect_network_metrics(metrics);
    result |= collect_process_metrics(metrics);
    result |= collect_filesystem_metrics(metrics);

    metrics->timestamp = monitoring_get_timestamp();

    uint64_t end_time = monitoring_get_timestamp();
    uint64_t collection_time = end_time - start_time;

    // Update performance statistics
    performance_stats.collection_count++;
    if (performance_stats.collection_count == 1) {
        performance_stats.min_collection_time = collection_time;
        performance_stats.max_collection_time = collection_time;
    } else {
        if (collection_time < performance_stats.min_collection_time) {
            performance_stats.min_collection_time = collection_time;
        }
        if (collection_time > performance_stats.max_collection_time) {
            performance_stats.max_collection_time = collection_time;
        }
        performance_stats.avg_collection_time =
            (performance_stats.avg_collection_time + collection_time) / 2;
    }

    if (result != 0) {
        performance_stats.error_count++;
    }

    // Store in current metrics
    if (current_metrics) {
        memcpy(current_metrics, metrics, sizeof(system_metrics_t));
    }

    // Add to history
    if (metrics_history_count < metrics_history_max) {
        system_metrics_t *history_entry = (system_metrics_t *)kmalloc(sizeof(system_metrics_t));
        if (history_entry) {
            memcpy(history_entry, metrics, sizeof(system_metrics_t));

            // Add to history list (simple linked list)
            history_entry->timestamp = (uint64_t)metrics_history; // Use timestamp field as next pointer
            metrics_history = history_entry;
            metrics_history_count++;
        }
    }

    return result;
}

// Get current metrics
int monitoring_get_current_metrics(system_metrics_t *metrics) {
    if (!metrics || !current_metrics) return -1;

    memcpy(metrics, current_metrics, sizeof(system_metrics_t));
    return 0;
}

// Health check implementations
int health_check_cpu_usage(void) {
    if (!current_metrics) return -1;

    if (current_metrics->cpu_usage_percent > 95) {
        return -1; // Critical
    } else if (current_metrics->cpu_usage_percent > 85) {
        return 1; // Warning
    }

    return 0; // OK
}

int health_check_memory_usage(void) {
    if (!current_metrics) return -1;

    if (current_metrics->memory_usage_percent > 95) {
        return -1; // Critical
    } else if (current_metrics->memory_usage_percent > 90) {
        return 1; // Warning
    }

    return 0; // OK
}

int health_check_disk_space(void) {
    if (!current_metrics) return -1;

    if (current_metrics->fs_usage_percent > 95) {
        return -1; // Critical
    } else if (current_metrics->fs_usage_percent > 85) {
        return 1; // Warning
    }

    return 0; // OK
}

int health_check_network_interfaces(void) {
    // Simplified network interface check
    // In a real implementation, this would check interface status
    return 0; // OK
}

int health_check_kernel_modules(void) {
    // Simplified kernel module check
    // In a real implementation, this would verify loaded modules
    return 0; // OK
}

// Health check management
int monitoring_add_health_check(const char *name, int (*check_func)(void), uint32_t interval) {
    if (!name || !check_func) return -1;

    health_check_t *check = (health_check_t *)kmalloc(sizeof(health_check_t));
    if (!check) return -1;

    // Copy name
    int i;
    for (i = 0; i < 63 && name[i]; i++) {
        check->name[i] = name[i];
    }
    check->name[i] = '\0';

    check->check_function = check_func;
    check->interval_seconds = interval;
    check->last_check = 0;
    check->last_result = true;
    check->last_message[0] = '\0';

    // Add to list
    check->next = health_checks;
    health_checks = check;

    return 0;
}

int monitoring_run_health_checks(void) {
    health_check_t *check = health_checks;
    uint32_t current_time = (uint32_t)monitoring_get_timestamp();

    while (check) {
        if (current_time - check->last_check >= check->interval_seconds) {
            int result = check->check_function();
            check->last_check = current_time;
            check->last_result = (result == 0);

            // Set status message
            if (result == 0) {
                for (int i = 0; "OK"[i]; i++) {
                    check->last_message[i] = "OK"[i];
                }
                check->last_message[2] = '\0';
            } else if (result == 1) {
                for (int i = 0; "WARNING"[i]; i++) {
                    check->last_message[i] = "WARNING"[i];
                }
                check->last_message[7] = '\0';
            } else {
                for (int i = 0; "CRITICAL"[i]; i++) {
                    check->last_message[i] = "CRITICAL"[i];
                }
                check->last_message[8] = '\0';
            }
        }

        check = check->next;
    }

    return 0;
}

// Alert rule management
int monitoring_add_alert_rule(const char *name, const char *metric, const char *condition,
                             uint64_t threshold, const char *action) {
    if (!name || !metric || !condition || !action) return -1;

    alert_rule_t *rule = (alert_rule_t *)kmalloc(sizeof(alert_rule_t));
    if (!rule) return -1;

    // Copy fields
    int i;
    for (i = 0; i < 63 && name[i]; i++) {
        rule->name[i] = name[i];
    }
    rule->name[i] = '\0';

    for (i = 0; i < 63 && metric[i]; i++) {
        rule->metric[i] = metric[i];
    }
    rule->metric[i] = '\0';

    for (i = 0; i < 31 && condition[i]; i++) {
        rule->condition[i] = condition[i];
    }
    rule->condition[i] = '\0';

    for (i = 0; i < 127 && action[i]; i++) {
        rule->action[i] = action[i];
    }
    rule->action[i] = '\0';

    rule->threshold = threshold;
    rule->enabled = true;
    rule->trigger_count = 0;
    rule->last_triggered = 0;

    // Add to list
    rule->next = alert_rules;
    alert_rules = rule;

    return 0;
}

int monitoring_check_alerts(void) {
    if (!current_metrics) return -1;

    alert_rule_t *rule = alert_rules;
    uint64_t current_time = monitoring_get_timestamp();

    while (rule) {
        if (rule->enabled) {
            uint64_t metric_value = 0;

            // Get metric value
            if (strcmp(rule->metric, "cpu_usage_percent") == 0) {
                metric_value = current_metrics->cpu_usage_percent;
            } else if (strcmp(rule->metric, "memory_usage_percent") == 0) {
                metric_value = current_metrics->memory_usage_percent;
            } else if (strcmp(rule->metric, "fs_usage_percent") == 0) {
                metric_value = current_metrics->fs_usage_percent;
            }

            // Check condition
            bool triggered = false;
            if (strcmp(rule->condition, ">") == 0) {
                triggered = (metric_value > rule->threshold);
            } else if (strcmp(rule->condition, "<") == 0) {
                triggered = (metric_value < rule->threshold);
            } else if (strcmp(rule->condition, "==") == 0) {
                triggered = (metric_value == rule->threshold);
            } else if (strcmp(rule->condition, "!=") == 0) {
                triggered = (metric_value != rule->threshold);
            }

            if (triggered && (current_time - rule->last_triggered) > 300) { // 5 minutes cooldown
                rule->trigger_count++;
                rule->last_triggered = current_time;

                // Execute action (simplified)
                kprintf("ALERT: %s - %s %s %lu (current: %lu)\n",
                       rule->name, rule->metric, rule->condition,
                       rule->threshold, metric_value);
            }
        }

        rule = rule->next;
    }

    return 0;
}

// Utility functions
uint64_t monitoring_get_timestamp(void) {
    // Return current timestamp (simplified)
    static uint64_t timestamp = 0;
    return ++timestamp;
}

int monitoring_format_metrics(const system_metrics_t *metrics, char *buffer, size_t size) {
    if (!metrics || !buffer || size < 512) return -1;

    // Simplified metrics formatting
    ksprintf(buffer, "System Metrics Report\n");
    return 0;
}

perf_stats_t *monitoring_get_performance_stats(void) {
    return &performance_stats;
}

int monitoring_reset_performance_stats(void) {
    memset(&performance_stats, 0, sizeof(perf_stats_t));
    return 0;
}

// Simplified kernel sprintf for metrics formatting
static int ksprintf(char *buffer, const char *format, ...) {
    // Very simplified sprintf - just copy format for now
    // In real implementation, this would use proper formatting
    if (buffer && format) {
        int i;
        for (i = 0; format[i] && i < 255; i++) {
            buffer[i] = format[i];
        }
        buffer[i] = '\0';
        return i;
    }
    return 0;
}
