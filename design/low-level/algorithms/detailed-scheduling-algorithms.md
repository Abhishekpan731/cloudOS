# Detailed Scheduling Algorithms - Low-Level Design

## Advanced Multi-Level Feedback Queue (MLFQ) with Container Awareness

### Algorithm Overview

CloudOS implements a sophisticated MLFQ with 8 priority levels, dynamic priority adjustment, and container-aware resource allocation.

```
Priority Levels:
0-1:   Real-time processes (FIFO/RR)
2-3:   Interactive processes (short time slices, quick response)
4-5:   Normal processes (balanced time slices)
6-7:   Batch processes (long time slices, CPU-intensive)
```

### Detailed Priority Calculation Algorithm

```c
// Enhanced dynamic priority calculation
uint32_t calculate_enhanced_priority(process_t* proc, uint64_t current_time) {
    uint32_t base_priority = proc->static_priority;

    // 1. Aging calculation (prevent starvation)
    uint64_t wait_time = current_time - proc->last_run_time;
    uint32_t aging_bonus = 0;

    if (wait_time > STARVATION_THRESHOLD) {
        // Exponential aging for long-waiting processes
        aging_bonus = min(wait_time / AGING_FACTOR, MAX_AGING_BONUS);
        aging_bonus = aging_bonus * aging_bonus / 100; // Quadratic scaling
    }

    // 2. CPU burst analysis (interactive vs CPU-bound detection)
    uint32_t cpu_penalty = 0;
    if (proc->recent_cpu_bursts > CPU_BURST_THRESHOLD) {
        cpu_penalty = (proc->avg_cpu_burst_length * CPU_PENALTY_FACTOR) / 1000;
    }

    // 3. I/O behavior bonus (reward interactive processes)
    uint32_t io_bonus = 0;
    if (proc->io_operations > IO_THRESHOLD) {
        uint32_t io_ratio = (proc->io_wait_time * 100) / proc->total_runtime;
        if (io_ratio > INTERACTIVE_IO_RATIO) {
            io_bonus = INTERACTIVE_BONUS;
        }
    }

    // 4. Container hierarchy adjustment
    uint32_t container_adjustment = 0;
    if (proc->container_id != SYSTEM_CONTAINER_ID) {
        container_t* container = find_container(proc->container_id);
        if (container) {
            // Higher container priority = lower process priority number
            container_adjustment = (MAX_CONTAINER_PRIORITY - container->priority) * 2;
        }
    }

    // 5. Memory pressure penalty
    uint32_t memory_penalty = 0;
    if (get_memory_pressure() > HIGH_PRESSURE_THRESHOLD) {
        if (proc->memory_usage > LARGE_PROCESS_THRESHOLD) {
            memory_penalty = MEMORY_PRESSURE_PENALTY;
        }
    }

    // 6. NUMA locality bonus
    uint32_t numa_bonus = 0;
    int preferred_node = proc->numa_preferred_node;
    int current_node = get_current_numa_node();
    if (preferred_node == current_node) {
        numa_bonus = NUMA_LOCALITY_BONUS;
    }

    // Calculate final priority (lower number = higher priority)
    int32_t final_priority = base_priority
                           + container_adjustment
                           + cpu_penalty
                           + memory_penalty
                           - aging_bonus
                           - io_bonus
                           - numa_bonus;

    return clamp(final_priority, MIN_PRIORITY, MAX_PRIORITY);
}

// Time slice calculation with exponential scaling
uint32_t calculate_adaptive_time_slice(process_t* proc, uint32_t system_load) {
    uint32_t base_slice = BASE_TIME_SLICE; // 10ms

    // Priority-based scaling
    uint32_t priority_factor = (MAX_PRIORITY - proc->dynamic_priority + 1);

    // Process type multipliers
    float type_multiplier = 1.0f;
    switch (proc->process_type) {
        case PROCESS_REAL_TIME:
            type_multiplier = 5.0f;  // 50ms max for RT
            break;
        case PROCESS_INTERACTIVE:
            type_multiplier = 1.5f;  // 15ms for interactive
            break;
        case PROCESS_NORMAL:
            type_multiplier = 2.0f;  // 20ms for normal
            break;
        case PROCESS_BATCH:
            type_multiplier = 8.0f;  // 80ms for batch
            break;
        case PROCESS_IDLE:
            type_multiplier = 10.0f; // 100ms for idle
            break;
    }

    // System load adjustment (exponential backoff under high load)
    float load_factor = 1.0f;
    if (system_load > 80) {
        load_factor = 0.5f; // Halve time slices under very high load
    } else if (system_load > 60) {
        load_factor = 0.75f; // Reduce time slices under high load
    }

    // Container resource allocation
    float container_factor = 1.0f;
    if (proc->container_id != SYSTEM_CONTAINER_ID) {
        container_t* container = find_container(proc->container_id);
        if (container && container->cpu_limit > 0) {
            // Scale time slice based on container CPU allocation
            container_factor = (float)container->cpu_shares / CONTAINER_DEFAULT_SHARES;
            container_factor = clamp(container_factor, 0.1f, 2.0f);
        }
    }

    // Calculate final time slice
    uint32_t time_slice = (uint32_t)(base_slice * priority_factor *
                                   type_multiplier * load_factor * container_factor);

    return clamp(time_slice, MIN_TIME_SLICE, MAX_TIME_SLICE);
}
```

### Advanced Load Balancing with Work Stealing

```c
// Work-stealing load balancer for SMP systems
typedef struct cpu_runqueue {
    // Multiple priority queues per CPU
    run_queue_t rt_queue;           // Real-time queue
    run_queue_t interactive_queue;  // Interactive processes
    run_queue_t normal_queue;       // Normal processes
    run_queue_t batch_queue;        // Batch processes
    run_queue_t idle_queue;         // Idle processes

    // Load balancing state
    uint32_t load_weight;           // Weighted load
    uint32_t nr_running;            // Number of running processes
    uint64_t last_balance_time;     // Last balance operation

    // Work stealing
    atomic_t steal_lock;            // Lock for work stealing
    uint32_t steal_attempts;        // Unsuccessful steal attempts

    // NUMA awareness
    int numa_node;                  // NUMA node for this CPU
    cpu_runqueue_t* numa_siblings;  // Other CPUs in same NUMA node

    // Statistics
    uint64_t context_switches;      // Context switch count
    uint64_t migrations_in;         // Processes migrated in
    uint64_t migrations_out;        // Processes migrated out
} cpu_runqueue_t;

// Advanced work-stealing algorithm
process_t* work_steal_process(int target_cpu) {
    cpu_runqueue_t* target_rq = &cpu_runqueues[target_cpu];
    process_t* stolen_process = NULL;

    // Try to acquire steal lock (non-blocking)
    if (!atomic_cmpxchg(&target_rq->steal_lock, 0, 1)) {
        return NULL; // Another CPU is already stealing
    }

    // Prefer stealing from same NUMA node first
    int current_numa = get_current_numa_node();
    int target_numa = cpu_to_numa_node(target_cpu);

    // Calculate steal priority based on queue lengths
    struct steal_candidate {
        run_queue_t* queue;
        uint32_t priority;
        uint32_t count;
    } candidates[] = {
        {&target_rq->batch_queue, 1, target_rq->batch_queue.count},
        {&target_rq->normal_queue, 2, target_rq->normal_queue.count},
        {&target_rq->interactive_queue, 3, target_rq->interactive_queue.count}
        // Don't steal RT processes - they have specific affinity
    };

    // Sort candidates by steal priority and queue length
    for (int i = 0; i < 3; i++) {
        if (candidates[i].count > STEAL_THRESHOLD) {
            // Try to steal from the most loaded queue
            stolen_process = try_steal_from_queue(candidates[i].queue,
                                                current_numa == target_numa);
            if (stolen_process) {
                // Update migration statistics
                target_rq->migrations_out++;
                stolen_process->last_cpu = get_current_cpu();
                break;
            }
        }
    }

    atomic_set(&target_rq->steal_lock, 0);
    return stolen_process;
}

// Intelligent migration decision
bool should_migrate_process_detailed(process_t* proc, int from_cpu, int to_cpu) {
    // 1. Check hard CPU affinity
    if (!(proc->cpu_affinity_mask & (1ULL << to_cpu))) {
        return false;
    }

    // 2. Calculate migration cost
    uint64_t migration_cost = MIGRATION_BASE_COST;

    // Cache warmth penalty
    if (proc->last_cpu == from_cpu) {
        migration_cost += CACHE_WARMTH_PENALTY;
    }

    // NUMA penalty
    int from_numa = cpu_to_numa_node(from_cpu);
    int to_numa = cpu_to_numa_node(to_cpu);
    if (from_numa != to_numa) {
        migration_cost += NUMA_MIGRATION_PENALTY;

        // Check process memory locality
        uint64_t local_memory = get_process_memory_on_node(proc, from_numa);
        uint64_t total_memory = proc->memory_usage;
        if (total_memory > 0) {
            uint32_t locality_percent = (local_memory * 100) / total_memory;
            if (locality_percent > HIGH_LOCALITY_THRESHOLD) {
                migration_cost += MEMORY_LOCALITY_PENALTY;
            }
        }
    }

    // 3. Calculate migration benefit
    cpu_runqueue_t* from_rq = &cpu_runqueues[from_cpu];
    cpu_runqueue_t* to_rq = &cpu_runqueues[to_cpu];

    uint64_t load_imbalance = 0;
    if (from_rq->load_weight > to_rq->load_weight) {
        load_imbalance = from_rq->load_weight - to_rq->load_weight;
    }

    uint64_t migration_benefit = load_imbalance * LOAD_BALANCE_FACTOR;

    // Process priority bonus (higher priority processes get preference)
    if (proc->dynamic_priority < HIGH_PRIORITY_THRESHOLD) {
        migration_benefit += HIGH_PRIORITY_MIGRATION_BONUS;
    }

    // 4. Make migration decision
    return migration_benefit > migration_cost;
}
```

### Container-Aware Scheduling with Hierarchical Allocation

```c
// Hierarchical container scheduler
typedef struct container_scheduler {
    container_id_t id;
    char name[CONTAINER_NAME_MAX];

    // Resource allocation
    uint32_t cpu_shares;            // CPU shares (relative weight)
    uint32_t cpu_quota;             // CPU quota in microseconds per period
    uint32_t cpu_period;            // CPU period in microseconds
    uint64_t memory_limit;          // Memory limit in bytes

    // Current usage tracking
    uint64_t cpu_usage_ns;          // CPU usage in nanoseconds
    uint64_t memory_usage;          // Current memory usage
    uint64_t period_start_time;     // Start of current period

    // Throttling state
    bool throttled;                 // Currently throttled
    uint64_t throttle_count;        // Number of throttling events
    uint64_t unthrottle_time;       // When to unthrottle

    // Process queues per container
    run_queue_t container_processes; // Processes in this container
    uint32_t nr_processes;          // Number of processes

    // Hierarchical scheduling
    struct container_scheduler* parent;   // Parent container
    struct container_scheduler* children; // Child containers
    struct container_scheduler* sibling;  // Sibling containers

    // Fairness tracking
    uint64_t vruntime;              // Virtual runtime for fairness
    uint64_t min_vruntime;          // Minimum vruntime in container

    spinlock_t lock;                // Container scheduler lock
} container_scheduler_t;

// Container CPU bandwidth allocation
void container_bandwidth_control(container_scheduler_t* cs) {
    uint64_t current_time = get_system_time_ns();

    // Check if we're in a new period
    if (current_time >= cs->period_start_time + cs->cpu_period) {
        // New period - reset usage and unthrottle
        cs->cpu_usage_ns = 0;
        cs->period_start_time = current_time;
        cs->throttled = false;

        // Wake up throttled processes
        if (cs->container_processes.count > 0) {
            wake_up_container_processes(cs);
        }
    }

    // Check if quota exceeded
    if (cs->cpu_quota > 0 && cs->cpu_usage_ns >= cs->cpu_quota) {
        if (!cs->throttled) {
            cs->throttled = true;
            cs->throttle_count++;

            // Move all container processes to throttled state
            throttle_container_processes(cs);
        }
    }
}

// Hierarchical fair scheduling within containers
process_t* container_select_next_process(container_scheduler_t* cs) {
    if (cs->throttled || cs->container_processes.count == 0) {
        return NULL;
    }

    process_t* selected = NULL;
    uint64_t min_vruntime = UINT64_MAX;

    // Find process with minimum virtual runtime
    for (process_t* proc = cs->container_processes.head; proc; proc = proc->next) {
        if (proc->state == PROCESS_READY) {
            // Calculate process virtual runtime within container
            uint64_t proc_vruntime = proc->total_runtime * NICE_0_WEIGHT /
                                   priority_to_weight(proc->dynamic_priority);

            if (proc_vruntime < min_vruntime) {
                min_vruntime = proc_vruntime;
                selected = proc;
            }
        }
    }

    if (selected) {
        // Update container virtual runtime
        cs->vruntime = min_vruntime;

        // Adjust time slice based on container allocation
        uint32_t container_time_slice = calculate_container_time_slice(cs, selected);
        selected->time_slice = min(selected->time_slice, container_time_slice);
    }

    return selected;
}

// Calculate time slice based on container resource allocation
uint32_t calculate_container_time_slice(container_scheduler_t* cs, process_t* proc) {
    // Base time slice from container CPU shares
    uint32_t base_slice = (BASE_TIME_SLICE * cs->cpu_shares) / CONTAINER_DEFAULT_SHARES;

    // Adjust for number of processes in container
    if (cs->nr_processes > 1) {
        base_slice = base_slice / cs->nr_processes;
    }

    // Apply container quota if specified
    if (cs->cpu_quota > 0) {
        uint64_t remaining_quota = cs->cpu_quota - cs->cpu_usage_ns;
        uint32_t quota_slice = remaining_quota / 1000; // Convert ns to μs

        base_slice = min(base_slice, quota_slice);
    }

    return clamp(base_slice, MIN_TIME_SLICE, MAX_TIME_SLICE);
}
```

### Real-Time Scheduling with Deadline Guarantees

```c
// Earliest Deadline First (EDF) scheduler for real-time tasks
typedef struct rt_task {
    process_t* process;             // Associated process
    uint64_t period;                // Task period in microseconds
    uint64_t deadline;              // Absolute deadline
    uint64_t wcet;                  // Worst-case execution time
    uint64_t remaining_time;        // Remaining execution time

    // Admission control
    double utilization;             // Task utilization (WCET/period)
    bool admitted;                  // Admission control passed

    // Deadline miss tracking
    uint32_t deadline_misses;       // Number of deadline misses
    uint64_t last_deadline_miss;    // Time of last deadline miss

    struct rt_task* next;           // Next in deadline order
} rt_task_t;

// EDF scheduling decision
process_t* edf_schedule_next(void) {
    rt_task_t* earliest_deadline = NULL;
    uint64_t current_time = get_system_time();

    // Find task with earliest absolute deadline
    for (rt_task_t* task = rt_ready_queue; task; task = task->next) {
        if (task->process->state == PROCESS_READY) {
            if (!earliest_deadline || task->deadline < earliest_deadline->deadline) {
                earliest_deadline = task;
            }
        }
    }

    if (earliest_deadline) {
        // Check for deadline miss
        if (current_time > earliest_deadline->deadline) {
            earliest_deadline->deadline_misses++;
            earliest_deadline->last_deadline_miss = current_time;

            // Trigger deadline miss handler
            handle_deadline_miss(earliest_deadline);
        }

        return earliest_deadline->process;
    }

    return NULL;
}

// Rate Monotonic scheduling for periodic tasks
process_t* rate_monotonic_schedule(void) {
    rt_task_t* highest_priority = NULL;

    // Find task with shortest period (highest priority in RM)
    for (rt_task_t* task = rt_ready_queue; task; task = task->next) {
        if (task->process->state == PROCESS_READY) {
            if (!highest_priority || task->period < highest_priority->period) {
                highest_priority = task;
            }
        }
    }

    return highest_priority ? highest_priority->process : NULL;
}

// Admission control for real-time tasks
bool rt_admission_control(rt_task_t* new_task) {
    double total_utilization = new_task->utilization;

    // Calculate current system utilization
    for (rt_task_t* task = rt_ready_queue; task; task = task->next) {
        if (task->admitted) {
            total_utilization += task->utilization;
        }
    }

    // Liu & Layland bound for RM: U ≤ n(2^(1/n) - 1)
    // For EDF: U ≤ 1
    double bound = (rt_scheduling_policy == RT_POLICY_EDF) ? 1.0 :
                   rt_task_count * (pow(2.0, 1.0/rt_task_count) - 1.0);

    if (total_utilization <= bound) {
        new_task->admitted = true;
        return true;
    }

    return false;
}
```

### Performance Optimization Techniques

```c
// CPU frequency scaling based on load
void cpu_frequency_scaling(void) {
    uint32_t current_load = get_cpu_load_percentage();
    uint32_t current_freq = get_cpu_frequency();
    uint32_t target_freq = current_freq;

    // Aggressive scaling for power efficiency
    if (current_load < 20) {
        target_freq = CPU_FREQ_MIN;
    } else if (current_load < 50) {
        target_freq = CPU_FREQ_LOW;
    } else if (current_load < 80) {
        target_freq = CPU_FREQ_MEDIUM;
    } else {
        target_freq = CPU_FREQ_MAX;
    }

    // Gradual frequency transitions to avoid performance spikes
    if (target_freq != current_freq) {
        set_cpu_frequency_gradual(target_freq);
    }
}

// Cache-aware scheduling
void optimize_cache_locality(process_t* proc, int target_cpu) {
    // Check L1/L2 cache sharing
    if (cpus_share_cache(proc->last_cpu, target_cpu, L2_CACHE)) {
        proc->cache_affinity_bonus = L2_CACHE_BONUS;
    } else if (cpus_share_cache(proc->last_cpu, target_cpu, L3_CACHE)) {
        proc->cache_affinity_bonus = L3_CACHE_BONUS;
    } else {
        proc->cache_affinity_bonus = 0;
    }

    // Adjust scheduling weight based on cache affinity
    proc->effective_priority = proc->dynamic_priority - proc->cache_affinity_bonus;
}

// Energy-aware scheduling for mobile/edge devices
process_t* energy_aware_schedule(void) {
    process_t* selected = NULL;
    uint32_t min_energy_cost = UINT32_MAX;

    for (process_t* proc = ready_queue.head; proc; proc = proc->next) {
        // Calculate energy cost = performance_state * execution_time
        uint32_t perf_state = estimate_required_performance_state(proc);
        uint32_t exec_time = estimate_execution_time(proc);
        uint32_t energy_cost = perf_state * exec_time;

        // Prefer energy-efficient choices
        if (energy_cost < min_energy_cost) {
            min_energy_cost = energy_cost;
            selected = proc;
        }
    }

    return selected;
}
```

### Algorithm Performance Characteristics

| Algorithm Component | Time Complexity | Space Complexity | Cache Efficiency |
|-------------------|----------------|------------------|------------------|
| Enhanced Priority Calc | O(1) | O(1) | Excellent |
| Work Stealing | O(log n) | O(1) | Good |
| Container Scheduling | O(k log k) | O(k) | Good (k=containers) |
| EDF Scheduling | O(n) | O(n) | Fair (n=RT tasks) |
| Load Balancing | O(c²) | O(c) | Poor (c=CPUs) |
| Cache Optimization | O(1) | O(1) | Excellent |

### Scheduling Parameters and Tuning

```c
// Scheduling parameters (tunable via sysctl)
struct sched_params {
    // Time slice parameters
    uint32_t base_time_slice;       // 10000 μs (10ms)
    uint32_t min_time_slice;        // 1000 μs (1ms)
    uint32_t max_time_slice;        // 100000 μs (100ms)

    // Priority adjustment
    uint32_t aging_factor;          // 5000 μs aging increment
    uint32_t max_aging_bonus;       // 50 priority levels max
    uint32_t interactive_bonus;     // 10 priority levels
    uint32_t cpu_penalty_divisor;   // 20 (5% CPU = 1 priority penalty)

    // Load balancing
    uint32_t balance_interval;      // 10000 μs (10ms)
    uint32_t migration_cost;        // 1000 μs estimated cost
    uint32_t steal_threshold;       // 4 processes minimum to steal

    // Container scheduling
    uint32_t container_default_shares; // 1024 default CPU shares
    uint32_t container_min_shares;     // 64 minimum CPU shares
    uint32_t container_max_shares;     // 8192 maximum CPU shares

    // Real-time scheduling
    uint32_t rt_max_utilization;    // 95% max RT utilization
    uint32_t deadline_miss_threshold; // 3 consecutive misses = demotion

    // Energy management
    bool energy_aware_enabled;      // Energy-aware scheduling
    uint32_t freq_scale_threshold;  // 80% load for max frequency
};
```

This enhanced scheduling design provides:
- **Advanced load balancing** with work-stealing and NUMA awareness
- **Container resource isolation** with hierarchical fair scheduling
- **Real-time guarantees** with EDF and Rate Monotonic scheduling
- **Energy optimization** for mobile and edge deployments
- **Cache-aware placement** for optimal performance
- **Comprehensive tuning parameters** for different workload characteristics

<function_calls>
<invoke name="TodoWrite">
<parameter name="todos">[{"content": "Enhance process management with detailed scheduling algorithms", "status": "completed", "activeForm": "Enhancing process management with detailed scheduling algorithms"}, {"content": "Add detailed memory management algorithms and data structures", "status": "in_progress", "activeForm": "Adding detailed memory management algorithms and data structures"}, {"content": "Expand network stack with protocol state machines", "status": "pending", "activeForm": "Expanding network stack with protocol state machines"}, {"content": "Add comprehensive security policy framework", "status": "pending", "activeForm": "Adding comprehensive security policy framework"}, {"content": "Create detailed file system B+ tree and journaling algorithms", "status": "pending", "activeForm": "Creating detailed file system B+ tree and journaling algorithms"}, {"content": "Add performance optimization and caching strategies", "status": "pending", "activeForm": "Adding performance optimization and caching strategies"}, {"content": "Create detailed container isolation mechanisms", "status": "pending", "activeForm": "Creating detailed container isolation mechanisms"}, {"content": "Add comprehensive error handling and recovery", "status": "pending", "activeForm": "Adding comprehensive error handling and recovery"}]