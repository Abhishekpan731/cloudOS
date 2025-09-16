# Process Scheduling Algorithms - Low-Level Design

## Overview

CloudOS implements a sophisticated multi-level scheduling system optimized for cloud workloads, real-time tasks, and AI/ML applications. The scheduler combines priority-based scheduling with aging, load balancing, and adaptive time slicing.

## Core Scheduling Algorithm

### Priority-Based Preemptive Scheduler

#### Algorithm Overview
```
Algorithm: CloudOS Process Scheduler
Input: Ready queue, current running process, system load
Output: Next process to run

1. Update all process priorities with aging
2. Check for real-time processes (priority < 20)
3. If real-time process available:
   - Select highest priority real-time process
   - Preempt current process if necessary
4. Else select from normal processes using CFS-like algorithm
5. Apply load balancing across CPU cores
6. Update time slice based on priority and system load
```

#### Time Complexity
- **Process Selection**: O(log n) using priority heap
- **Priority Update**: O(n) for aging (amortized O(1) per process)
- **Load Balancing**: O(cores) for multi-core systems

### Priority Calculation Algorithm

```c
// Dynamic priority calculation with aging
uint32_t calculate_dynamic_priority(process_t* proc, uint64_t current_time) {
    uint32_t base_priority = proc->static_priority;
    uint32_t nice_adjustment = proc->nice_value;

    // Aging factor: increase priority for waiting processes
    uint64_t wait_time = current_time - proc->last_run_time;
    uint32_t aging_bonus = min(wait_time / AGING_FACTOR, MAX_AGING_BONUS);

    // CPU usage penalty: decrease priority for CPU-intensive processes
    uint32_t cpu_penalty = proc->cpu_usage_percent / CPU_PENALTY_DIVISOR;

    // Interactive bonus: boost for I/O bound processes
    uint32_t interactive_bonus = proc->io_wait_time > IO_THRESHOLD ?
                                INTERACTIVE_BONUS : 0;

    // Calculate final priority (lower number = higher priority)
    uint32_t dynamic_priority = base_priority + nice_adjustment -
                               aging_bonus - interactive_bonus + cpu_penalty;

    return clamp(dynamic_priority, MIN_PRIORITY, MAX_PRIORITY);
}
```

### Time Slice Calculation

```c
// Adaptive time slice based on priority and system conditions
uint32_t calculate_time_slice(process_t* proc, uint32_t system_load) {
    uint32_t base_slice = BASE_TIME_SLICE; // 10ms default

    // Priority adjustment: higher priority gets longer slice
    uint32_t priority_multiplier = (MAX_PRIORITY - proc->dynamic_priority) / 10;

    // Load adjustment: reduce slice under high load
    uint32_t load_divisor = 1 + (system_load / LOAD_FACTOR);

    // Process type adjustment
    uint32_t type_multiplier = 1;
    if (proc->flags & PROCESS_REALTIME) {
        type_multiplier = 3; // Longer slice for real-time
    } else if (proc->flags & PROCESS_INTERACTIVE) {
        type_multiplier = 2; // Medium slice for interactive
    } else if (proc->flags & PROCESS_BATCH) {
        type_multiplier = 4; // Longest slice for batch
    }

    uint32_t time_slice = (base_slice * priority_multiplier * type_multiplier) /
                         load_divisor;

    return clamp(time_slice, MIN_TIME_SLICE, MAX_TIME_SLICE);
}
```

## Load Balancing Algorithm

### Multi-Core Load Balancing

```c
// SMP load balancing algorithm
void balance_load_across_cores(void) {
    cpu_info_t cores[MAX_CPUS];
    uint32_t total_load = 0;
    uint32_t avg_load;

    // Collect load information from all cores
    for (int i = 0; i < num_cpus; i++) {
        cores[i].load = calculate_cpu_load(i);
        cores[i].queue_length = get_runqueue_length(i);
        total_load += cores[i].load;
    }

    avg_load = total_load / num_cpus;

    // Find overloaded and underloaded cores
    for (int i = 0; i < num_cpus; i++) {
        if (cores[i].load > avg_load + LOAD_IMBALANCE_THRESHOLD) {
            // Find target core for migration
            int target_cpu = find_least_loaded_cpu();
            if (target_cpu != -1) {
                migrate_processes(i, target_cpu);
            }
        }
    }
}

// Process migration decision
bool should_migrate_process(process_t* proc, int from_cpu, int to_cpu) {
    // Check CPU affinity
    if (!(proc->cpu_affinity_mask & (1 << to_cpu))) {
        return false;
    }

    // Check cache warmth (avoid excessive migration)
    uint64_t cache_penalty = estimate_cache_penalty(proc, from_cpu, to_cpu);
    uint64_t load_benefit = estimate_load_benefit(from_cpu, to_cpu);

    return load_benefit > cache_penalty + MIGRATION_COST;
}
```

## Real-Time Scheduling

### Fixed Priority Preemptive Scheduling

```c
// Real-time process scheduling (POSIX.1b compliant)
process_t* select_realtime_process(void) {
    process_t* highest_priority = NULL;
    uint32_t highest_prio = MAX_RT_PRIORITY + 1;

    // Iterate through real-time run queue
    for (process_t* proc = rt_runqueue.head; proc; proc = proc->next) {
        if (proc->rt_priority < highest_prio) {
            highest_prio = proc->rt_priority;
            highest_priority = proc;
        }
    }

    return highest_priority;
}

// Real-time scheduling policy implementation
void schedule_realtime_process(process_t* proc) {
    switch (proc->sched_policy) {
        case SCHED_FIFO:
            // First-In-First-Out: run until voluntary yield or preemption
            proc->time_slice = INFINITE_TIME_SLICE;
            break;

        case SCHED_RR:
            // Round-Robin: fixed time slice
            proc->time_slice = RT_TIME_SLICE;
            break;

        case SCHED_SPORADIC:
            // Sporadic: budget-based scheduling
            proc->time_slice = min(proc->budget_remaining, RT_TIME_SLICE);
            break;
    }
}
```

## Container Scheduling

### Container-Aware Process Groups

```c
// Container resource allocation algorithm
void schedule_container_processes(container_t* container) {
    uint32_t total_cpu_limit = container->cpu_limit; // In CPU shares
    uint32_t process_count = container->process_count;

    // Calculate per-process CPU allocation
    uint32_t cpu_per_process = total_cpu_limit / process_count;

    // Distribute CPU time based on container limits
    for (process_t* proc = container->process_list; proc; proc = proc->next) {
        // Adjust process priority based on container allocation
        uint32_t container_priority_bonus =
            calculate_container_priority_bonus(container, cpu_per_process);

        proc->dynamic_priority = clamp(
            proc->static_priority - container_priority_bonus,
            MIN_PRIORITY, MAX_PRIORITY
        );

        // Update process time slice based on container limits
        proc->time_slice = calculate_container_time_slice(
            proc, container, cpu_per_process
        );
    }
}

// Container CPU throttling
bool should_throttle_container(container_t* container) {
    uint64_t current_time = get_system_time();
    uint64_t period_usage = container->cpu_usage_in_period;
    uint64_t period_limit = container->cpu_period_limit;

    // Check if container exceeded its CPU quota
    if (period_usage >= period_limit) {
        // Reset at period boundary
        if (current_time >= container->next_period_start) {
            container->cpu_usage_in_period = 0;
            container->next_period_start = current_time + container->cpu_period;
            return false;
        }
        return true; // Throttle until next period
    }

    return false;
}
```

## AI/ML Workload Scheduling

### GPU-Aware Scheduling

```c
// AI workload scheduling with GPU affinity
process_t* select_ai_process(void) {
    process_t* best_candidate = NULL;
    uint32_t highest_score = 0;

    for (process_t* proc = ai_runqueue.head; proc; proc = proc->next) {
        uint32_t score = calculate_ai_scheduling_score(proc);

        if (score > highest_score) {
            highest_score = score;
            best_candidate = proc;
        }
    }

    return best_candidate;
}

uint32_t calculate_ai_scheduling_score(process_t* proc) {
    uint32_t score = 0;

    // Prefer processes with GPU resources allocated
    if (proc->gpu_memory_allocated > 0) {
        score += 1000;
    }

    // Batch processing bonus
    if (proc->ai_workload_type == AI_BATCH_INFERENCE) {
        score += 500;
    }

    // Model size consideration (prefer larger models for efficiency)
    score += min(proc->model_size_mb / 100, 200);

    // Queue wait time (aging)
    uint64_t wait_time = get_system_time() - proc->queue_enter_time;
    score += min(wait_time / 1000, 300); // Max 300 points for wait time

    return score;
}
```

## Memory-Aware Scheduling

### NUMA-Aware Process Placement

```c
// NUMA topology-aware scheduling
int select_best_cpu_for_process(process_t* proc) {
    int best_cpu = -1;
    uint32_t best_score = 0;

    for (int cpu = 0; cpu < num_cpus; cpu++) {
        if (!(proc->cpu_affinity_mask & (1 << cpu))) {
            continue; // CPU not allowed by affinity mask
        }

        uint32_t score = calculate_numa_score(proc, cpu);

        if (score > best_score) {
            best_score = score;
            best_cpu = cpu;
        }
    }

    return best_cpu;
}

uint32_t calculate_numa_score(process_t* proc, int cpu) {
    uint32_t score = 1000; // Base score
    int numa_node = get_numa_node_for_cpu(cpu);

    // Memory locality bonus
    uint64_t local_memory = get_process_memory_on_node(proc, numa_node);
    uint64_t total_memory = proc->memory_usage;

    if (total_memory > 0) {
        uint32_t locality_bonus = (local_memory * 500) / total_memory;
        score += locality_bonus;
    }

    // CPU load penalty
    uint32_t cpu_load = get_cpu_load_percent(cpu);
    score -= cpu_load * 2;

    // Cache warmth bonus
    if (proc->last_cpu == cpu) {
        score += 200; // Prefer same CPU for cache locality
    }

    return score;
}
```

## Performance Characteristics

### Algorithm Complexity Analysis

| Algorithm Component | Time Complexity | Space Complexity | Notes |
|-------------------|----------------|------------------|-------|
| Process Selection | O(log n) | O(n) | Priority heap |
| Priority Update | O(n) amortized O(1) | O(1) | Aging calculation |
| Load Balancing | O(cores × processes) | O(cores) | Migration decisions |
| NUMA Placement | O(cores × nodes) | O(1) | Topology aware |
| Container Scheduling | O(containers × processes) | O(containers) | Resource allocation |
| RT Scheduling | O(rt_processes) | O(rt_processes) | Fixed priority |

### Performance Targets

- **Context Switch Latency**: <1μs on modern hardware
- **Scheduling Decision Time**: <10μs for 1000 processes
- **Load Balancing Overhead**: <1% of total CPU time
- **Real-time Scheduling Jitter**: <5μs worst-case
- **Container Scheduling Fairness**: ±2% of allocated share

## Scheduling Policies

### Policy Implementation Matrix

| Policy | Algorithm | Use Case | Preemption | Time Slice |
|--------|-----------|----------|------------|------------|
| SCHED_NORMAL | CFS-like | General purpose | Yes | Dynamic |
| SCHED_FIFO | Fixed Priority | Real-time | Yes | Infinite |
| SCHED_RR | Round Robin | Real-time | Yes | Fixed |
| SCHED_BATCH | Low Priority | Background | Yes | Long |
| SCHED_IDLE | Lowest Priority | System cleanup | Yes | Long |
| SCHED_SPORADIC | Budget-based | Periodic RT | Yes | Budget |

### Configuration Parameters

```c
// Scheduler tuning parameters
#define BASE_TIME_SLICE         10000    // 10ms in microseconds
#define MIN_TIME_SLICE          1000     // 1ms minimum
#define MAX_TIME_SLICE          100000   // 100ms maximum
#define AGING_FACTOR            5000     // 5ms aging increment
#define MAX_AGING_BONUS         50       // Maximum aging bonus
#define INTERACTIVE_BONUS       10       // I/O bound process bonus
#define CPU_PENALTY_DIVISOR     20       // CPU usage penalty factor
#define LOAD_IMBALANCE_THRESHOLD 20      // 20% load difference
#define MIGRATION_COST          1000     // Migration overhead estimate
#define RT_TIME_SLICE           5000     // 5ms for round-robin RT
```

## Implementation Status

### Completed Algorithms ✅
- [x] Priority-based preemptive scheduling
- [x] Dynamic priority calculation with aging
- [x] Adaptive time slice calculation
- [x] Multi-core load balancing
- [x] Real-time scheduling (FIFO, RR)
- [x] Container-aware scheduling

### Planned Enhancements (Phase 2-3)
- [ ] Machine learning-based workload prediction
- [ ] Energy-aware scheduling for mobile/edge
- [ ] Heterogeneous computing (CPU+GPU+NPU)
- [ ] Distributed scheduling across clusters
- [ ] Quantum computing task scheduling

---
*CloudOS Scheduling Algorithms v1.0 - Optimized for Cloud and Real-Time Workloads*