# CloudOS Process Management Guide

## Overview

The CloudOS process management system provides a comprehensive framework for process creation, scheduling, synchronization, and lifecycle management. This guide details the architecture, algorithms, and implementation of the process subsystem, designed to support high-performance computing workloads while maintaining security and efficiency.

## Process Architecture

### Process Model

```text
Process Hierarchy:
┌─────────────────────────────────────────────────────────────┐
│                    System Processes                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   init (1)  │ │  kthreadd   │ │  systemd    │           │
│  │             │ │  (2)        │ │  (user)     │           │
│  └──────┬──────┘ └─────────────┘ └─────────────┘           │
│         │                                                  │
│  ┌──────▼──────┐                                           │
│  │ User Session│                                           │
│  │             │                                           │
│  └──────┬──────┘                                           │
│         │                                                  │
│  ┌──────▼──────┐     ┌─────────────┐                       │
│  │   Shell     │────►│   Commands  │                       │
│  │             │     │             │                       │
│  └──────┬──────┘     └─────────────┘                       │
│         │                                                  │
│  ┌──────▼──────┐                                           │
│  │ Application │                                           │
│  │ Processes   │                                           │
│  └─────────────┘                                           │
├─────────────────────────────────────────────────────────────┤
│                Thread Groups                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Thread 1  │ │   Thread 2  │ │   Thread 3  │           │
│  │ (Main)      │ │             │ │             │           │
│  └──────┬──────┘ └─────────────┘ └─────────────┘           │
│         │                                                  │
│  ┌──────▼──────┐                                           │
│  │ Shared      │                                           │
│  │ Resources   │                                           │
│  │             │                                           │
│  │ ┌─────────┐ │                                           │
│  │ │ Address │ │                                           │
│  │ │ Space   │ │                                           │
│  │ │ Files   │ │                                           │
│  │ │ Signals │ │                                           │
│  │ └─────────┘ │                                           │
│  └─────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

### Process Control Block (PCB)

```c
// Process control block structure
struct task_struct {
    // Process identification
    pid_t pid;                          // Process ID
    pid_t tgid;                         // Thread group ID
    struct pid *pids[PIDTYPE_MAX];      // PID structures

    // Process relationships
    struct task_struct *parent;         // Parent process
    struct list_head children;          // Child processes
    struct list_head sibling;           // Sibling processes

    // Process state
    volatile long state;                // Process state
    void *stack;                        // Kernel stack
    struct thread_info *thread_info;    // Thread information

    // CPU state
    struct thread_struct thread;        // Architecture-specific state

    // Memory management
    struct mm_struct *mm;               // Memory descriptor
    struct mm_struct *active_mm;        // Active memory descriptor

    // File system
    struct fs_struct *fs;               // File system information
    struct files_struct *files;         // Open files

    // Scheduling
    int prio;                          // Dynamic priority
    int static_prio;                   // Static priority
    int normal_prio;                   // Normal priority
    unsigned int rt_priority;          // Real-time priority

    // Scheduling classes
    const struct sched_class *sched_class; // Scheduler class
    struct sched_entity se;            // Scheduling entity
    struct sched_rt_entity rt;         // Real-time entity

    // Timing
    u64 start_time;                    // Start time
    u64 real_start_time;               // Real start time
    u64 utime;                         // User time
    u64 stime;                         // System time

    // Signals
    struct signal_struct *signal;      // Signal handlers
    struct sighand_struct *sighand;    // Signal handlers
    sigset_t blocked;                  // Blocked signals
    sigset_t real_blocked;             // Real blocked signals

    // Credentials
    const struct cred *real_cred;      // Real credentials
    const struct cred *cred;           // Effective credentials

    // Namespaces
    struct nsproxy *nsproxy;           // Namespace proxy

    // Cgroups
    struct cgroup_subsys_state *cgroups[CGROUP_SUBSYS_COUNT];

    // Statistics
    struct task_stats stats;           // Process statistics

    // Debug
    struct audit_context *audit_context; // Audit context
};
```

## Process States

### Process State Machine

```text
Process States:
     ┌─────────────┐
     │   Created   │
     └──────┬──────┘
            │
     ┌──────▼──────┐
     │   Ready     │ ◄─────────────────┐
     └──────┬──────┘                   │
            │                          │
     ┌──────▼──────┐          ┌────────▼────────┐
     │  Running    │          │   Blocked       │
     └──────┬──────┘          └────────┬────────┘
            │                          │
     ┌──────▼──────┐                   │
     │ Terminated  │                   │
     └─────────────┘                   │
            ▲                          │
            └──────────────────────────┘
                 I/O Completion / Event
```

### State Definitions

```c
// Process states
#define TASK_RUNNING         0x00000000  // Running or runnable
#define TASK_INTERRUPTIBLE   0x00000001  // Sleeping, interruptible
#define TASK_UNINTERRUPTIBLE 0x00000002  // Sleeping, uninterruptible
#define TASK_STOPPED         0x00000004  // Stopped
#define TASK_TRACED          0x00000008  // Being traced
#define TASK_DEAD            0x00000010  // Zombie process
#define TASK_WAKEKILL        0x00000020  // Wake on kill signal
#define TASK_WAKING          0x00000040  // Waking up
#define TASK_PARKED          0x00000080  // Parked
#define TASK_NOLOAD          0x00000100  // No load balancing
#define TASK_NEW             0x00000200  // New process
```

## Process Scheduling

### Scheduler Classes

#### Completely Fair Scheduler (CFS)

```c
// CFS run queue
struct cfs_rq {
    struct load_weight load;           // Run queue load
    unsigned int nr_running;           // Number of running tasks

    u64 exec_clock;                    // Execution clock
    u64 min_vruntime;                  // Minimum virtual runtime

    struct rb_root_cached tasks_timeline; // RB tree of tasks
    struct rb_node *rb_leftmost;       // Leftmost node

    struct list_head tasks;            // List of tasks
    struct sched_entity *curr;         // Currently running task
    struct sched_entity *next;         // Next task to run

    // Statistics
    u64 nr_spread_over;                // Spread over
    u64 nr_migrations;                 // Number of migrations
};

// Scheduling entity
struct sched_entity {
    struct load_weight load;           // Load weight
    struct rb_node run_node;           // RB tree node
    struct list_head group_node;       // Group node

    unsigned int on_rq;                // On run queue

    u64 exec_start;                    // Execution start time
    u64 sum_exec_runtime;              // Total execution time
    u64 vruntime;                      // Virtual runtime
    u64 prev_sum_exec_runtime;         // Previous execution time

    u64 last_wakeup;                   // Last wakeup time
    u64 avg_overlap;                   // Average overlap

    struct sched_statistics statistics; // Statistics
};
```

#### Real-Time Scheduler

```c
// Real-time run queue
struct rt_rq {
    struct rt_prio_array active;       // Active priority array
    unsigned int rt_nr_running;        // Number of RT tasks

    int highest_prio;                  // Highest priority
    int rt_queued;                     // RT tasks queued

    // Throttling
    u64 rt_time;                       // RT time
    u64 rt_runtime;                    // RT runtime

    struct hrtimer rt_period_timer;    // Period timer
};

// Real-time priority array
struct rt_prio_array {
    DECLARE_BITMAP(bitmap, MAX_RT_PRIO); // Priority bitmap
    struct list_head queue[MAX_RT_PRIO]; // Priority queues
};
```

### Scheduling Algorithm

```c
// Main scheduling function
struct task_struct *schedule(void) {
    struct task_struct *prev, *next;
    unsigned long *switch_count;
    struct rq *rq;
    int cpu;

    // Get current CPU run queue
    cpu = smp_processor_id();
    rq = cpu_rq(cpu);
    prev = rq->curr;

    // Schedule previous task
    schedule_debug(prev);

    // Clear previous task
    if (prev->state && !(preempt_count() & PREEMPT_ACTIVE)) {
        if (unlikely(signal_pending_state(prev->state, prev))) {
            prev->state = TASK_RUNNING;
        } else {
            deactivate_task(rq, prev, DEQUEUE_SLEEP);
        }
        switch_count = &prev->nvcsw;
    }

    // Pick next task
    next = pick_next_task(rq, prev);
    if (likely(next != prev)) {
        rq->curr = next;
        ++*switch_count;

        // Context switch
        context_switch(rq, prev, next);
        return next;
    }

    return prev;
}

// Pick next task to run
struct task_struct *pick_next_task(struct rq *rq, struct task_struct *prev) {
    const struct sched_class *class;
    struct task_struct *p;

    // Try each scheduling class in priority order
    for_each_class(class) {
        p = class->pick_next_task(rq);
        if (p) return p;
    }

    // No task found, return idle task
    return rq->idle;
}
```

## Process Creation and Destruction

### Fork Implementation

```c
// Process fork system call
pid_t sys_fork(void) {
    struct kernel_clone_args args = {
        .flags = SIGCHLD,
        .exit_signal = SIGCHLD,
    };

    return kernel_clone(&args);
}

// Kernel clone implementation
pid_t kernel_clone(struct kernel_clone_args *args) {
    struct task_struct *p;
    int trace = 0;
    pid_t pid;

    // Allocate new task structure
    p = dup_task_struct(current, args->node);
    if (!p) return -ENOMEM;

    // Copy process state
    copy_process(p, trace, args->node, args);

    // Initialize new process
    init_new_process(p);

    // Wake up new process
    wake_up_new_task(p);

    // Return PID
    pid = p->pid;
    return pid;
}

// Duplicate task structure
struct task_struct *dup_task_struct(struct task_struct *orig, int node) {
    struct task_struct *tsk;
    int err;

    // Allocate task structure
    tsk = alloc_task_struct_node(node);
    if (!tsk) return NULL;

    // Copy task structure
    *tsk = *orig;

    // Initialize new fields
    tsk->thread_pid = 0;
    tsk->wake_entry.func = NULL;
    tsk->wake_entry.private = 0;

    // Initialize lists
    INIT_LIST_HEAD(&tsk->children);
    INIT_LIST_HEAD(&tsk->sibling);

    return tsk;
}
```

### Process Exit

```c
// Process exit system call
void sys_exit(int code) {
    do_exit(code);
}

// Process exit implementation
void do_exit(long code) {
    struct task_struct *tsk = current;

    // Set exit code
    tsk->exit_code = code;

    // Notify parent
    if (tsk->parent) {
        tsk->parent->signal->group_exit_code = code;
        wake_up_process(tsk->parent);
    }

    // Release resources
    exit_mm(tsk);
    exit_files(tsk);
    exit_fs(tsk);
    exit_thread(tsk);

    // Change state to zombie
    tsk->state = TASK_DEAD;

    // Schedule final cleanup
    schedule();
}

// Process cleanup (called by parent)
void release_task(struct task_struct *p) {
    // Free PID
    free_pid(p->pid);

    // Free task structure
    free_task_struct(p);
}
```

## Thread Management

### Thread Creation

```c
// Thread creation
int sys_clone(unsigned long clone_flags, unsigned long newsp,
              int __user *parent_tidptr, int __user *child_tidptr,
              unsigned long tls) {
    struct kernel_clone_args args = {
        .flags = clone_flags,
        .pidfd = parent_tidptr,
        .child_tid = child_tidptr,
        .parent_tid = parent_tidptr,
        .exit_signal = (clone_flags & CLONE_THREAD) ? -1 : SIGCHLD,
        .stack = newsp,
        .tls = tls,
    };

    return kernel_clone(&args);
}

// Thread-specific clone flags
#define CLONE_THREAD     0x00010000  // Share thread group
#define CLONE_SIGHAND    0x00000800  // Share signal handlers
#define CLONE_VM         0x00000100  // Share address space
#define CLONE_FILES      0x00000400  // Share open files
#define CLONE_FS         0x00000200  // Share file system info
```

### Thread Synchronization

#### Mutex Implementation

```c
// Futex-based mutex
struct mutex {
    atomic_long_t owner;
    spinlock_t wait_lock;
    struct list_head wait_list;
};

// Mutex lock
void mutex_lock(struct mutex *lock) {
    // Fast path - try to acquire
    if (atomic_long_cmpxchg(&lock->owner, 0, current->pid) == 0) {
        return;
    }

    // Slow path - wait
    mutex_lock_slowpath(lock);
}

void mutex_lock_slowpath(struct mutex *lock) {
    struct task_struct *owner;

    for (;;) {
        // Check if lock is available
        if (atomic_long_cmpxchg(&lock->owner, 0, current->pid) == 0) {
            break;
        }

        // Add to wait list
        list_add_tail(&current->wait_list, &lock->wait_list);

        // Sleep
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule();

        // Remove from wait list
        list_del(&current->wait_list);
    }
}

// Mutex unlock
void mutex_unlock(struct mutex *lock) {
    // Clear owner
    atomic_long_set(&lock->owner, 0);

    // Wake up waiter
    if (!list_empty(&lock->wait_list)) {
        struct task_struct *waiter = list_first_entry(&lock->wait_list,
                                                     struct task_struct, wait_list);
        wake_up_process(waiter);
    }
}
```

## Process Synchronization

### Semaphore Implementation

```c
// System V semaphore
struct sem_array {
    struct kern_ipc_perm sem_perm;     // Permissions
    time_t sem_otime;                  // Last operation time
    time_t sem_ctime;                  // Creation time
    struct sem *sem_base;              // Array of semaphores
    struct list_head sem_pending;      // Pending operations
    struct list_head list_id;          // List of semaphore arrays
    int sem_nsems;                     // Number of semaphores
    int sem_id;                        // Semaphore ID
};

// Semaphore operations
int semop(int semid, struct sembuf *sops, unsigned nsops) {
    struct sem_array *sma;
    struct sembuf *sop;
    int error;

    // Get semaphore array
    sma = sem_obtain_object_check(current->nsproxy->ipc_ns, semid);
    if (IS_ERR(sma)) return PTR_ERR(sma);

    // Perform operations
    for (sop = sops; sop < sops + nsops; sop++) {
        int semnum = sop->sem_num;
        int alter = sop->sem_op;

        if (alter > 0) {
            // Increase semaphore
            sma->sem_base[semnum].semval += alter;
            // Wake up waiters
            wake_up_semaphore_waiters(sma, semnum);
        } else if (alter < 0) {
            // Decrease semaphore
            while (sma->sem_base[semnum].semval < -alter) {
                // Wait
                sleep_on_semaphore(sma, semnum);
            }
            sma->sem_base[semnum].semval += alter;
        } else {
            // Wait for zero
            while (sma->sem_base[semnum].semval != 0) {
                sleep_on_semaphore(sma, semnum);
            }
        }
    }

    return 0;
}
```

### Message Queue Implementation

```c
// System V message queue
struct msg_queue {
    struct kern_ipc_perm q_perm;       // Permissions
    time_t q_stime;                    // Last send time
    time_t q_rtime;                    // Last receive time
    time_t q_ctime;                    // Creation time
    unsigned long q_cbytes;            // Current bytes
    unsigned long q_qnum;              // Number of messages
    unsigned long q_qbytes;            // Max bytes
    pid_t q_lspid;                     // Last send PID
    pid_t q_lrpid;                     // Last receive PID
    struct list_head q_messages;       // Message list
    struct list_head q_receivers;      // Waiting receivers
    struct list_head q_senders;        // Waiting senders
};

// Message structure
struct msg_msg {
    struct list_head m_list;           // Message list
    long m_type;                       // Message type
    size_t m_ts;                       // Message size
    struct msg_msgseg *next;           // Next segment
    void *security;                    // Security context
    /* the actual message follows immediately */
};

// Send message
int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) {
    struct msg_queue *msq;
    struct msg_msg *msg;
    long mtype;

    // Get message queue
    msq = msg_obtain_object_check(current->nsproxy->ipc_ns, msqid);
    if (IS_ERR(msq)) return PTR_ERR(msq);

    // Allocate message
    msg = alloc_msg(msgsz);
    if (!msg) return -ENOMEM;

    // Copy message
    mtype = copy_msg(msg, msgp, msgsz);
    msg->m_type = mtype;

    // Add to queue
    list_add_tail(&msg->m_list, &msq->q_messages);
    msq->q_qnum++;
    msq->q_cbytes += msgsz;

    // Wake up receivers
    wake_up_msg_receivers(msq);

    return 0;
}

// Receive message
int msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
    struct msg_queue *msq;
    struct msg_msg *msg;

    // Get message queue
    msq = msg_obtain_object_check(current->nsproxy->ipc_ns, msqid);
    if (IS_ERR(msq)) return PTR_ERR(msq);

    // Find message
    msg = find_msg(msq, msgtyp, msgflg);
    if (!msg) {
        // Wait for message
        sleep_on_msg_queue(msq, msgtyp);
        msg = find_msg(msq, msgtyp, msgflg);
    }

    if (!msg) return -ENOMSG;

    // Copy message to user
    copy_msg_to_user(msgp, msg, msgsz);

    // Remove message
    list_del(&msg->m_list);
    msq->q_qnum--;
    msq->q_cbytes -= msg->m_ts;

    // Free message
    free_msg(msg);

    return msgsz;
}
```

## Signal Management

### Signal Delivery

```c
// Signal structure
struct siginfo {
    int si_signo;                      // Signal number
    int si_errno;                      // Error number
    int si_code;                       // Signal code
    union {
        // Signal-specific data
        struct {
            pid_t si_pid;             // Sending process ID
            uid_t si_uid;             // Sending user ID
            int si_status;            // Exit status
        } _sigchld;
        // ... other signal types
    } _sifields;
};

// Signal handler
struct sigaction {
    void (*sa_handler)(int);           // Signal handler
    unsigned long sa_flags;            // Flags
    sigset_t sa_mask;                  // Mask
    void (*sa_restorer)(void);         // Restorer
};

// Send signal to process
int send_sig_info(int sig, struct siginfo *info, struct task_struct *t) {
    unsigned long flags;
    int ret = -EAGAIN;

    spin_lock_irqsave(&t->sighand->siglock, flags);

    // Check if signal is blocked
    if (!sig_ignored(t, sig) && !sig_task_ignored(t, sig)) {
        // Queue signal
        ret = queue_signal(t, sig, info);
    }

    spin_unlock_irqrestore(&t->sighand->siglock, flags);

    if (ret > 0) {
        // Wake up process if necessary
        signal_wake_up(t, sig);
    }

    return ret;
}
```

### Signal Handling

```c
// Signal handling in kernel
void do_signal(struct pt_regs *regs) {
    struct ksignal ksig;
    int signr;

    // Get pending signal
    if (get_signal(&ksig)) {
        // Set up signal frame
        if (setup_sigframe(&ksig, regs) != 0) {
            // Failed to set up frame
            force_sigsegv(ksig.sig, current);
            return;
        }

        // Call signal handler
        signal_delivered(ksig.sig, &ksig.info, &ksig.ka, regs);

        // Return to user space
        return;
    }

    // No signal to handle
    return;
}

// Setup signal frame
int setup_sigframe(struct ksignal *ksig, struct pt_regs *regs) {
    struct sigframe __user *frame;
    void __user *fp = NULL;
    int err = 0;

    // Allocate signal frame
    frame = get_sigframe(ksig, regs, sizeof(*frame));
    if (!access_ok(frame, sizeof(*frame))) {
        return -EFAULT;
    }

    // Setup frame
    put_user_try {
        put_user_ex(regs->ip, &frame->pretcode);
        put_user_ex(regs->sp, &frame->pinfo);
        put_user_ex(ksig->sig, &frame->sig);
        // ... setup rest of frame
    } put_user_catch(err);

    // Setup registers for signal handler
    regs->ip = (unsigned long) ksig->ka.sa.sa_handler;
    regs->sp = (unsigned long) frame;
    regs->dx = ksig->sig;

    return err;
}
```

## Process Groups and Sessions

### Process Group Management

```c
// Process group structure
struct pid *pid;
struct task_struct *tasks[PIDTYPE_MAX];

// Create new process group
int sys_setpgid(pid_t pid, pid_t pgid) {
    struct task_struct *p;
    struct pid *pgrp;
    int err;

    // Find process
    if (pid) {
        p = find_task_by_vpid(pid);
    } else {
        p = current;
    }

    if (!p) return -ESRCH;

    // Check permissions
    if (p != current) {
        if (!same_thread_group(p, current)) return -EPERM;
    }

    // Set process group
    if (pgid) {
        pgrp = find_get_pid(pgid);
        if (!pgrp) return -EPERM;
    } else {
        pgrp = task_pgrp(current);
    }

    err = setpgid(p, pgrp);
    if (pgrp != task_pgrp(current)) {
        put_pid(pgrp);
    }

    return err;
}
```

### Session Management

```c
// Create new session
pid_t sys_setsid(void) {
    struct task_struct *group_leader = current;
    struct pid *sid;
    int err;

    // Check if already session leader
    if (group_leader->signal->leader) return -EPERM;

    // Check if process group leader
    if (group_leader->signal->group_leader) {
        struct task_struct *p;

        // Check if any children in our group
        for_each_process(p) {
            if (p->parent == group_leader && same_pgrp(p, group_leader)) {
                return -EPERM;
            }
        }
    }

    // Create new session
    sid = alloc_pid(current->nsproxy->pid_ns_for_children);
    if (!sid) return -ENOMEM;

    // Set session ID
    group_leader->signal->session = sid->numbers[group_leader->nsproxy->pid_ns->level].nr;
    group_leader->signal->leader = 1;

    // Create new process group
    err = setpgid(group_leader, sid);
    if (err) {
        free_pid(sid);
        return err;
    }

    return group_leader->pid;
}
```

## Resource Management

### CPU Affinity

```c
// Set CPU affinity
int sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
    struct task_struct *p;
    struct cpumask *new_mask;
    int retval;

    // Find process
    if (pid) {
        p = find_task_by_vpid(pid);
    } else {
        p = current;
    }

    if (!p) return -ESRCH;

    // Check permissions
    if (!check_same_owner(p)) return -EPERM;

    // Convert cpu_set_t to cpumask
    new_mask = cpuset_to_cpumask(mask, cpusetsize);
    if (!new_mask) return -ENOMEM;

    // Set affinity
    retval = set_cpus_allowed_ptr(p, new_mask);

    free_cpumask_var(new_mask);
    return retval;
}

// Get CPU affinity
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
    struct task_struct *p;
    int retval;

    // Find process
    if (pid) {
        p = find_task_by_vpid(pid);
    } else {
        p = current;
    }

    if (!p) return -ESRCH;

    // Get affinity mask
    cpumask_to_cpuset(mask, &p->cpus_allowed);

    return 0;
}
```

### Priority Management

```c
// Set process priority
int sys_setpriority(int which, int who, int niceval) {
    struct task_struct *p;
    int error = -EINVAL;

    // Validate nice value
    if (niceval < MIN_NICE || niceval > MAX_NICE) return -EINVAL;

    switch (which) {
    case PRIO_PROCESS:
        if (who) {
            p = find_task_by_vpid(who);
        } else {
            p = current;
        }
        if (!p) return -ESRCH;
        error = set_one_prio(p, niceval, error);
        break;

    case PRIO_PGRP:
        if (who) {
            struct pid *pgrp = find_get_pid(who);
            if (!pgrp) return -ESRCH;
            error = set_prio_pgrp(pgrp, niceval);
            put_pid(pgrp);
        } else {
            error = set_prio_pgrp(task_pgrp(current), niceval);
        }
        break;

    case PRIO_USER:
        error = set_user_nice(current, niceval);
        break;
    }

    return error;
}
```

## Process Monitoring and Statistics

### Process Statistics

```c
// Process statistics structure
struct task_stats {
    u64 start_time;                    // Start time
    u64 end_time;                      // End time
    u64 user_time;                     // User CPU time
    u64 sys_time;                      // System CPU time
    u64 min_flt;                       // Minor page faults
    u64 maj_flt;                       // Major page faults
    u64 nvcsw;                         // Voluntary context switches
    u64 nivcsw;                        // Involuntary context switches
    u64 inblock;                       // Block I/O delays
    u64 oublock;                       // Block I/O delays
    u64 rss;                           // Resident set size
    u64 vsize;                         // Virtual memory size
    u64 nswap;                         // Swap pages
    u64 cnswap;                        // Cumulative swap pages
};

// Update process statistics
void update_process_stats(struct task_struct *task) {
    struct task_stats *stats = &task->stats;
    struct rusage *ru = &task->signal->ru;

    // Update CPU times
    stats->user_time = ru->ru_utime.tv_sec * 1000000 + ru->ru_utime.tv_usec;
    stats->sys_time = ru->ru_stime.tv_sec * 1000000 + ru->ru_stime.tv_usec;

    // Update memory statistics
    if (task->mm) {
        stats->rss = get_mm_rss(task->mm);
        stats->vsize = task->mm->total_vm << PAGE_SHIFT;
    }

    // Update I/O statistics
    stats->inblock = ru->ru_inblock;
    stats->oublock = ru->ru_oublock;
}
```

### Process Tracing

```c
// Process tracing structure
struct ptrace_context {
    struct task_struct *tracer;        // Tracing process
    struct task_struct *tracee;        // Traced process
    unsigned long flags;               // Tracing flags
    struct list_head tracees;          // List of tracees
};

// Attach to process
int ptrace_attach(struct task_struct *child) {
    int retval;

    // Check permissions
    retval = ptrace_check_attach(child);
    if (retval) return retval;

    // Set up tracing
    child->ptrace = PT_PTRACED;
    child->parent = current;
    child->ptrace_context = kzalloc(sizeof(*child->ptrace_context), GFP_KERNEL);
    if (!child->ptrace_context) return -ENOMEM;

    child->ptrace_context->tracer = current;
    child->ptrace_context->tracee = child;

    // Add to tracer's list
    list_add(&child->ptrace_context->tracees, &current->ptrace_context->tracees);

    // Stop the child
    send_sig_info(SIGSTOP, SEND_SIG_NOINFO, child);

    return 0;
}
```

## Security Features

### Process Credentials

```c
// Process credentials structure
struct cred {
    atomic_t usage;                    // Reference count
    uid_t uid;                         // Real UID
    gid_t gid;                         // Real GID
    uid_t suid;                        // Saved UID
    gid_t sgid;                        // Saved GID
    uid_t euid;                        // Effective UID
    gid_t egid;                        // Effective GID
    uid_t fsuid;                       // File system UID
    gid_t fsgid;                       // File system GID
    unsigned securebits;               // Secure bits
    kernel_cap_t cap_inheritable;      // Inheritable capabilities
    kernel_cap_t cap_permitted;        // Permitted capabilities
    kernel_cap_t cap_effective;        // Effective capabilities
    kernel_cap_t cap_bset;             // Bounding set
    kernel_cap_t cap_ambient;          // Ambient capabilities
    struct user_struct *user;          // User structure
    struct user_namespace *user_ns;    // User namespace
    struct group_info *group_info;     // Group information
};

// Check process permissions
bool capable(int cap) {
    struct cred *cred = current_cred();

    if (cred->cap_effective & CAP_TO_MASK(cap)) {
        return true;
    }

    return false;
}
```

## Future Enhancements

### Planned Features

- **Control Groups (cgroups)**: Resource control and isolation
- **Namespaces**: Process isolation improvements
- **Real-time Scheduling**: Enhanced real-time support
- **Process Migration**: Cross-node process migration
- **Container Integration**: Native container process management
- **AI Workload Scheduling**: ML-optimized process scheduling
- **Energy-Aware Scheduling**: Power-efficient process placement

---

## Document Information

**CloudOS Process Management Guide**
*Comprehensive guide for process lifecycle, scheduling, and synchronization*
