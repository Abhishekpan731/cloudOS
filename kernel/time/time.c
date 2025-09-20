#include "kernel/time.h"
#include "kernel/memory.h"
#include "kernel/hal.h"

// System time variables
static volatile uint64_t system_ticks = 0;
static volatile uint64_t boot_time_unix = 0;
static timer_t* active_timers = NULL;
static bool time_initialized = false;

// Time zone offset (in seconds from UTC)
int32_t system_timezone_offset = 0;

// Days in each month (non-leap year)
static const uint8_t days_per_month[12] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

void time_init(void) {
    if (time_initialized) {
        return;
    }

    // Initialize HAL timer
    hal_timer_init();
    hal_timer_set_frequency(TICKS_PER_SECOND);

    // Try to get initial time from RTC if available
    if (rtc_available()) {
        datetime_t dt;
        rtc_read_time(&dt);
        boot_time_unix = datetime_to_timestamp(&dt);
    } else {
        // If no RTC, assume Unix epoch start for now
        // This should be updated via NTP or manual setting
        boot_time_unix = 0;
    }

    system_ticks = 0;
    active_timers = NULL;
    time_initialized = true;
}

uint64_t get_system_time_ms(void) {
    if (!time_initialized) {
        return 0;
    }
    return system_ticks;
}

uint64_t get_system_time_us(void) {
    if (!time_initialized) {
        return 0;
    }
    return system_ticks * 1000;
}

uint64_t get_system_time_ns(void) {
    if (!time_initialized) {
        return 0;
    }

    // Use high-resolution timer if available
    uint64_t hal_ns = hal_get_timestamp_ns();
    if (hal_ns > 0) {
        return hal_ns;
    }

    // Fallback to tick-based time
    return system_ticks * 1000000;
}

uint64_t get_uptime_ms(void) {
    return get_system_time_ms();
}

uint64_t get_unix_timestamp(void) {
    if (!time_initialized) {
        return 0;
    }
    return boot_time_unix + (system_ticks / 1000);
}

void get_current_time(timespec_t* ts) {
    if (!ts || !time_initialized) {
        return;
    }

    uint64_t total_ns = get_system_time_ns();
    ts->seconds = boot_time_unix + (total_ns / NANOSECONDS_PER_SECOND);
    ts->nanoseconds = total_ns % NANOSECONDS_PER_SECOND;
}

void timespec_add(timespec_t* result, const timespec_t* a, const timespec_t* b) {
    if (!result || !a || !b) {
        return;
    }

    result->seconds = a->seconds + b->seconds;
    result->nanoseconds = a->nanoseconds + b->nanoseconds;

    // Handle nanosecond overflow
    if (result->nanoseconds >= NANOSECONDS_PER_SECOND) {
        result->seconds++;
        result->nanoseconds -= NANOSECONDS_PER_SECOND;
    }
}

void timespec_sub(timespec_t* result, const timespec_t* a, const timespec_t* b) {
    if (!result || !a || !b) {
        return;
    }

    result->seconds = a->seconds - b->seconds;

    if (a->nanoseconds >= b->nanoseconds) {
        result->nanoseconds = a->nanoseconds - b->nanoseconds;
    } else {
        result->seconds--;
        result->nanoseconds = (NANOSECONDS_PER_SECOND + a->nanoseconds) - b->nanoseconds;
    }
}

int timespec_compare(const timespec_t* a, const timespec_t* b) {
    if (!a || !b) {
        return 0;
    }

    if (a->seconds > b->seconds) return 1;
    if (a->seconds < b->seconds) return -1;

    if (a->nanoseconds > b->nanoseconds) return 1;
    if (a->nanoseconds < b->nanoseconds) return -1;

    return 0;
}

void timespec_to_ms(const timespec_t* ts, uint64_t* ms) {
    if (!ts || !ms) {
        return;
    }
    *ms = (ts->seconds * 1000) + (ts->nanoseconds / 1000000);
}

void ms_to_timespec(uint64_t ms, timespec_t* ts) {
    if (!ts) {
        return;
    }
    ts->seconds = ms / 1000;
    ts->nanoseconds = (ms % 1000) * 1000000;
}

bool is_leap_year(uint32_t year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

uint8_t days_in_month(uint8_t month, uint32_t year) {
    if (month < 1 || month > 12) {
        return 0;
    }

    if (month == 2 && is_leap_year(year)) {
        return 29;
    }

    return days_per_month[month - 1];
}

void timestamp_to_datetime(uint64_t timestamp, datetime_t* dt) {
    if (!dt) {
        return;
    }

    // Simple implementation - can be optimized
    uint64_t days = timestamp / 86400;  // Seconds per day
    uint64_t seconds_today = timestamp % 86400;

    // Calculate year
    uint32_t year = UNIX_EPOCH_YEAR;
    while (days >= (is_leap_year(year) ? 366 : 365)) {
        days -= is_leap_year(year) ? 366 : 365;
        year++;
    }
    dt->year = year;

    // Calculate month and day
    uint8_t month = 1;
    while (days >= days_in_month(month, year)) {
        days -= days_in_month(month, year);
        month++;
    }
    dt->month = month;
    dt->day = (uint8_t)(days + 1);

    // Calculate time
    dt->hour = (uint8_t)(seconds_today / 3600);
    seconds_today %= 3600;
    dt->minute = (uint8_t)(seconds_today / 60);
    dt->second = (uint8_t)(seconds_today % 60);
    dt->nanosecond = 0;  // We don't have nanosecond precision in timestamp
}

uint64_t datetime_to_timestamp(const datetime_t* dt) {
    if (!dt) {
        return 0;
    }

    uint64_t timestamp = 0;

    // Count days from epoch year to target year
    for (uint32_t y = UNIX_EPOCH_YEAR; y < dt->year; y++) {
        timestamp += is_leap_year(y) ? 366 : 365;
    }

    // Count days from start of year to target month
    for (uint8_t m = 1; m < dt->month; m++) {
        timestamp += days_in_month(m, dt->year);
    }

    // Add days in current month (minus 1 since day is 1-based)
    timestamp += dt->day - 1;

    // Convert days to seconds
    timestamp *= 86400;

    // Add hours, minutes, seconds
    timestamp += dt->hour * 3600;
    timestamp += dt->minute * 60;
    timestamp += dt->second;

    return timestamp;
}

timer_t* timer_create(uint64_t timeout_ms, timer_callback_t callback, void* data) {
    if (!callback) {
        return NULL;
    }

    timer_t* timer = (timer_t*)kmalloc(sizeof(timer_t));
    if (!timer) {
        return NULL;
    }

    timer->expires = system_ticks + timeout_ms;
    timer->callback = callback;
    timer->data = data;
    timer->active = false;
    timer->next = NULL;

    return timer;
}

void timer_start(timer_t* timer) {
    if (!timer) {
        return;
    }

    timer->active = true;

    // Add to active timers list
    timer->next = active_timers;
    active_timers = timer;
}

void timer_stop(timer_t* timer) {
    if (!timer) {
        return;
    }

    timer->active = false;

    // Remove from active timers list
    if (active_timers == timer) {
        active_timers = timer->next;
    } else {
        timer_t* current = active_timers;
        while (current && current->next != timer) {
            current = current->next;
        }
        if (current) {
            current->next = timer->next;
        }
    }
}

void timer_destroy(timer_t* timer) {
    if (!timer) {
        return;
    }

    timer_stop(timer);
    kfree(timer);
}

void timer_tick(void) {
    system_ticks++;

    // Check expired timers
    timer_t* current = active_timers;
    timer_t* prev = NULL;

    while (current) {
        if (current->active && system_ticks >= current->expires) {
            // Timer expired, call callback
            current->callback(current->data);

            // Remove from active list
            if (prev) {
                prev->next = current->next;
            } else {
                active_timers = current->next;
            }

            timer_t* next = current->next;
            current->active = false;
            current = next;
        } else {
            prev = current;
            current = current->next;
        }
    }
}

void sleep_ms(uint64_t milliseconds) {
    uint64_t start_time = system_ticks;
    uint64_t end_time = start_time + milliseconds;

    // This is a simple busy wait implementation
    // In a real OS, this would yield to other processes
    while (system_ticks < end_time) {
        // Yield CPU or halt until next timer interrupt
        __asm__ volatile("hlt");
    }
}

void sleep_us(uint64_t microseconds) {
    sleep_ms(microseconds / 1000);
}

void delay_ms(uint64_t milliseconds) {
    // Busy wait using CPU cycles for more precise delays
    uint64_t cpu_freq = hal_get_cpu_frequency();
    if (cpu_freq == 0) {
        // Fallback to sleep if CPU frequency unknown
        sleep_ms(milliseconds);
        return;
    }

    uint64_t cycles_per_ms = cpu_freq / 1000;
    uint64_t target_cycles = cycles_per_ms * milliseconds;
    uint64_t start_cycles = hal_get_cpu_cycles();

    while ((hal_get_cpu_cycles() - start_cycles) < target_cycles) {
        // Busy wait
        __asm__ volatile("pause");
    }
}

void delay_us(uint64_t microseconds) {
    uint64_t cpu_freq = hal_get_cpu_frequency();
    if (cpu_freq == 0) {
        sleep_us(microseconds);
        return;
    }

    uint64_t cycles_per_us = cpu_freq / 1000000;
    uint64_t target_cycles = cycles_per_us * microseconds;
    uint64_t start_cycles = hal_get_cpu_cycles();

    while ((hal_get_cpu_cycles() - start_cycles) < target_cycles) {
        __asm__ volatile("pause");
    }
}

// Weak implementations for RTC functions (can be overridden by platform-specific code)
__attribute__((weak)) bool rtc_available(void) {
    return false;
}

__attribute__((weak)) void rtc_read_time(datetime_t* dt) {
    if (dt) {
        // Default to Unix epoch
        dt->year = UNIX_EPOCH_YEAR;
        dt->month = 1;
        dt->day = 1;
        dt->hour = 0;
        dt->minute = 0;
        dt->second = 0;
        dt->nanosecond = 0;
    }
}

__attribute__((weak)) void rtc_set_time(const datetime_t* dt) {
    // Default implementation does nothing
    (void)dt;
}