#ifndef KERNEL_TIME_H
#define KERNEL_TIME_H

#include "kernel/types.h"

// Time structures
typedef struct {
    uint64_t seconds;      // Seconds since epoch
    uint32_t nanoseconds;  // Nanoseconds within the current second
} timespec_t;

typedef struct {
    uint32_t year;
    uint8_t month;     // 1-12
    uint8_t day;       // 1-31
    uint8_t hour;      // 0-23
    uint8_t minute;    // 0-59
    uint8_t second;    // 0-59
    uint32_t nanosecond;
} datetime_t;

// Timer callback function type
typedef void (*timer_callback_t)(void* data);

// Timer structure
typedef struct timer {
    uint64_t expires;           // When timer expires (in ticks)
    timer_callback_t callback;  // Function to call when timer expires
    void* data;                 // Data to pass to callback
    bool active;                // Whether timer is active
    struct timer* next;         // Next timer in list
} timer_t;

// System time constants
#define NANOSECONDS_PER_SECOND  1000000000ULL
#define MICROSECONDS_PER_SECOND 1000000ULL
#define MILLISECONDS_PER_SECOND 1000ULL
#define TICKS_PER_SECOND        1000ULL  // 1000 Hz timer

// Unix epoch start
#define UNIX_EPOCH_YEAR 1970

// Time management functions
void time_init(void);
uint64_t get_system_time_ms(void);
uint64_t get_system_time_us(void);
uint64_t get_system_time_ns(void);
uint64_t get_uptime_ms(void);
uint64_t get_unix_timestamp(void);

// Timespec operations
void get_current_time(timespec_t* ts);
void timespec_add(timespec_t* result, const timespec_t* a, const timespec_t* b);
void timespec_sub(timespec_t* result, const timespec_t* a, const timespec_t* b);
int timespec_compare(const timespec_t* a, const timespec_t* b);
void timespec_to_ms(const timespec_t* ts, uint64_t* ms);
void ms_to_timespec(uint64_t ms, timespec_t* ts);

// Date/time conversion
void timestamp_to_datetime(uint64_t timestamp, datetime_t* dt);
uint64_t datetime_to_timestamp(const datetime_t* dt);
bool is_leap_year(uint32_t year);
uint8_t days_in_month(uint8_t month, uint32_t year);

// Timer management
timer_t* timer_create(uint64_t timeout_ms, timer_callback_t callback, void* data);
void timer_start(timer_t* timer);
void timer_stop(timer_t* timer);
void timer_destroy(timer_t* timer);
void timer_tick(void);  // Called by timer interrupt handler

// Sleep functions
void sleep_ms(uint64_t milliseconds);
void sleep_us(uint64_t microseconds);
void delay_ms(uint64_t milliseconds);  // Busy wait
void delay_us(uint64_t microseconds);  // Busy wait

// Time zone support (basic)
extern int32_t system_timezone_offset; // Offset from UTC in seconds

// Platform-specific time functions (implemented in HAL)
uint64_t hal_get_timestamp_ns(void);
uint64_t hal_get_cpu_cycles(void);
uint64_t hal_get_cpu_frequency(void);
void hal_timer_init(void);
void hal_timer_set_frequency(uint32_t hz);

// RTC (Real-Time Clock) functions
bool rtc_available(void);
void rtc_read_time(datetime_t* dt);
void rtc_set_time(const datetime_t* dt);

#endif // KERNEL_TIME_H