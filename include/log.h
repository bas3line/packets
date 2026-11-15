/* log.h - leveled logging with optional colour, always to stderr. */
#ifndef PS_LOG_H
#define PS_LOG_H

#include <stddef.h>

typedef enum {
    PS_LOG_DEBUG = 0,
    PS_LOG_INFO,
    PS_LOG_WARN,
    PS_LOG_ERROR,
    PS_LOG_OFF
} ps_log_level;

void ps_log_init(ps_log_level level, int color);
int ps_log_enabled(ps_log_level level);
void ps_log(ps_log_level level, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

/* Wall-clock "HH:MM:SS.micro" into buf (at least 16 bytes). */
void ps_clock_stamp(char *buf, size_t cap);

#define LOG_DEBUG(...) ps_log(PS_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) ps_log(PS_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...) ps_log(PS_LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) ps_log(PS_LOG_ERROR, __VA_ARGS__)

#endif /* PS_LOG_H */
