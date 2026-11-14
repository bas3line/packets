/* log.c - leveled logging. */
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static ps_log_level g_level = PS_LOG_INFO;
static int g_color = 0;

void ps_log_init(ps_log_level level, int color) {
    g_level = level;
    /* Only emit colour when stderr is a terminal, unless forced. */
    g_color = color && isatty(STDERR_FILENO);
}

int ps_log_enabled(ps_log_level level) { return level >= g_level; }

void ps_clock_stamp(char *buf, size_t cap) {
    struct timespec ts;
    struct tm tm;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    snprintf(buf, cap, "%02d:%02d:%02d.%06ld", tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000);
}

static const char *level_tag(ps_log_level level) {
    switch (level) {
    case PS_LOG_DEBUG:
        return "dbg";
    case PS_LOG_INFO:
        return "inf";
    case PS_LOG_WARN:
        return "warn";
    case PS_LOG_ERROR:
        return "err";
    default:
        return "???";
    }
}

static const char *level_color(ps_log_level level) {
    switch (level) {
    case PS_LOG_DEBUG:
        return "\033[0;90m";
    case PS_LOG_INFO:
        return "\033[0;36m";
    case PS_LOG_WARN:
        return "\033[1;33m";
    case PS_LOG_ERROR:
        return "\033[1;31m";
    default:
        return "";
    }
}

void ps_log(ps_log_level level, const char *fmt, ...) {
    if (!ps_log_enabled(level)) {
        return;
    }

    char stamp[32];
    ps_clock_stamp(stamp, sizeof(stamp));

    const char *prefix = g_color ? level_color(level) : "";
    const char *reset = g_color ? "\033[0m" : "";

    fprintf(stderr, "%s%s [%s]%s ", prefix, stamp, level_tag(level), reset);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}
