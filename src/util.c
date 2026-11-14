/* util.c - small shared helpers. */
#include "util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *g_prog = "pktsniff";

void ps_set_prog_name(const char *name) {
    if (name && *name) {
        g_prog = name;
    }
}

const char *ps_prog_name(void) { return g_prog; }

static void oom(size_t n) {
    fprintf(stderr, "%s: out of memory allocating %zu bytes\n", g_prog, n);
    exit(1);
}

void *ps_xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) {
        oom(n);
    }
    return p;
}

void *ps_xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        oom(n);
    }
    return q;
}

char *ps_strdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = ps_xmalloc(n);
    memcpy(p, s, n);
    return p;
}

size_t ps_strlcpy(char *dst, const char *src, size_t cap) {
    size_t len = strlen(src);
    if (cap > 0) {
        size_t n = len < cap - 1 ? len : cap - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return len;
}

uint64_t ps_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

void ps_sleep_ms(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

void ps_fmt_bytes(char *out, size_t cap, uint64_t bytes) {
    static const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = (double)bytes;
    size_t u = 0;

    while (v >= 1000.0 && u + 1 < sizeof(units) / sizeof(units[0])) {
        v /= 1000.0;
        u++;
    }
    if (u == 0) {
        snprintf(out, cap, "%llu B", (unsigned long long)bytes);
    } else if (v < 10.0) {
        snprintf(out, cap, "%.2f %s", v, units[u]);
    } else if (v < 100.0) {
        snprintf(out, cap, "%.1f %s", v, units[u]);
    } else {
        snprintf(out, cap, "%.0f %s", v, units[u]);
    }
}

void ps_fmt_rate(char *out, size_t cap, double value) {
    if (value >= 1e9) {
        snprintf(out, cap, "%.2f G/s", value / 1e9);
    } else if (value >= 1e6) {
        snprintf(out, cap, "%.2f M/s", value / 1e6);
    } else if (value >= 1e3) {
        snprintf(out, cap, "%.1f k/s", value / 1e3);
    } else {
        snprintf(out, cap, "%.0f /s", value);
    }
}

int ps_parse_u64(const char *s, uint64_t *out) {
    char *end = NULL;
    unsigned long long v;

    if (!s || !*s) {
        return -1;
    }
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || *end != '\0') {
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

int ps_parse_u32(const char *s, uint32_t *out) {
    uint64_t v;
    if (ps_parse_u64(s, &v) != 0 || v > UINT32_MAX) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

size_t ps_appendf(char *buf, size_t cap, size_t off, const char *fmt, ...) {
    va_list ap;
    int n;

    if (off >= cap) {
        return off;
    }
    va_start(ap, fmt);
    n = vsnprintf(buf + off, cap - off, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return off;
    }
    return off + (size_t)n;
}
