/* util.h - small shared helpers. */
#ifndef PS_UTIL_H
#define PS_UTIL_H

#include <stddef.h>
#include <stdint.h>

void ps_set_prog_name(const char *name);
const char *ps_prog_name(void);

void *ps_xmalloc(size_t n);
void *ps_xrealloc(void *p, size_t n);
char *ps_strdup(const char *s);

/* Copy at most cap-1 bytes and always NUL-terminate. Returns strlen(src). */
size_t ps_strlcpy(char *dst, const char *src, size_t cap);

uint64_t ps_now_us(void);
void ps_sleep_ms(unsigned ms);

/* "12.3 MB" style rendering. */
void ps_fmt_bytes(char *out, size_t cap, uint64_t bytes);
/* "1.2 Mpps" / "835 kbps" style rendering. */
void ps_fmt_rate(char *out, size_t cap, double value);

/* Strict unsigned parse; returns 0 on success. */
int ps_parse_u64(const char *s, uint64_t *out);
int ps_parse_u32(const char *s, uint32_t *out);

/* Print a warning and return how many bytes were written (may truncate). */
size_t ps_appendf(char *buf, size_t cap, size_t off, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 4, 5)))
#endif
    ;

#endif /* PS_UTIL_H */
