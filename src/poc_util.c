/*
 * poc_util.c — Byte order helpers, timers, logging with levels and callback
 */

#include "poc_internal.h"
#include <time.h>
#include <stdio.h>
#include <stdarg.h>

uint64_t poc_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint16_t poc_read16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

uint32_t poc_read32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

void poc_write16(uint8_t *p, uint16_t v)
{
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

void poc_write32(uint8_t *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

/* ── Logging with levels and callback ───────────────────────────── */

static poc_log_fn g_log_fn = NULL;
static void      *g_log_ud = NULL;
static int        g_log_level = POC_LOG_DEBUG;

void poc_set_log_callback(poc_log_fn fn, void *userdata)
{
    g_log_fn = fn;
    g_log_ud = userdata;
}

void poc_set_log_level(int level)
{
    g_log_level = level;
}

void poc_log_at(int level, const char *fmt, ...)
{
    if (level > g_log_level)
        return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (g_log_fn) {
        g_log_fn(level, buf, g_log_ud);
        return;
    }

    /* Default: stderr with timestamp and level tag */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    static const char *tags[] = {"ERR", "WRN", "INF", "DBG"};
    const char *tag = (level >= 0 && level <= 3) ? tags[level] : "???";

    fprintf(stderr, "[poc %02d:%02d:%02d.%03ld %s] %s\n",
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000,
            tag, buf);
}

/* Backward compat — poc_log() maps to INFO */
void poc_log(const char *fmt, ...)
{
    if (POC_LOG_INFO > g_log_level)
        return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    poc_log_at(POC_LOG_INFO, "%s", buf);
}
