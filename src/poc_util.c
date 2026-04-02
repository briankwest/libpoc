/*
 * poc_util.c — Byte order helpers, timers, logging
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

void poc_log(const char *fmt, ...)
{
    va_list ap;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    fprintf(stderr, "[poc %02d:%02d:%02d.%03ld] ",
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}
