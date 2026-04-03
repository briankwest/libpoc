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

/* ── Human-readable protocol names ─────────────────────────────── */

const char *poc_cmd_name(uint8_t cmd)
{
    switch (cmd) {
    case 0x01: return "login";
    case 0x04: return "validate";
    case 0x06: return "heartbeat";
    case 0x11: return "enter_group";
    case 0x13: return "invite_tmp_group";
    case 0x15: return "enter_tmp_group";
    case 0x17: return "leave_group";
    case 0x19: return "reject_tmp_group";
    case 0x25: return "status_change";
    case 0x2D: return "force_exit";
    case 0x43: return "message";
    case 0x4D: return "pull_to_group";
    case 0x5D: return "start_ptt";
    case 0x5E: return "end_ptt";
    case 0x66: return "start_ptt_alt";
    case 0x67: return "end_ptt_alt";
    case 0x70: return "note_income";
    case 0x72: return "voice_income";
    case 0x73: return "voice_message";
    default:   return "unknown";
    }
}

const char *poc_notify_name(uint8_t cmd)
{
    switch (cmd) {
    case 0x01: return "response";
    case 0x06: return "heartbeat";
    case 0x07: return "challenge";
    case 0x0B: return "user_data";
    case 0x0D: return "ptt_start";
    case 0x0F: return "ptt_end";
    case 0x11: return "enter_group";
    case 0x13: return "invite_tmp_group";
    case 0x15: return "enter_tmp_group";
    case 0x17: return "leave_tmp_group";
    case 0x19: return "reject_tmp_group";
    case 0x1D: return "delivery_ack";
    case 0x1F: return "rename_user";
    case 0x21: return "set_default_group";
    case 0x25: return "user_status";
    case 0x27: return "set_privilege";
    case 0x29: return "set_priority";
    case 0x2B: return "remove_user";
    case 0x2D: return "force_exit";
    case 0x33: return "add_group";
    case 0x35: return "del_group";
    case 0x37: return "rename_group";
    case 0x39: return "set_group_master";
    case 0x3B: return "group_user_joined";
    case 0x3D: return "group_user_left";
    case 0x43: return "text_message";
    case 0x4D: return "pull_to_group";
    case 0x5D: return "ptt_start";
    case 0x5E: return "ptt_end";
    case 0x66: return "ptt_start_alt";
    case 0x67: return "ptt_end_alt";
    case 0x70: return "note_income";
    case 0x72: return "voice_income";
    case 0x73: return "voice_message";
    case 0x80: return "content";
    case 0x84: return "multicast";
    default:   return "unknown";
    }
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
