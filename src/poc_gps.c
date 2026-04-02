/*
 * poc_gps.c — GPS position reporting
 *
 * Two reporting paths:
 *   1. TCP: GPS heartbeat piggybacked on signaling channel
 *   2. HTTP: POST to GPS server (gps.realptt.com:8080 or custom)
 *
 * GPS heartbeat format (from CMessageBuilder::GPSHeart):
 *   Standard MS-framed message with lat/lng as IEEE 754 floats.
 */

#include "poc_internal.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

/*
 * Build GPS heartbeat message for TCP channel.
 *
 * Layout:
 *   [0]      session_id
 *   [1-4]    user_id (big-endian)
 *   [5]      cmd (heartbeat variant with GPS flag)
 *   [6-9]    latitude (IEEE 754 float, big-endian)
 *   [10-13]  longitude (IEEE 754 float, big-endian)
 */
int poc_build_gps_heartbeat(poc_ctx_t *ctx, uint8_t *buf, int buflen)
{
    if (buflen < 14)
        return POC_ERR;

    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_HEARTBEAT;

    /* Pack lat/lng as big-endian IEEE 754 floats */
    union { float f; uint32_t u; } lat, lng;
    lat.f = ctx->gps_lat;
    lng.f = ctx->gps_lng;
    poc_write32(buf + 6, lat.u);
    poc_write32(buf + 10, lng.u);

    return 14;
}

/*
 * Build APRS-style position string (for APRS-IS forwarding path in server).
 * Format: @DDHHMMz{lat}/{lng}{symbol}
 */
int poc_build_gps_aprs(poc_ctx_t *ctx, char *buf, int buflen)
{
    if (!ctx || buflen < 64)
        return POC_ERR;

    double lat = ctx->gps_lat;
    double lng = ctx->gps_lng;

    /* Convert decimal degrees to APRS DDMM.MM format */
    char ns = lat >= 0 ? 'N' : 'S';
    char ew = lng >= 0 ? 'E' : 'W';
    lat = fabs(lat);
    lng = fabs(lng);

    int lat_deg = (int)lat;
    double lat_min = (lat - lat_deg) * 60.0;
    int lng_deg = (int)lng;
    double lng_min = (lng - lng_deg) * 60.0;

    snprintf(buf, buflen, "%02d%05.2f%c/%03d%05.2f%c>",
             lat_deg, lat_min, ns, lng_deg, lng_min, ew);

    return strlen(buf);
}

/*
 * Set GPS position and optionally send heartbeat.
 * Called from public API poc_set_gps().
 */
int poc_gps_update(poc_ctx_t *ctx, float lat, float lng)
{
    ctx->gps_lat = lat;
    ctx->gps_lng = lng;
    ctx->gps_valid = true;
    ctx->gps_updated = true;

    poc_log("gps: position updated to %.6f, %.6f", lat, lng);
    return POC_OK;
}

/*
 * Called from I/O thread timer to send GPS if due.
 * Interval controlled by server (GetGpsInterval) or default 60s.
 */
void poc_gps_tick(poc_ctx_t *ctx)
{
    if (!ctx->gps_valid || !ctx->gps_updated)
        return;
    if (atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return;

    uint64_t now = poc_mono_ms();
    if (now - ctx->last_gps_send < (uint64_t)ctx->gps_interval_ms)
        return;

    uint8_t buf[32];
    int len = poc_build_gps_heartbeat(ctx, buf, sizeof(buf));
    if (len > 0) {
        poc_tcp_send_frame(ctx, buf, len);
        ctx->last_gps_send = now;
        ctx->gps_updated = false;
        poc_log("gps: sent position heartbeat");
    }
}
