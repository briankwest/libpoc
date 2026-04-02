/*
 * test_gps.c — Tests for GPS position reporting
 */

#include "poc_internal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

static poc_ctx_t *make_gps_ctx(void)
{
    poc_ctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->user_id = 12345;
    ctx->session_id = 1;
    ctx->gps_interval_ms = 60000;
    return ctx;
}

void test_gps(void)
{
    /* GPS heartbeat build */
    {
        test_begin("gps: heartbeat builds 14 bytes");
        poc_ctx_t *ctx = make_gps_ctx();
        ctx->gps_lat = 37.7749f;
        ctx->gps_lng = -122.4194f;
        uint8_t buf[32];
        int len = poc_build_gps_heartbeat(ctx, buf, sizeof(buf));
        test_assert(len == 14, "should be 14 bytes");
        free(ctx);
    }

    {
        test_begin("gps: heartbeat contains user_id");
        poc_ctx_t *ctx = make_gps_ctx();
        ctx->gps_lat = 0.0f;
        ctx->gps_lng = 0.0f;
        uint8_t buf[32];
        poc_build_gps_heartbeat(ctx, buf, sizeof(buf));
        test_assert(poc_read32(buf + 1) == 12345, "user_id at offset 1");
        free(ctx);
    }

    {
        test_begin("gps: heartbeat cmd is 0x06");
        poc_ctx_t *ctx = make_gps_ctx();
        ctx->gps_lat = 51.5074f;
        ctx->gps_lng = -0.1278f;
        uint8_t buf[32];
        poc_build_gps_heartbeat(ctx, buf, sizeof(buf));
        test_assert(buf[5] == CMD_HEARTBEAT, "cmd = heartbeat");
        free(ctx);
    }

    {
        test_begin("gps: lat/lng packed as floats at offset 6");
        poc_ctx_t *ctx = make_gps_ctx();
        ctx->gps_lat = 1.0f;
        ctx->gps_lng = 2.0f;
        uint8_t buf[32];
        poc_build_gps_heartbeat(ctx, buf, sizeof(buf));

        union { float f; uint32_t u; } lat, lng;
        lat.u = poc_read32(buf + 6);
        lng.u = poc_read32(buf + 10);
        test_assert(fabsf(lat.f - 1.0f) < 0.001f && fabsf(lng.f - 2.0f) < 0.001f,
                    "floats should roundtrip");
        free(ctx);
    }

    /* APRS format */
    {
        test_begin("gps: APRS format builds valid string");
        poc_ctx_t *ctx = make_gps_ctx();
        ctx->gps_lat = 37.7749f;
        ctx->gps_lng = -122.4194f;
        char aprs[128];
        int len = poc_build_gps_aprs(ctx, aprs, sizeof(aprs));
        test_assert(len > 0, "should produce output");
        /* Should contain N and W for SF coordinates */
        test_assert(strchr(aprs, 'N') != NULL, "should have N");
        test_assert(strchr(aprs, 'W') != NULL, "should have W");
        free(ctx);
    }

    /* GPS update */
    {
        test_begin("gps: update sets coordinates");
        poc_ctx_t *ctx = make_gps_ctx();
        poc_gps_update(ctx, 48.8566f, 2.3522f);
        test_assert(ctx->gps_valid, "should be valid");
        test_assert(ctx->gps_updated, "should be updated");
        test_assert(fabsf(ctx->gps_lat - 48.8566f) < 0.001f, "lat");
        test_assert(fabsf(ctx->gps_lng - 2.3522f) < 0.001f, "lng");
        free(ctx);
    }

    /* Buffer too small */
    {
        test_begin("gps: heartbeat rejects small buffer");
        poc_ctx_t *ctx = make_gps_ctx();
        uint8_t buf[8];
        int len = poc_build_gps_heartbeat(ctx, buf, sizeof(buf));
        test_assert(len == POC_ERR, "should fail");
        free(ctx);
    }
}
