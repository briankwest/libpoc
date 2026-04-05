/*
 * test_tcp_frame.c — Tests for MS-frame TCP layer
 */

#include "poc_internal.h"
#include <string.h>
#include <stdlib.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

/* Test helper: build an MS frame in a buffer */
static int build_ms_frame(uint8_t *buf, const uint8_t *payload, uint16_t len)
{
    buf[0] = MS_MAGIC_0;
    buf[1] = MS_MAGIC_1;
    poc_write16(buf + 2, len);
    memcpy(buf + MS_HDR_LEN, payload, len);
    return MS_HDR_LEN + len;
}

/* Override poc_parse_message for testing */
int __real_poc_parse_message(poc_ctx_t *ctx, const uint8_t *data, int len);

void test_tcp_frame(void)
{
    /* MS frame constants */
    {
        test_begin("MS magic bytes are 'M' 'S'");
        test_assert(MS_MAGIC_0 == 0x4D && MS_MAGIC_1 == 0x53, "M=0x4D S=0x53");
    }

    {
        test_begin("MS header length is 4");
        test_assert(MS_HDR_LEN == 4, "header is 4 bytes");
    }

    /* Build frame manually */
    {
        test_begin("build MS frame with 6-byte payload");
        uint8_t payload[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        uint8_t frame[64];
        int flen = build_ms_frame(frame, payload, 6);

        test_assert(flen == 10, "total frame should be 10 bytes");
    }

    /* Verify frame header */
    {
        test_begin("frame header magic and length");
        uint8_t payload[] = {0xAA, 0xBB};
        uint8_t frame[64];
        build_ms_frame(frame, payload, 2);

        test_assert(frame[0] == 'M' && frame[1] == 'S', "magic");
    }

    {
        test_begin("frame length field is big-endian");
        uint8_t payload[256];
        memset(payload, 0, 256);
        uint8_t frame[512];
        build_ms_frame(frame, payload, 256);

        test_assert(frame[2] == 0x01 && frame[3] == 0x00, "256 = 0x0100 big-endian");
    }

    /* Verify payload follows header */
    {
        test_begin("payload follows header at offset 4");
        uint8_t payload[] = {0xDE, 0xAD};
        uint8_t frame[64];
        build_ms_frame(frame, payload, 2);

        test_assert(frame[4] == 0xDE && frame[5] == 0xAD, "payload intact");
    }

    /* poc_tcp_send_frame builds correct frame */
    {
        test_begin("tcp_send_frame returns error on closed socket");
        poc_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.tcp_fd = -1;
        int rc = poc_tcp_send_frame(&ctx, (uint8_t *)"hi", 2);
        test_assert(rc == POC_ERR_NETWORK, "should fail with no socket");
    }

    /* Empty payload frame */
    {
        test_begin("zero-length payload frame");
        uint8_t frame[64];
        int flen = build_ms_frame(frame, (uint8_t *)"", 0);
        test_assert(flen == 4, "header only");
        test_assert(frame[2] == 0 && frame[3] == 0, "length = 0");
    }

    /* Max payload length encoding */
    {
        test_begin("max payload length 65535 encodes correctly");
        uint8_t hdr[4];
        hdr[0] = MS_MAGIC_0;
        hdr[1] = MS_MAGIC_1;
        poc_write16(hdr + 2, 65535);
        test_assert(hdr[2] == 0xFF && hdr[3] == 0xFF, "0xFFFF");
    }
}
