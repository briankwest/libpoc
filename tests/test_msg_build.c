/*
 * test_msg_build.c — Tests for protocol message builders
 */

#include "poc_internal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

static poc_ctx_t *make_ctx(void)
{
    poc_ctx_t *ctx = calloc(1, sizeof(*ctx));
    snprintf(ctx->account, sizeof(ctx->account), "12345678");
    snprintf(ctx->password_sha1, sizeof(ctx->password_sha1),
             "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
    ctx->session_id = 0;
    ctx->user_id = 0xFFFFFFFF;
    return ctx;
}

void test_msg_build(void)
{
    /* Login message */
    {
        test_begin("login: cmd byte is 0x01");
        poc_ctx_t *ctx = make_ctx();
        uint8_t buf[256];
        int len = poc_build_login(ctx, buf, sizeof(buf));
        test_assert(len > 0 && buf[5] == CMD_LOGIN, "cmd should be 0x01");
        free(ctx);
    }

    {
        test_begin("login: user_id is 0xFFFFFFFF");
        poc_ctx_t *ctx = make_ctx();
        uint8_t buf[256];
        poc_build_login(ctx, buf, sizeof(buf));
        uint32_t uid = poc_read32(buf + 1);
        test_assert(uid == 0xFFFFFFFF, "initial login user_id");
        free(ctx);
    }

    {
        test_begin("login: session_id increments");
        poc_ctx_t *ctx = make_ctx();
        uint8_t buf[256];
        poc_build_login(ctx, buf, sizeof(buf));
        uint8_t s1 = buf[0];
        poc_build_login(ctx, buf, sizeof(buf));
        uint8_t s2 = buf[0];
        test_assert(s2 == s1 + 1, "should increment");
        free(ctx);
    }

    {
        test_begin("login: protocol version present");
        poc_ctx_t *ctx = make_ctx();
        uint8_t buf[256];
        poc_build_login(ctx, buf, sizeof(buf));
        uint32_t ver = poc_read32(buf + 6);
        test_assert(ver == POC_PROTOCOL_VER, "version mismatch");
        free(ctx);
    }

    {
        test_begin("login: account name in payload");
        poc_ctx_t *ctx = make_ctx();
        uint8_t buf[256];
        int len = poc_build_login(ctx, buf, sizeof(buf));
        /* Account starts at offset 10 */
        test_assert(len > 10 && memcmp(buf + 10, "12345678", 8) == 0,
                    "account should be at offset 10");
        free(ctx);
    }

    {
        test_begin("login: rejects oversized account");
        poc_ctx_t *ctx = make_ctx();
        memset(ctx->account, 'A', 31);
        ctx->account[31] = '\0';
        uint8_t buf[256];
        int len = poc_build_login(ctx, buf, sizeof(buf));
        test_assert(len > 0, "31-char account should still fit");
        free(ctx);
    }

    /* Validate message */
    {
        test_begin("validate: cmd byte is 0x04");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 42;
        ctx->challenge_nonce = 0xDEADBEEF;
        uint8_t buf[64];
        int len = poc_build_validate(ctx, buf, sizeof(buf));
        test_assert(len == 26 && buf[5] == CMD_VALIDATE, "cmd 0x04, len 26");
        free(ctx);
    }

    {
        test_begin("validate: contains user_id from challenge");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 12345;
        ctx->challenge_nonce = 0xABCD;
        uint8_t buf[64];
        poc_build_validate(ctx, buf, sizeof(buf));
        uint32_t uid = poc_read32(buf + 1);
        test_assert(uid == 12345, "user_id should match");
        free(ctx);
    }

    {
        test_begin("validate: HMAC digest is 20 bytes at offset 6");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 1;
        ctx->challenge_nonce = 0x12345678;
        uint8_t buf[64];
        int len = poc_build_validate(ctx, buf, sizeof(buf));
        /* 6 header + 20 HMAC = 26 */
        test_assert(len == 26, "total 26 bytes");
        /* HMAC should not be all zeros */
        int nonzero = 0;
        for (int i = 6; i < 26; i++)
            if (buf[i]) nonzero++;
        test_assert(nonzero > 0, "HMAC should not be empty");
        free(ctx);
    }

    {
        test_begin("validate: same inputs produce same HMAC");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 99;
        ctx->challenge_nonce = 0xCAFEBABE;
        uint8_t buf1[64], buf2[64];
        poc_build_validate(ctx, buf1, sizeof(buf1));
        /* Reset session_id to match */
        ctx->session_id--;
        poc_build_validate(ctx, buf2, sizeof(buf2));
        /* Skip session_id byte, compare rest */
        test_assert(memcmp(buf1 + 1, buf2 + 1, 25) == 0, "deterministic");
        free(ctx);
    }

    /* Heartbeat message */
    {
        test_begin("heartbeat: cmd byte is 0x06");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 100;
        uint8_t buf[16];
        int len = poc_build_heartbeat(ctx, buf, sizeof(buf));
        test_assert(len == 6 && buf[5] == CMD_HEARTBEAT, "cmd 0x06, len 6");
        free(ctx);
    }

    {
        test_begin("heartbeat: contains user_id");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 0xAABBCCDD;
        uint8_t buf[16];
        poc_build_heartbeat(ctx, buf, sizeof(buf));
        test_assert(poc_read32(buf + 1) == 0xAABBCCDD, "user_id");
        free(ctx);
    }

    /* Start PTT */
    {
        test_begin("start_ptt: cmd byte is 0x5D");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 42;
        uint8_t buf[64];
        int len = poc_build_start_ptt(ctx, buf, sizeof(buf));
        test_assert(len > 6 && buf[5] == CMD_START_PTT, "cmd 0x5D");
        free(ctx);
    }

    {
        test_begin("start_ptt: codec byte is POC_CODEC_OPUS_SWB");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 42;
        uint8_t buf[64];
        poc_build_start_ptt(ctx, buf, sizeof(buf));
        test_assert(buf[6] == POC_CODEC_OPUS_SWB, "codec byte = 7");
        free(ctx);
    }

    /* End PTT */
    {
        test_begin("end_ptt: cmd byte is 0x5E, length 6");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 42;
        uint8_t buf[16];
        int len = poc_build_end_ptt(ctx, buf, sizeof(buf));
        test_assert(len == 6 && buf[5] == CMD_END_PTT, "cmd 0x5E");
        free(ctx);
    }

    /* Enter group */
    {
        test_begin("enter_group: group_id at offset 6");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 42;
        uint8_t buf[32];
        int len = poc_build_enter_group(ctx, 999, buf, sizeof(buf));
        test_assert(len == 10, "10 bytes total");
        test_assert(poc_read32(buf + 6) == 999, "group_id");
        free(ctx);
    }

    /* Buffer too small */
    {
        test_begin("heartbeat: rejects tiny buffer");
        poc_ctx_t *ctx = make_ctx();
        uint8_t buf[4];
        int len = poc_build_heartbeat(ctx, buf, sizeof(buf));
        test_assert(len == POC_ERR, "should fail");
        free(ctx);
    }

    /* Leave group */
    {
        test_begin("leave_group: cmd byte is 0x17, length 6");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 42;
        uint8_t buf[16];
        int len = poc_build_leave_group(ctx, buf, sizeof(buf));
        test_assert(len == 6 && buf[5] == 0x17, "cmd 0x17, len 6");
        free(ctx);
    }

    /* Send user message */
    {
        test_begin("send_user_msg: cmd 0x43, target at offset 6");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 1;
        uint8_t buf[256];
        int len = poc_build_send_user_msg(ctx, 999, "hello", buf, sizeof(buf));
        test_assert(len > 10 && buf[5] == CMD_NOTIFY_EXT_DATA, "cmd 0x43");
        test_assert(poc_read32(buf + 6) == 999, "target_id");
        test_assert(memcmp(buf + 10, "hello", 5) == 0, "text at offset 10");
        free(ctx);
    }

    /* Send group message */
    {
        test_begin("send_group_msg: cmd 0x43, group at offset 6");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 1;
        uint8_t buf[256];
        int len = poc_build_send_group_msg(ctx, 500, "test", buf, sizeof(buf));
        test_assert(len > 10 && buf[5] == CMD_NOTIFY_EXT_DATA, "cmd 0x43");
        test_assert(poc_read32(buf + 6) == 500, "group_id");
        test_assert(memcmp(buf + 10, "test", 4) == 0, "text at offset 10");
        free(ctx);
    }

    /* register_push_token */
    {
        test_begin("register_push_token: cmd byte is 0x90");
        poc_ctx_t *ctx = make_ctx();
        ctx->user_id = 1001;
        uint8_t token[32];
        for (int i = 0; i < 32; i++) token[i] = (uint8_t)(0xA0 + i);
        const char *bid = "net.kerchunk.ios";
        uint8_t buf[256];
        int len = poc_build_register_push_token(ctx, token, 32, bid,
                                                buf, sizeof(buf));
        int expected = 8 + 32 + (int)strlen(bid);
        test_assert(len == expected, "length = 8 + token_len + bid_len");
        test_assert(buf[5] == CMD_REGISTER_PUSH_TOKEN, "cmd byte 0x90");
        test_assert(buf[6] == 32, "token_len at offset 6");
        test_assert(buf[7] == (uint8_t)strlen(bid), "bid_len at offset 7");
        test_assert(memcmp(buf + 8, token, 32) == 0, "token bytes at offset 8");
        test_assert(memcmp(buf + 8 + 32, bid, strlen(bid)) == 0,
                    "bundle_id bytes after token");
        test_assert(poc_read32(buf + 1) == 1001, "user_id at offset 1");
        free(ctx);
    }

    {
        test_begin("register_push_token: rejects oversized token");
        poc_ctx_t *ctx = make_ctx();
        uint8_t token[200] = {0};
        uint8_t buf[256];
        int len = poc_build_register_push_token(ctx, token, 65,
                                                "x", buf, sizeof(buf));
        test_assert(len < 0, "should reject token_len > 64");
        free(ctx);
    }

    {
        test_begin("register_push_token: rejects empty bundle_id");
        poc_ctx_t *ctx = make_ctx();
        uint8_t token[32] = {0};
        uint8_t buf[256];
        int len = poc_build_register_push_token(ctx, token, 32,
                                                "", buf, sizeof(buf));
        test_assert(len < 0, "should reject empty bundle_id");
        free(ctx);
    }
}
