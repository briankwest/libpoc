/*
 * test_msg_parse.c — Tests for message parser dispatch
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
    ctx->state = POC_STATE_CONNECTING;
    ctx->login_state = LOGIN_SENT_LOGIN;
    return ctx;
}

void test_msg_parse(void)
{
    /* Reject short messages */
    {
        test_begin("parse: rejects 0-byte message");
        poc_ctx_t *ctx = make_ctx();
        int rc = poc_parse_message(ctx, NULL, 0);
        test_assert(rc == POC_ERR, "should error");
        free(ctx);
    }

    {
        test_begin("parse: rejects 1-byte message");
        poc_ctx_t *ctx = make_ctx();
        uint8_t data[] = {0x01};
        int rc = poc_parse_message(ctx, data, 1);
        test_assert(rc == POC_ERR, "should error");
        free(ctx);
    }

    /* Challenge triggers validate */
    {
        test_begin("parse: challenge sets user_id");
        poc_ctx_t *ctx = make_ctx();
        ctx->tcp_fd = -1; /* prevent actual send */
        ctx->login_state = LOGIN_SENT_LOGIN;
        snprintf(ctx->password_sha1, sizeof(ctx->password_sha1),
                 "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");

        /* Build a minimal challenge: session + cmd + user_id + nonce */
        uint8_t msg[16];
        msg[0] = 0x01; /* session */
        msg[1] = CMD_CHALLENGE; /* 0x07 */
        poc_write32(msg + 2, 42);       /* user_id */
        poc_write32(msg + 6, 0xBEEF);   /* nonce */

        poc_parse_message(ctx, msg, 10);
        test_assert(ctx->user_id == 42, "user_id from challenge");
        free(ctx);
    }

    {
        test_begin("parse: challenge sets nonce");
        poc_ctx_t *ctx = make_ctx();
        ctx->tcp_fd = -1;
        snprintf(ctx->password_sha1, sizeof(ctx->password_sha1),
                 "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");

        uint8_t msg[16];
        msg[0] = 0x01;
        msg[1] = CMD_CHALLENGE;
        poc_write32(msg + 2, 1);
        poc_write32(msg + 6, 0xDEADCAFE);

        poc_parse_message(ctx, msg, 10);
        test_assert(ctx->challenge_nonce == 0xDEADCAFE, "nonce from challenge");
        free(ctx);
    }

    {
        test_begin("parse: challenge advances login state to SENT_VALIDATE");
        poc_ctx_t *ctx = make_ctx();
        ctx->tcp_fd = -1;
        snprintf(ctx->password_sha1, sizeof(ctx->password_sha1),
                 "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");

        uint8_t msg[16];
        msg[0] = 0x01;
        msg[1] = CMD_CHALLENGE;
        poc_write32(msg + 2, 1);
        poc_write32(msg + 6, 0x1234);

        poc_parse_message(ctx, msg, 10);
        test_assert(ctx->login_state == LOGIN_SENT_VALIDATE,
                    "should advance to SENT_VALIDATE");
        free(ctx);
    }

    /* UserData transitions to ONLINE */
    {
        test_begin("parse: user_data transitions to ONLINE");
        poc_ctx_t *ctx = make_ctx();
        ctx->login_state = LOGIN_SENT_VALIDATE;

        uint8_t msg[8];
        msg[0] = 0x01;
        msg[1] = CMD_NOTIFY_USER_DATA;
        /* Minimal payload - just enough to trigger transition */
        memset(msg + 2, 0, 6);

        poc_parse_message(ctx, msg, 8);
        test_assert(ctx->state == POC_STATE_ONLINE, "should be ONLINE");
        test_assert(ctx->login_state == LOGIN_ONLINE, "login state ONLINE");
        free(ctx);
    }

    /* PTT start notification */
    {
        test_begin("parse: ptt_start sets speaker_id");
        poc_ctx_t *ctx = make_ctx();
        ctx->state = POC_STATE_ONLINE;

        uint8_t msg[16];
        msg[0] = 0x01;
        msg[1] = CMD_START_PTT; /* 0x5D */
        poc_write32(msg + 2, 777);  /* speaker_id */
        msg[6] = 0;                /* flags */

        poc_parse_message(ctx, msg, 7);
        test_assert(ctx->ptt_rx_active, "ptt_rx should be active");
        test_assert(ctx->ptt_speaker_id == 777, "speaker_id");
        free(ctx);
    }

    /* PTT start alternate command */
    {
        test_begin("parse: ptt_start_alt (0x66) also works");
        poc_ctx_t *ctx = make_ctx();
        ctx->state = POC_STATE_ONLINE;

        uint8_t msg[16];
        msg[0] = 0x01;
        msg[1] = CMD_START_PTT_ALT; /* 0x66 */
        poc_write32(msg + 2, 888);
        msg[6] = 0;

        poc_parse_message(ctx, msg, 7);
        test_assert(ctx->ptt_speaker_id == 888, "speaker from alt cmd");
        free(ctx);
    }

    /* PTT end notification */
    {
        test_begin("parse: ptt_end clears rx_active");
        poc_ctx_t *ctx = make_ctx();
        ctx->state = POC_STATE_ONLINE;
        ctx->ptt_rx_active = true;
        ctx->ptt_speaker_id = 777;

        uint8_t msg[16];
        msg[0] = 0x01;
        msg[1] = CMD_END_PTT; /* 0x5E */
        poc_write32(msg + 2, 777);

        poc_parse_message(ctx, msg, 6);
        test_assert(!ctx->ptt_rx_active, "ptt_rx should be cleared");
        free(ctx);
    }

    /* Force exit */
    {
        test_begin("parse: force_exit transitions to OFFLINE");
        poc_ctx_t *ctx = make_ctx();
        ctx->state = POC_STATE_ONLINE;

        uint8_t msg[4];
        msg[0] = 0x01;
        msg[1] = CMD_FORCE_EXIT;

        poc_parse_message(ctx, msg, 2);
        test_assert(ctx->state == POC_STATE_OFFLINE, "should be OFFLINE");
        free(ctx);
    }

    /* Heartbeat doesn't crash */
    {
        test_begin("parse: heartbeat ack accepted");
        poc_ctx_t *ctx = make_ctx();
        uint8_t msg[4];
        msg[0] = 0x01;
        msg[1] = CMD_HEARTBEAT;
        int rc = poc_parse_message(ctx, msg, 2);
        test_assert(rc == POC_OK, "should succeed");
        free(ctx);
    }

    /* Unknown command doesn't crash */
    {
        test_begin("parse: unknown cmd handled gracefully");
        poc_ctx_t *ctx = make_ctx();
        uint8_t msg[8];
        msg[0] = 0x01;
        msg[1] = 0xFE; /* unknown */
        memset(msg + 2, 0xAA, 6);
        int rc = poc_parse_message(ctx, msg, 8);
        test_assert(rc == POC_OK, "should not crash");
        free(ctx);
    }

    /* Privilege update */
    {
        test_begin("parse: privilege update stores value");
        poc_ctx_t *ctx = make_ctx();
        uint8_t msg[8];
        msg[0] = 0x01;
        msg[1] = CMD_NOTIFY_MOD_PRIV;
        poc_write32(msg + 2, 0x0FFF);
        poc_parse_message(ctx, msg, 6);
        test_assert(ctx->privilege == 0x0FFF, "privilege stored");
        free(ctx);
    }
}
