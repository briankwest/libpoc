/*
 * test_msg_parse.c — Tests for message parser dispatch
 */

#include "poc_internal.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
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
        int sv[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        ctx->tcp_fd = sv[0];  /* writable socket for validate send */
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
        close(sv[0]); close(sv[1]);
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

    /* Message (ext data) handler */
    {
        test_begin("parse: ext_data fires message event");
        poc_ctx_t *ctx = make_ctx();
        ctx->state = POC_STATE_ONLINE;
        poc_evt_init(&ctx->evt_queue);

        /* Server→client format: [session][cmd=0x43][sender_id(4)][text] */
        uint8_t msg[32];
        msg[0] = 0x01;
        msg[1] = CMD_NOTIFY_EXT_DATA;
        poc_write32(msg + 2, 42); /* from user 42 */
        memcpy(msg + 6, "hello", 6); /* including null */

        poc_parse_message(ctx, msg, 12);

        /* Check event queue has a message event */
        poc_event_t evt;
        int found = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt)) {
            if (evt.type == POC_EVT_MESSAGE) {
                found = 1;
                test_assert(evt.message.from_id == 42, "from_id should be 42");
                test_assert(strcmp(evt.message.text, "hello") == 0, "text should match");
            }
        }
        test_assert(found, "should have message event");
        free(ctx);
    }

    /* UserData parses groups */
    {
        test_begin("parse: user_data parses group list");
        poc_ctx_t *ctx = make_ctx();
        ctx->login_state = LOGIN_SENT_VALIDATE;
        poc_evt_init(&ctx->evt_queue);

        /* Build a minimal user_data: [session][cmd=0x0B][count(2)][gid(4)][nlen(1)][name] */
        uint8_t msg[64];
        int off = 0;
        msg[off++] = 0x01;
        msg[off++] = CMD_NOTIFY_USER_DATA;
        poc_write16(msg + off, 2); off += 2; /* 2 groups */
        /* Group 100 "Dispatch" */
        poc_write32(msg + off, 100); off += 4;
        msg[off++] = 8;
        memcpy(msg + off, "Dispatch", 8); off += 8;
        /* Group 200 "Field" */
        poc_write32(msg + off, 200); off += 4;
        msg[off++] = 5;
        memcpy(msg + off, "Field", 5); off += 5;

        poc_parse_message(ctx, msg, off);

        test_assert(ctx->state == POC_STATE_ONLINE, "should be ONLINE");
        test_assert(ctx->group_count == 2, "should have 2 groups");
        test_assert(ctx->groups[0].id == 100, "group 0 id");
        test_assert(strcmp(ctx->groups[0].name, "Dispatch") == 0, "group 0 name");
        test_assert(ctx->groups[1].id == 200, "group 1 id");
        test_assert(strcmp(ctx->groups[1].name, "Field") == 0, "group 1 name");
        free(ctx);
    }

    /* ── Phase 1: user status handlers ── */

    {
        test_begin("parse: mod_status fires user_status event");
        poc_ctx_t *ctx = make_ctx();
        poc_evt_init(&ctx->evt_queue);
        uint8_t msg[8];
        msg[0] = 0x01; msg[1] = 0x25; /* CMD_NOTIFY_MOD_STATUS */
        poc_write32(msg + 2, 42);
        msg[6] = 1; /* online */
        poc_parse_message(ctx, msg, 7);
        poc_event_t evt;
        int found = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt))
            if (evt.type == POC_EVT_USER_STATUS) {
                found = 1;
                test_assert(evt.user_status.user_id == 42, "user_id=42");
                test_assert(evt.user_status.status == 1, "status=online");
            }
        test_assert(found, "should have user_status event");
        free(ctx);
    }

    {
        test_begin("parse: remove_user fires user_removed event");
        poc_ctx_t *ctx = make_ctx();
        poc_evt_init(&ctx->evt_queue);
        uint8_t msg[8];
        msg[0] = 0x01; msg[1] = 0x2B; /* CMD_NOTIFY_REMOVE_USER */
        poc_write32(msg + 2, 99);
        poc_parse_message(ctx, msg, 6);
        poc_event_t evt;
        int found = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt))
            if (evt.type == POC_EVT_USER_REMOVED) {
                found = 1;
                test_assert(evt.user_removed.user_id == 99, "user_id=99");
            }
        test_assert(found, "should have user_removed event");
        free(ctx);
    }

    {
        test_begin("parse: mod_name fires groups_updated");
        poc_ctx_t *ctx = make_ctx();
        poc_evt_init(&ctx->evt_queue);
        uint8_t msg[16];
        msg[0] = 0x01; msg[1] = 0x1F; /* CMD_NOTIFY_MOD_NAME */
        poc_write32(msg + 2, 42);
        memcpy(msg + 6, "Alice", 6);
        poc_parse_message(ctx, msg, 12);
        poc_event_t evt;
        int found = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt))
            if (evt.type == POC_EVT_GROUPS_UPDATED) found = 1;
        test_assert(found, "should fire groups_updated");
        free(ctx);
    }

    {
        test_begin("parse: group add/del updates group list");
        poc_ctx_t *ctx = make_ctx();
        poc_evt_init(&ctx->evt_queue);
        ctx->group_count = 0;

        /* Add group 500 "Test" */
        uint8_t add[16];
        add[0] = 0x01; add[1] = 0x33; /* CMD_NOTIFY_ADD_GROUP */
        poc_write32(add + 2, 500);
        add[6] = 4;
        memcpy(add + 7, "Test", 4);
        poc_parse_message(ctx, add, 11);
        test_assert(ctx->group_count == 1, "should have 1 group");
        test_assert(ctx->groups[0].id == 500, "id=500");

        /* Delete group 500 */
        uint8_t del[8];
        del[0] = 0x01; del[1] = 0x35; /* CMD_NOTIFY_DEL_GROUP */
        poc_write32(del + 2, 500);
        poc_parse_message(ctx, del, 6);
        test_assert(ctx->group_count == 0, "should have 0 groups");
        free(ctx);
    }

    {
        test_begin("parse: pkg_ack doesn't crash");
        poc_ctx_t *ctx = make_ctx();
        uint8_t msg[4];
        msg[0] = 0x01; msg[1] = 0x1D; /* CMD_NOTIFY_PKG_ACK */
        int rc = poc_parse_message(ctx, msg, 2);
        test_assert(rc == POC_OK, "should succeed");
        free(ctx);
    }

    /* ── Phase 2: temp group + pull ── */

    {
        test_begin("parse: tmp_group_invite fires event");
        poc_ctx_t *ctx = make_ctx();
        poc_evt_init(&ctx->evt_queue);
        uint8_t msg[12];
        msg[0] = 0x01; msg[1] = 0x13; /* CMD_NOTIFY_INVITE_TMP */
        poc_write32(msg + 2, 999); /* group_id */
        poc_write32(msg + 6, 42);  /* inviter_id */
        poc_parse_message(ctx, msg, 10);
        poc_event_t evt;
        int found = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt))
            if (evt.type == POC_EVT_TMP_GROUP_INVITE) {
                found = 1;
                test_assert(evt.tmp_group_invite.group_id == 999, "gid=999");
                test_assert(evt.tmp_group_invite.inviter_id == 42, "inviter=42");
            }
        test_assert(found, "should have invite event");
        free(ctx);
    }

    {
        test_begin("parse: pull_to_group sets active group");
        poc_ctx_t *ctx = make_ctx();
        poc_evt_init(&ctx->evt_queue);
        ctx->active_group_id = 0;
        uint8_t msg[8];
        msg[0] = 0x01; msg[1] = 0x4D; /* CMD_PULL_TO_GROUP */
        poc_write32(msg + 2, 200);
        poc_parse_message(ctx, msg, 6);
        test_assert(ctx->active_group_id == 200, "active_group=200");
        poc_event_t evt;
        int found = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt))
            if (evt.type == POC_EVT_PULL_TO_GROUP) found = 1;
        test_assert(found, "should have pull event");
        free(ctx);
    }

    /* ── Phase 3: voice messages ── */

    {
        test_begin("parse: voice_income fires event");
        poc_ctx_t *ctx = make_ctx();
        poc_evt_init(&ctx->evt_queue);
        uint8_t msg[16];
        msg[0] = 0x01; msg[1] = 0x72; /* CMD_VOICE_INCOME */
        poc_write32(msg + 2, 77); /* from_id */
        poc_parse_message(ctx, msg, 6);
        poc_event_t evt;
        int found = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt))
            if (evt.type == POC_EVT_VOICE_MESSAGE) {
                found = 1;
                test_assert(evt.voice_message.from_id == 77, "from=77");
            }
        test_assert(found, "should have voice_message event");
        free(ctx);
    }

    /* ── Auth failure handling ── */

    {
        test_begin("parse: response with error during validate fires login_error");
        poc_ctx_t *ctx = make_ctx();
        ctx->login_state = LOGIN_SENT_VALIDATE;
        poc_evt_init(&ctx->evt_queue);

        /* Server sends: [session=0x01][cmd=0x01][error_code=0x01] */
        uint8_t msg[4];
        msg[0] = 0x01;
        msg[1] = CMD_LOGIN;  /* 0x01 = response */
        msg[2] = 0x01;       /* non-zero = auth failed */

        poc_parse_message(ctx, msg, 3);

        test_assert(ctx->login_state == LOGIN_FAILED, "should be LOGIN_FAILED");
        test_assert(ctx->state == POC_STATE_OFFLINE, "should be OFFLINE");

        poc_event_t evt;
        int found_err = 0, found_offline = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt)) {
            if (evt.type == POC_EVT_LOGIN_ERROR) {
                found_err = 1;
                test_assert(evt.login_error.code == POC_ERR_AUTH, "code=AUTH");
            }
            if (evt.type == POC_EVT_STATE_CHANGE && evt.state_change.state == POC_STATE_OFFLINE)
                found_offline = 1;
        }
        test_assert(found_err, "should have login_error event");
        test_assert(found_offline, "should have offline event");
        free(ctx);
    }

    {
        test_begin("parse: response with success during validate doesn't error");
        poc_ctx_t *ctx = make_ctx();
        ctx->login_state = LOGIN_SENT_VALIDATE;
        poc_evt_init(&ctx->evt_queue);

        uint8_t msg[4];
        msg[0] = 0x01;
        msg[1] = CMD_LOGIN;
        msg[2] = 0x00;  /* success */

        poc_parse_message(ctx, msg, 3);

        /* Should NOT transition to failed */
        test_assert(ctx->login_state == LOGIN_SENT_VALIDATE, "still in validate");

        poc_event_t evt;
        int found_err = 0;
        while (poc_evt_pop(&ctx->evt_queue, &evt))
            if (evt.type == POC_EVT_LOGIN_ERROR) found_err = 1;
        test_assert(!found_err, "should NOT have error event");
        free(ctx);
    }
}
