/*
 * poc_msg_parse.c — Parse incoming server messages
 *
 * Dispatches by command type byte at payload[1].
 * Payload layout: [session_id] [cmd_type] [cmd_data...]
 */

#include "poc_internal.h"
#include <string.h>
#include <stdio.h>

static void handle_challenge(poc_ctx_t *ctx, const uint8_t *data, int len);
static void handle_user_data(poc_ctx_t *ctx, const uint8_t *data, int len);
static void handle_start_ptt(poc_ctx_t *ctx, const uint8_t *data, int len);
static void handle_end_ptt(poc_ctx_t *ctx, const uint8_t *data, int len);
static void handle_response(poc_ctx_t *ctx, const uint8_t *data, int len);
static void handle_force_exit(poc_ctx_t *ctx, const uint8_t *data, int len);
static void handle_group_notify(poc_ctx_t *ctx, uint8_t cmd, const uint8_t *data, int len);
static void handle_ext_data(poc_ctx_t *ctx, const uint8_t *data, int len);

int poc_parse_message(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    if (len < 2) {
        poc_log("parse: message too short (%d bytes)", len);
        return POC_ERR;
    }

    uint8_t session = data[0];
    uint8_t cmd = data[1];
    const uint8_t *payload = data + 2;
    int plen = len - 2;

    poc_log("parse: session=%02x cmd=%02x len=%d", session, cmd, plen);

    ctx->last_activity = poc_mono_ms();

    switch (cmd) {
    case CMD_CHALLENGE:
        handle_challenge(ctx, payload, plen);
        break;

    case CMD_LOGIN:   /* 0x01 — server response/result */
        handle_response(ctx, payload, plen);
        break;

    case CMD_NOTIFY_USER_DATA:
        handle_user_data(ctx, payload, plen);
        break;

    case CMD_START_PTT:
    case CMD_START_PTT_ALT:
    case CMD_NOTIFY_START_PTT:
        handle_start_ptt(ctx, payload, plen);
        break;

    case CMD_END_PTT:
    case CMD_END_PTT_ALT:
    case CMD_NOTIFY_END_PTT:
        handle_end_ptt(ctx, payload, plen);
        break;

    case CMD_FORCE_EXIT:
        handle_force_exit(ctx, payload, plen);
        break;

    case CMD_HEARTBEAT:
        poc_log("parse: heartbeat ack");
        break;

    case CMD_NOTIFY_ENTER_GROUP:
    case CMD_NOTIFY_ADD_GROUP:
    case CMD_NOTIFY_DEL_GROUP:
    case CMD_NOTIFY_GRP_ADD_USER:
    case CMD_NOTIFY_GRP_DEL_USER:
    case CMD_NOTIFY_GRP_MOD_NAME:
        handle_group_notify(ctx, cmd, payload, plen);
        break;

    case CMD_NOTIFY_MOD_PRIV:
        if (plen >= 4) {
            ctx->privilege = poc_read32(payload);
            poc_log("parse: privilege updated to 0x%08x", ctx->privilege);
        }
        break;

    /* ── Phase 1: user status + group state ── */

    case CMD_NOTIFY_MOD_STATUS:
        if (plen >= 5) {
            uint32_t uid = poc_read32(payload);
            int status = payload[4];
            poc_log("user_status: user=%u status=%d", uid, status);
            poc_event_t evt = { .type = POC_EVT_USER_STATUS,
                                .user_status = { .user_id = uid, .status = status }};
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_MOD_NAME:
        if (plen >= 5) {
            uint32_t uid = poc_read32(payload);
            const char *name = (const char *)(payload + 4);
            poc_log("mod_name: user=%u name=%.*s", uid, plen - 4, name);
            /* fire groups_updated so the caller can re-query */
            poc_event_t evt = { .type = POC_EVT_GROUPS_UPDATED };
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_MOD_DEF_GRP:
        if (plen >= 8) {
            uint32_t uid = poc_read32(payload);
            uint32_t gid = poc_read32(payload + 4);
            poc_log("mod_def_group: user=%u group=%u", uid, gid);
        }
        break;

    case CMD_NOTIFY_MOD_PRIORITY:
        if (plen >= 5) {
            uint32_t uid = poc_read32(payload);
            int prio = payload[4];
            poc_log("mod_priority: user=%u priority=%d", uid, prio);
        }
        break;

    case CMD_NOTIFY_REMOVE_USER:
        if (plen >= 4) {
            uint32_t uid = poc_read32(payload);
            poc_log("remove_user: user=%u", uid);
            poc_event_t evt = { .type = POC_EVT_USER_REMOVED,
                                .user_removed = { .user_id = uid }};
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_GRP_MOD_MSTR:
        if (plen >= 8) {
            uint32_t gid = poc_read32(payload);
            uint32_t master = poc_read32(payload + 4);
            poc_log("grp_mod_master: group=%u new_master=%u", gid, master);
        }
        break;

    case CMD_NOTIFY_PKG_ACK:
        poc_log("pkg_ack: len=%d", plen);
        break;

    /* ── Phase 2: temp groups + dispatch ── */

    case CMD_NOTIFY_INVITE_TMP:
        if (plen >= 8) {
            uint32_t gid = poc_read32(payload);
            uint32_t inviter = poc_read32(payload + 4);
            poc_log("tmp_group_invite: group=%u inviter=%u", gid, inviter);
            poc_event_t evt = { .type = POC_EVT_TMP_GROUP_INVITE,
                                .tmp_group_invite = { .group_id = gid, .inviter_id = inviter }};
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_ENTER_TMP:
        if (plen >= 4) {
            uint32_t gid = poc_read32(payload);
            poc_log("tmp_group_enter: group=%u", gid);
            ctx->active_group_id = gid;
            poc_event_t evt = { .type = POC_EVT_GROUPS_UPDATED };
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_LEAVE_TMP:
        poc_log("tmp_group_leave");
        ctx->active_group_id = 0;
        break;

    case CMD_NOTIFY_REJECT_TMP:
        poc_log("tmp_group_rejected");
        break;

    case CMD_PULL_TO_GROUP:
        if (plen >= 4) {
            uint32_t gid = poc_read32(payload);
            poc_log("pull_to_group: group=%u", gid);
            ctx->active_group_id = gid;
            poc_event_t evt = { .type = POC_EVT_PULL_TO_GROUP,
                                .pull_to_group = { .group_id = gid }};
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    /* ── Phase 3: voice messages ── */

    case CMD_NOTE_INCOME:
    case CMD_VOICE_INCOME:
    case CMD_VOICE_MESSAGE: {
        if (plen >= 4) {
            uint32_t from_id = poc_read32(payload);
            uint64_t note_id = (plen >= 12) ? ((uint64_t)poc_read32(payload + 4) << 32 | poc_read32(payload + 8)) : 0;
            const char *desc = (plen > 12) ? (const char *)(payload + 12) : "";
            poc_log("voice_message: from=%u note=%llu cmd=%02x", from_id, (unsigned long long)note_id, cmd);
            poc_event_t evt = { .type = POC_EVT_VOICE_MESSAGE };
            evt.voice_message.from_id = from_id;
            evt.voice_message.note_id = note_id;
            snprintf(evt.voice_message.desc, sizeof(evt.voice_message.desc), "%s", desc);
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;
    }

    case CMD_NOTIFY_EXT_DATA:
        handle_ext_data(ctx, payload, plen);
        break;

    case CMD_RECV_CONTENT:
    case CMD_RECV_MCAST:
        poc_log("parse: content cmd=%02x len=%d (ignored on TCP)", cmd, plen);
        break;

    default:
        poc_log("parse: unhandled cmd=%02x len=%d", cmd, plen);
        /* Hex dump first 32 bytes for debugging */
        {
            char hex[97];
            int dumplen = plen < 32 ? plen : 32;
            for (int i = 0; i < dumplen; i++)
                sprintf(hex + i * 3, "%02x ", payload[i]);
            hex[dumplen * 3] = '\0';
            poc_log("  data: %s", hex);
        }
        break;
    }

    return POC_OK;
}

/*
 * Challenge (cmd 0x07):
 *   [0-3]   UserID (big-endian)
 *   [4-7]   ChallengeNonce (big-endian)
 *   [8]     PrivilegeEx
 *   [9-10]  EncryptKeyType (big-endian)
 *   [11]    GPSUploadFlag
 *   [12..]  GPS strings, XOR creds, version, privilege
 */
static void handle_challenge(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    if (len < 4) {
        poc_log("challenge: too short (%d)", len);
        return;
    }

    ctx->user_id = poc_read32(data);
    poc_log("challenge: user_id=%u", ctx->user_id);

    if (len >= 8) {
        ctx->challenge_nonce = poc_read32(data + 4);
        poc_log("challenge: nonce=0x%08x", ctx->challenge_nonce);
    }

    if (len >= 11) {
        uint16_t key_type = poc_read16(data + 9);
        poc_log("challenge: key_type=0x%04x priv_ex=0x%02x gps_flag=0x%02x",
                key_type, data[8], data[11]);
    }

    /* Send validate response */
    uint8_t vbuf[64];
    int vlen = poc_build_validate(ctx, vbuf, sizeof(vbuf));
    if (vlen > 0) {
        poc_tcp_send_frame(ctx, vbuf, vlen);
        atomic_store(&ctx->login_state, LOGIN_SENT_VALIDATE);
        ctx->login_sent_at = poc_mono_ms();
        poc_log("challenge: sent validate response");
    }
}

/*
 * Response/Result (cmd 0x01): server ack to our commands.
 * Generic — used after validate, enter_group, start_ptt, etc.
 */
static void handle_response(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    poc_log("response: len=%d", len);

    if (atomic_load(&ctx->login_state) == LOGIN_SENT_VALIDATE) {
        /* This might be a login error — if user_data follows, we're OK */
        poc_log("response: during validate phase");
    }

    if (atomic_load(&ctx->ptt_active)) {
        /* PTT grant/deny comes as a response */
        bool granted = (len >= 1 && data[0] == 0);
        poc_event_t evt = { .type = POC_EVT_PTT_GRANTED,
                            .ptt_granted = { .granted = granted }};
        poc_evt_push(&ctx->evt_queue, &evt);
        if (!granted) {
            atomic_store(&ctx->ptt_active, false);
            poc_log("response: PTT denied");
        }
    }
}

/*
 * UserData (cmd 0x0B): full group/member list after successful login.
 * Signals transition to ONLINE state.
 */
static void handle_user_data(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    poc_log("user_data: received %d bytes — login complete", len);

    atomic_store(&ctx->login_state, LOGIN_ONLINE);
    atomic_store(&ctx->state, POC_STATE_ONLINE);
    ctx->login_retries = 0;

    /* Parse group list: [0-1] count (big-endian), then per group:
     * [4 bytes] group_id, [1 byte] name_len, [N bytes] name */
    if (len >= 2) {
        int group_count = poc_read16(data);
        int off = 2;
        ctx->group_count = 0;

        for (int i = 0; i < group_count && i < MAX_GROUPS && off < len; i++) {
            if (off + 5 > len) break;
            uint32_t gid = poc_read32(data + off); off += 4;
            int nlen = data[off]; off++;
            if (off + nlen > len) break;

            poc_group_t *g = &ctx->groups[ctx->group_count];
            g->id = gid;
            int copy = nlen < 63 ? nlen : 63;
            memcpy(g->name, data + off, copy);
            g->name[copy] = '\0';
            g->user_count = 0;
            g->is_active = false;
            g->is_tmp = false;
            ctx->group_count++;
            off += nlen;

            poc_log("user_data: group %u '%s'", gid, g->name);
        }
        poc_log("user_data: %d groups parsed", ctx->group_count);
    }

    /* Fire state change */
    poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                        .state_change = { .state = POC_STATE_ONLINE }};
    poc_evt_push(&ctx->evt_queue, &evt);

    /* Fire groups updated */
    if (ctx->group_count > 0) {
        poc_event_t gevt = { .type = POC_EVT_GROUPS_UPDATED };
        poc_evt_push(&ctx->evt_queue, &gevt);
    }
}

/*
 * PTT Start notification (cmd 0x5D/0x66):
 *   [0-3]  SpeakerUserID (big-endian)
 *   [4]    Flags byte
 *   [5-6]  Extended flags (if len > 5)
 */
static void handle_start_ptt(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    if (len < 4) return;

    uint32_t speaker_id = poc_read32(data);
    bool anonymous = false;

    if (len > 6) {
        uint16_t ext_flags = poc_read16(data + 5);
        anonymous = ext_flags & 1;
    }

    atomic_store(&ctx->ptt_rx_active, true);
    ctx->ptt_speaker_id = speaker_id;
    snprintf(ctx->ptt_speaker_name, sizeof(ctx->ptt_speaker_name),
             anonymous ? "Anonymous" : "User %u", speaker_id);

    poc_log("ptt_start: speaker=%u %s", speaker_id,
            anonymous ? "(anon)" : "");

    poc_event_t evt = { .type = POC_EVT_PTT_START,
                        .ptt_start = { .speaker_id = speaker_id,
                                       .group_id = ctx->active_group_id }};
    snprintf(evt.ptt_start.name, sizeof(evt.ptt_start.name), "%s",
             ctx->ptt_speaker_name);
    poc_evt_push(&ctx->evt_queue, &evt);
}

/*
 * PTT End notification (cmd 0x5E/0x67):
 *   [0-3]  SpeakerUserID (big-endian)
 */
static void handle_end_ptt(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    if (len < 4) return;

    uint32_t speaker_id = poc_read32(data);
    atomic_store(&ctx->ptt_rx_active, false);

    poc_log("ptt_end: speaker=%u", speaker_id);

    poc_event_t evt = { .type = POC_EVT_PTT_END,
                        .ptt_end = { .speaker_id = speaker_id,
                                     .group_id = ctx->active_group_id }};
    poc_evt_push(&ctx->evt_queue, &evt);
}

static void handle_force_exit(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    poc_log("force_exit: stunned by server");
    atomic_store(&ctx->state, POC_STATE_OFFLINE);
    atomic_store(&ctx->login_state, LOGIN_IDLE);

    poc_event_t evt = { .type = POC_EVT_FORCE_EXIT };
    poc_evt_push(&ctx->evt_queue, &evt);
    poc_event_t sevt = { .type = POC_EVT_STATE_CHANGE,
                         .state_change = { .state = POC_STATE_OFFLINE }};
    poc_evt_push(&ctx->evt_queue, &sevt);
}

static void handle_group_notify(poc_ctx_t *ctx, uint8_t cmd,
                                const uint8_t *data, int len)
{
    poc_log("group_notify: cmd=%02x len=%d", cmd, len);

    if (len < 4) return;
    uint32_t gid = poc_read32(data);

    switch (cmd) {
    case CMD_NOTIFY_ADD_GROUP:
        /* New group added: [gid(4)][name_len(1)][name(N)] */
        if (ctx->group_count < MAX_GROUPS && len >= 5) {
            poc_group_t *g = &ctx->groups[ctx->group_count];
            g->id = gid;
            int nlen = data[4];
            int copy = (nlen < 63 && 5 + nlen <= len) ? nlen : 0;
            if (copy > 0) memcpy(g->name, data + 5, copy);
            g->name[copy] = '\0';
            g->user_count = 0;
            g->is_active = false;
            g->is_tmp = false;
            ctx->group_count++;
            poc_log("group_notify: added group %u '%s'", gid, g->name);
        }
        break;

    case CMD_NOTIFY_DEL_GROUP:
        /* Group removed: [gid(4)] */
        for (int i = 0; i < ctx->group_count; i++) {
            if (ctx->groups[i].id == gid) {
                ctx->groups[i] = ctx->groups[--ctx->group_count];
                poc_log("group_notify: removed group %u", gid);
                break;
            }
        }
        break;

    case CMD_NOTIFY_GRP_MOD_NAME:
        /* Group renamed: [gid(4)][name_len(1)][name(N)] */
        for (int i = 0; i < ctx->group_count; i++) {
            if (ctx->groups[i].id == gid && len >= 5) {
                int nlen = data[4];
                int copy = (nlen < 63 && 5 + nlen <= len) ? nlen : 0;
                if (copy > 0) memcpy(ctx->groups[i].name, data + 5, copy);
                ctx->groups[i].name[copy] = '\0';
                poc_log("group_notify: renamed group %u -> '%s'", gid, ctx->groups[i].name);
                break;
            }
        }
        break;

    case CMD_NOTIFY_ENTER_GROUP:
    case CMD_NOTIFY_GRP_ADD_USER:
        /* User joined group: [gid(4)][user_id(4)] */
        if (len >= 8) {
            uint32_t uid = poc_read32(data + 4);
            poc_log("group_notify: user %u joined group %u", uid, gid);
            for (int i = 0; i < ctx->group_count; i++)
                if (ctx->groups[i].id == gid) ctx->groups[i].user_count++;
        }
        break;

    case CMD_NOTIFY_GRP_DEL_USER:
        /* User left group: [gid(4)][user_id(4)] */
        if (len >= 8) {
            uint32_t uid = poc_read32(data + 4);
            poc_log("group_notify: user %u left group %u", uid, gid);
            for (int i = 0; i < ctx->group_count; i++)
                if (ctx->groups[i].id == gid && ctx->groups[i].user_count > 0)
                    ctx->groups[i].user_count--;
        }
        break;

    default:
        break;
    }

    /* Always fire groups_updated for any group change */
    poc_event_t evt = { .type = POC_EVT_GROUPS_UPDATED };
    poc_evt_push(&ctx->evt_queue, &evt);
}

/*
 * Ext data / text message (cmd 0x43):
 * Server→client format: [0-3] sender_id (big-endian), [4..] text (null-terminated)
 */
static void handle_ext_data(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    if (len < 5) return;

    uint32_t from_id = poc_read32(data);
    const char *text = (const char *)(data + 4);

    /* Ensure null-termination within bounds */
    int text_max = len - 4;
    bool terminated = false;
    for (int i = 0; i < text_max; i++) {
        if (text[i] == '\0') { terminated = true; break; }
    }

    poc_log("message: from user %u: %.*s", from_id,
            terminated ? text_max : text_max, text);

    poc_event_t evt = { .type = POC_EVT_MESSAGE };
    evt.message.from_id = from_id;
    snprintf(evt.message.text, sizeof(evt.message.text), "%.*s",
             text_max, text);
    poc_evt_push(&ctx->evt_queue, &evt);
}
