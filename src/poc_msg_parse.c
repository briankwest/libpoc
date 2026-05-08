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

    (void)data[0]; /* session byte — not used */
    uint8_t cmd = data[1];
    const uint8_t *payload = data + 2;
    int plen = len - 2;

    /* Don't spam heartbeat acks every 30s — everything else is interesting */
    if (cmd != CMD_HEARTBEAT)
        poc_log_at(POC_LOG_DEBUG, "recv: %s (%d bytes)", poc_notify_name(cmd), plen);

    ctx->last_activity = poc_mono_ms();

    /* Lock shared state: groups[], active_group_id, session_id are
     * accessed by both I/O thread (here) and caller thread (public API).
     * Hold the lock for the entire parse dispatch. */
    pthread_mutex_lock(&ctx->sig_mutex);

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
        /* silent — happens every 30s, not interesting */
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
            poc_log_at(POC_LOG_DEBUG, "privilege updated to 0x%08x", ctx->privilege);
        }
        break;

    /* ── Phase 1: user status + group state ── */

    case CMD_NOTIFY_MOD_STATUS:
        if (plen >= 5) {
            uint32_t uid = poc_read32(payload);
            int status = payload[4];
            poc_log("user %u is now %s", uid, status ? "online" : "offline");
            poc_event_t evt = { .type = POC_EVT_USER_STATUS,
                                .user_status = { .user_id = uid, .status = status }};
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_MOD_NAME:
        if (plen >= 5) {
            uint32_t uid = poc_read32(payload);
            const char *name = (const char *)(payload + 4);
            poc_log_at(POC_LOG_DEBUG, "user %u renamed to '%.*s'", uid, plen - 4, name);
            /* fire groups_updated so the caller can re-query */
            poc_event_t evt = { .type = POC_EVT_GROUPS_UPDATED };
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_MOD_DEF_GRP:
        if (plen >= 8) {
            uint32_t uid = poc_read32(payload);
            uint32_t gid = poc_read32(payload + 4);
            poc_log_at(POC_LOG_DEBUG, "user %u default group set to %u", uid, gid);
        }
        break;

    case CMD_NOTIFY_MOD_PRIORITY:
        if (plen >= 5) {
            uint32_t uid = poc_read32(payload);
            int prio = payload[4];
            poc_log_at(POC_LOG_DEBUG, "user %u priority set to %d", uid, prio);
        }
        break;

    case CMD_NOTIFY_REMOVE_USER:
        if (plen >= 4) {
            uint32_t uid = poc_read32(payload);
            poc_log("user %u removed from server", uid);
            poc_event_t evt = { .type = POC_EVT_USER_REMOVED,
                                .user_removed = { .user_id = uid }};
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_GRP_MOD_MSTR:
        if (plen >= 8) {
            uint32_t gid = poc_read32(payload);
            uint32_t master = poc_read32(payload + 4);
            poc_log_at(POC_LOG_DEBUG, "group %u: master changed to user %u", gid, master);
        }
        break;

    case CMD_NOTIFY_PKG_ACK:
        poc_log_at(POC_LOG_DEBUG, "message: delivered");
        {
            poc_event_t devt = { .type = POC_EVT_MESSAGE };
            devt.message.from_id = 0;
            snprintf(devt.message.text, sizeof(devt.message.text), "[delivered]");
            poc_evt_push(&ctx->evt_queue, &devt);
        }
        break;

    /* ── Phase 2: temp groups + dispatch ── */

    case CMD_NOTIFY_INVITE_TMP:
        if (plen >= 8) {
            uint32_t gid = poc_read32(payload);
            uint32_t inviter = poc_read32(payload + 4);
            poc_log("temp group invite: user %u invited you to group %u", inviter, gid);
            poc_event_t evt = { .type = POC_EVT_TMP_GROUP_INVITE,
                                .tmp_group_invite = { .group_id = gid, .inviter_id = inviter }};
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_ENTER_TMP:
        if (plen >= 4) {
            uint32_t gid = poc_read32(payload);
            poc_log("joined temp group %u", gid);
            ctx->active_group_id = gid;
            poc_event_t evt = { .type = POC_EVT_GROUPS_UPDATED };
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        break;

    case CMD_NOTIFY_LEAVE_TMP:
        poc_log("left temp group");
        ctx->active_group_id = 0;
        break;

    case CMD_NOTIFY_REJECT_TMP:
        poc_log("temp group invite rejected");
        break;

    case CMD_PULL_TO_GROUP:
        if (plen >= 4) {
            uint32_t gid = poc_read32(payload);
            poc_log("pulled into group %u by server", gid);
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
            poc_log("voice message from user %u (id=%llu)", from_id, (unsigned long long)note_id);
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
        poc_log_at(POC_LOG_DEBUG, "recv: %s (%d bytes, TCP — ignored)", poc_notify_name(cmd), plen);
        break;

    default:
        poc_log_at(POC_LOG_DEBUG, "recv: unhandled %s (0x%02x, %d bytes)", poc_notify_name(cmd), cmd, plen);
        break;
    }

    pthread_mutex_unlock(&ctx->sig_mutex);
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
        poc_log_at(POC_LOG_ERROR, "login: challenge too short (%d bytes)", len);
        return;
    }

    ctx->user_id = poc_read32(data);
    poc_log("login: server assigned user_id %u", ctx->user_id);

    if (len >= 8) {
        ctx->challenge_nonce = poc_read32(data + 4);
        poc_log_at(POC_LOG_DEBUG, "login: received auth challenge");
    }

    if (len >= 12) {
        uint16_t key_type = poc_read16(data + 9);
        poc_log_at(POC_LOG_DEBUG, "login: encryption=%s gps=%s",
                key_type ? "yes" : "none", (len > 11 && data[11]) ? "required" : "off");

        /* Extract session encryption key if present.
         * Some servers embed the key after the GPS flag: [12..12+key_len] */
        if (key_type == POC_KEY_TYPE_AES && len >= 28) {
            /* 16-byte AES key at offset 12 */
            poc_encrypt_set_key(&ctx->encrypt, POC_KEY_TYPE_AES, data + 12, 16);
            poc_log("login: session AES key set from challenge");
        }
    } else if (len >= 11) {
        poc_log_at(POC_LOG_DEBUG, "login: encryption=none gps=off");
    }

    /* Send validate response */
    uint8_t vbuf[64];
    int vlen = poc_build_validate(ctx, vbuf, sizeof(vbuf));
    if (vlen > 0) {
        int src = poc_tcp_send_frame(ctx, vbuf, vlen);
        if (src == POC_OK) {
            atomic_store(&ctx->login_state, LOGIN_SENT_VALIDATE);
            ctx->login_sent_at = poc_mono_ms();
            poc_log("login: sent auth response");
        } else {
            poc_log_at(POC_LOG_ERROR, "login: failed to send auth response");
        }
    } else {
        poc_log_at(POC_LOG_ERROR, "login: failed to build auth response");
    }
}

/*
 * Response/Result (cmd 0x01): server ack to our commands.
 * Generic — used after validate, enter_group, start_ptt, etc.
 */
static void handle_response(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    /* Login/validate error: server rejected our account or HMAC */
    login_state_t ls = atomic_load(&ctx->login_state);
    if (ls == LOGIN_SENT_LOGIN || ls == LOGIN_SENT_VALIDATE) {
        int code = (len >= 1) ? data[0] : -1;
        if (code != 0) {
            /* Non-zero = auth failed */
            const char *reason = "authentication failed";
            int err = POC_ERR_AUTH;
            switch (code) {
            case 0x06: reason = "account not found"; break;
            case 0x08: reason = "version mismatch"; break;
            case 0x0B: reason = "ICCID mismatch"; break;
            case 0x0C: reason = "IMEI mismatch"; break;
            default: break;
            }
            poc_log_at(POC_LOG_ERROR, "login: rejected — %s", reason);

            atomic_store(&ctx->login_state, LOGIN_FAILED);
            atomic_store(&ctx->state, POC_STATE_OFFLINE);

            poc_event_t evt = { .type = POC_EVT_LOGIN_ERROR,
                                .login_error = { .code = err }};
            snprintf(evt.login_error.msg, sizeof(evt.login_error.msg), "%s", reason);
            poc_evt_push(&ctx->evt_queue, &evt);

            poc_event_t sevt = { .type = POC_EVT_STATE_CHANGE,
                                 .state_change = { .state = POC_STATE_OFFLINE }};
            poc_evt_push(&ctx->evt_queue, &sevt);
            return;
        }
        /* code == 0: success — UserData (0x0B) will follow shortly */
        poc_log("login: credentials accepted, waiting for group data");
        return;
    }

    /* PTT grant/deny */
    if (atomic_load(&ctx->ptt_active)) {
        bool granted = (len >= 1 && data[0] == 0);
        poc_event_t evt = { .type = POC_EVT_PTT_GRANTED,
                            .ptt_granted = { .granted = granted }};
        poc_evt_push(&ctx->evt_queue, &evt);
        if (!granted) {
            atomic_store(&ctx->ptt_active, false);
            poc_log("ptt: floor request denied");
        }
        return;
    }

    /* Generic server response — could be ack to enter_group, leave_group, etc.
     * Only treat as delivery failure if it's a known error code. */
    if (len >= 1) {
        int code = data[0];
        if (code == 0) {
            poc_log_at(POC_LOG_DEBUG, "response: command acknowledged (ok)");
        } else if (code == 0x25) {
            poc_log_at(POC_LOG_WARNING, "message: delivery failed — user offline");
            poc_event_t evt = { .type = POC_EVT_MESSAGE };
            evt.message.from_id = 0;
            snprintf(evt.message.text, sizeof(evt.message.text),
                     "[delivery failed: user offline]");
            poc_evt_push(&ctx->evt_queue, &evt);
        } else {
            poc_log_at(POC_LOG_DEBUG, "response: code 0x%02x (ignored)", code);
        }
    }
}

/*
 * UserData (cmd 0x0B): full group/member list after successful login.
 * Signals transition to ONLINE state.
 */
static void handle_user_data(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    poc_log("login: complete — received group data (%d bytes)", len);

    atomic_store(&ctx->login_state, LOGIN_ONLINE);
    atomic_store(&ctx->state, POC_STATE_ONLINE);
    ctx->login_retries = 0;

    /* Send a UDP registration packet so the server learns our address.
     * Without this, listeners can't receive relayed audio. */
    {
        uint8_t ping = 0;
        poc_udp_send(ctx, &ping, 1);
    }

    /* Flush a cached APNs push token (if any) to the server now that
     * login has finished. We're holding sig_mutex via poc_parse_message
     * — the helper assumes that and won't try to relock. */
    poc_resend_push_token_if_set_locked(ctx);

    /* Parse group list: [0-1] count (big-endian), then per group:
     * [4 bytes] group_id, [1 byte] name_len, [N bytes] name */
    int off = 0;
    if (len >= 2) {
        int group_count = poc_read16(data);
        off = 2;
        ctx->group_count = 0;

        for (int i = 0; i < group_count && i < ctx->group_cap && off < len; i++) {
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

            poc_log("login:   group %u: %s", gid, g->name);
        }
        poc_log("login: %d groups available", ctx->group_count);
    }

    /* Parse user directory (appended after groups by updated servers).
     * Format: [user_count(2)] + per user: [uid(4)][nlen(1)][name(N)][status(1)] */
    if (off + 2 <= len) {
        int ucount = poc_read16(data + off); off += 2;
        ctx->user_count = 0;

        for (int i = 0; i < ucount && i < ctx->user_cap && off + 5 <= len; i++) {
            uint32_t uid = poc_read32(data + off); off += 4;
            int nlen = data[off]; off++;
            if (off + nlen + 1 > len) break;

            poc_user_t *u = &ctx->users[ctx->user_count];
            u->id = uid;
            int copy = nlen < 31 ? nlen : 31;
            memcpy(u->account, data + off, copy);
            u->account[copy] = '\0';
            snprintf(u->name, sizeof(u->name), "%s", u->account);
            off += nlen;
            u->status = data[off]; off++;
            u->privilege = 0;
            ctx->user_count++;
        }
        poc_log("login: %d users in directory", ctx->user_count);
    }

    /* Parse per-group encryption keys (appended after user directory).
     * Format: [gcount(2)] + per group: [gid(4)][key_type(1)][key_len(1)][key(N)] */
    if (off + 2 <= len) {
        int gkcount = poc_read16(data + off); off += 2;
        for (int i = 0; i < gkcount && off + 6 <= len; i++) {
            uint32_t gid = poc_read32(data + off); off += 4;
            uint8_t ktype = data[off]; off++;
            int klen = data[off]; off++;
            if (klen > 0 && off + klen <= len && ktype == POC_KEY_TYPE_AES) {
                poc_encrypt_set_group_key(&ctx->encrypt, gid, ktype, data + off, klen);
                poc_log("login: group %u AES key set (%d bytes)", gid, klen);
            }
            off += klen;
        }
    }

    /* Fire state change */
    poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                        .state_change = { .state = POC_STATE_ONLINE }};
    poc_evt_push(&ctx->evt_queue, &evt);

    /* Fire groups updated (also signals user roster is ready) */
    if (ctx->group_count > 0 || ctx->user_count > 0) {
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

    /* Server sends: [speaker_id(4)][flags(1)][name(null-terminated)]
     * Parse the speaker name from offset 5 if present */
    const char *speaker_name = NULL;
    if (len > 5)
        speaker_name = (const char *)(data + 5);

    atomic_store(&ctx->ptt_rx_active, true);
    ctx->ptt_speaker_id = speaker_id;

    if (speaker_name && speaker_name[0]) {
        snprintf(ctx->ptt_speaker_name, sizeof(ctx->ptt_speaker_name), "%s", speaker_name);
    } else {
        /* Look up from cached user directory */
        const char *found = NULL;
        for (int i = 0; i < ctx->user_count; i++) {
            if (ctx->users[i].id == speaker_id) { found = ctx->users[i].name; break; }
        }
        snprintf(ctx->ptt_speaker_name, sizeof(ctx->ptt_speaker_name),
                 "%s", found ? found : "Unknown");
    }

    poc_log("ptt: %s (user %u) started talking on group %u",
            ctx->ptt_speaker_name, speaker_id, ctx->active_group_id);

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

    poc_log("ptt: user %u stopped talking", speaker_id);

    poc_event_t evt = { .type = POC_EVT_PTT_END,
                        .ptt_end = { .speaker_id = speaker_id,
                                     .group_id = ctx->active_group_id }};
    poc_evt_push(&ctx->evt_queue, &evt);
}

static void handle_force_exit(poc_ctx_t *ctx, const uint8_t *data __attribute__((unused)), int len __attribute__((unused)))
{
    poc_log_at(POC_LOG_WARNING, "*** STUNNED by server — forced offline ***");
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
    poc_log_at(POC_LOG_DEBUG, "group: %s notification", poc_notify_name(cmd));

    if (len < 4) return;
    uint32_t gid = poc_read32(data);

    switch (cmd) {
    case CMD_NOTIFY_ADD_GROUP:
        /* New group added: [gid(4)][name_len(1)][name(N)] */
        if (ctx->group_count < ctx->group_cap && len >= 5) {
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
            poc_log("group: added group %u '%s'", gid, g->name);
        }
        break;

    case CMD_NOTIFY_DEL_GROUP:
        /* Group removed: [gid(4)] */
        for (int i = 0; i < ctx->group_count; i++) {
            if (ctx->groups[i].id == gid) {
                ctx->groups[i] = ctx->groups[--ctx->group_count];
                poc_log("group: removed group %u", gid);
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
                poc_log("group: renamed group %u to '%s'", gid, ctx->groups[i].name);
                break;
            }
        }
        break;

    case CMD_NOTIFY_ENTER_GROUP:
    case CMD_NOTIFY_GRP_ADD_USER:
        /* User joined group: [gid(4)][user_id(4)] */
        if (len >= 8) {
            uint32_t uid = poc_read32(data + 4);
            poc_log_at(POC_LOG_DEBUG, "group: user %u joined group %u", uid, gid);
            for (int i = 0; i < ctx->group_count; i++)
                if (ctx->groups[i].id == gid) ctx->groups[i].user_count++;
        }
        break;

    case CMD_NOTIFY_GRP_DEL_USER:
        /* User left group: [gid(4)][user_id(4)] */
        if (len >= 8) {
            uint32_t uid = poc_read32(data + 4);
            poc_log_at(POC_LOG_DEBUG, "group: user %u left group %u", uid, gid);
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

    /* Check for SOS marker (0xFF) or cancel (0xFE) at byte 4 */
    if (len >= 5 && ((uint8_t)data[4] == 0xFF || (uint8_t)data[4] == 0xFE)) {
        if ((uint8_t)data[4] == 0xFF) {
            int alert_type = (len >= 6) ? data[5] : 0;
            const char *alert_names[] = {"SOS", "ManDown", "Fall", "CallAlarm"};
            poc_log_at(POC_LOG_WARNING, "*** %s ALERT from user %u ***",
                       alert_type < 4 ? alert_names[alert_type] : "UNKNOWN", from_id);
            poc_event_t evt = { .type = POC_EVT_SOS,
                                .sos = { .user_id = from_id, .alert_type = alert_type }};
            poc_evt_push(&ctx->evt_queue, &evt);
        } else {
            poc_log("SOS cancelled by user %u", from_id);
            poc_event_t evt = { .type = POC_EVT_SOS,
                                .sos = { .user_id = from_id, .alert_type = -1 }};
            poc_evt_push(&ctx->evt_queue, &evt);
        }
        return;
    }

    /* Delivery receipt (0xFC), read receipt (0xFD), typing indicator (0xFB) */
    if (len >= 5) {
        uint8_t m = (uint8_t)data[4];
        if (m == 0xFC) {
            poc_log_at(POC_LOG_DEBUG, "message delivered to user %u", from_id);
            poc_event_t evt = { .type = POC_EVT_MSG_DELIVERED,
                                .msg_delivered = { .user_id = from_id }};
            poc_evt_push(&ctx->evt_queue, &evt);
            return;
        }
        if (m == 0xFD) {
            poc_log_at(POC_LOG_DEBUG, "message read by user %u", from_id);
            poc_event_t evt = { .type = POC_EVT_MSG_READ,
                                .msg_read = { .user_id = from_id }};
            poc_evt_push(&ctx->evt_queue, &evt);
            return;
        }
        if (m == 0xFB) {
            bool is_typing = (len >= 6 && data[5] != 0);
            poc_log_at(POC_LOG_DEBUG, "user %u %s", from_id, is_typing ? "typing" : "stopped typing");
            poc_event_t evt = { .type = POC_EVT_TYPING,
                                .typing = { .user_id = from_id, .typing = is_typing }};
            poc_evt_push(&ctx->evt_queue, &evt);
            return;
        }
    }

    /* Regular text message */
    const char *text = (const char *)(data + 4);
    int text_max = len - 4;

    poc_log("message from user %u: %.*s", from_id, text_max, text);

    poc_event_t evt = { .type = POC_EVT_MESSAGE };
    evt.message.from_id = from_id;
    snprintf(evt.message.text, sizeof(evt.message.text), "%.*s",
             text_max, text);
    poc_evt_push(&ctx->evt_queue, &evt);
}
