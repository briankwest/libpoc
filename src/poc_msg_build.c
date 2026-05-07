/*
 * poc_msg_build.c — Build outgoing protocol messages
 *
 * All messages are payloads inside MS-frames. The caller wraps with
 * poc_tcp_send_frame() which prepends the "MS" + length header.
 */

#include "poc_internal.h"
#include <stdlib.h>
#include <string.h>

/*
 * Login message (cmd 0x01):
 *   [0]    session_id
 *   [1-4]  user_id = 0xFFFFFFFF (initial login)
 *   [5]    cmd = 0x01
 *   [6-9]  protocol version (big-endian)
 *   [10..] account (null-terminated, max 31 bytes)
 *   [..]   IMEI (8 bytes, big-endian uint64)
 *   [..]   ICCID (null-terminated, max 32 bytes)
 */
int poc_build_login(poc_ctx_t *ctx, uint8_t *buf, int buflen)
{
    int acct_len = strlen(ctx->account) + 1;
    if (acct_len > 31) acct_len = 31;

    int iccid_len = ctx->iccid[0] ? (int)strlen(ctx->iccid) + 1 : 1;
    int total = 10 + acct_len + 8 + iccid_len;

    if (total > buflen)
        return POC_ERR;

    int off = 0;

    ctx->session_id++;
    buf[off++] = ctx->session_id;

    /* UserID = 0xFFFFFFFF for initial login */
    poc_write32(buf + off, 0xFFFFFFFF);
    off += 4;

    /* Command = LOGIN (0x01) */
    buf[off++] = CMD_LOGIN;

    /* Protocol version */
    poc_write32(buf + off, POC_PROTOCOL_VER);
    off += 4;

    /* Account name */
    memcpy(buf + off, ctx->account, acct_len);
    off += acct_len;

    /* IMEI as big-endian uint64 */
    uint64_t imei_val = 0;
    if (ctx->imei[0])
        imei_val = strtoull(ctx->imei, NULL, 10);
    buf[off++] = (imei_val >> 56) & 0xFF;
    buf[off++] = (imei_val >> 48) & 0xFF;
    buf[off++] = (imei_val >> 40) & 0xFF;
    buf[off++] = (imei_val >> 32) & 0xFF;
    buf[off++] = (imei_val >> 24) & 0xFF;
    buf[off++] = (imei_val >> 16) & 0xFF;
    buf[off++] = (imei_val >> 8) & 0xFF;
    buf[off++] = imei_val & 0xFF;

    /* ICCID */
    if (ctx->iccid[0]) {
        memcpy(buf + off, ctx->iccid, iccid_len);
        off += iccid_len;
    } else {
        buf[off++] = '\0';
    }

    return off;
}

/*
 * Validate message (cmd 0x04) — challenge response:
 *   [0]      session_id
 *   [1-4]    user_id (from challenge, big-endian)
 *   [5]      cmd = 0x04
 *   [6-25]   HMAC-SHA1(password_sha1_hex[40], nonce[4])
 *
 * The HMAC key is the 40-byte hex SHA1 password string.
 * The HMAC data is the 4-byte challenge nonce (big-endian).
 */
int poc_build_validate(poc_ctx_t *ctx, uint8_t *buf, int buflen)
{
    int total = 26;  /* 6 header + 20 HMAC */
    if (buflen < total)
        return POC_ERR;

    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_VALIDATE;

    /* HMAC-SHA1(sha1_hex_password, challenge_nonce) */
    uint8_t nonce_buf[4];
    poc_write32(nonce_buf, ctx->challenge_nonce);

    poc_hmac_sha1((const uint8_t *)ctx->password_sha1, 40,
                  nonce_buf, 4,
                  buf + 6);

    return total;
}

/*
 * Heartbeat (cmd 0x06):
 *   [0]    session_id
 *   [1-4]  user_id (big-endian)
 *   [5]    cmd = 0x06
 */
int poc_build_heartbeat(poc_ctx_t *ctx, uint8_t *buf, int buflen)
{
    if (buflen < 6)
        return POC_ERR;

    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_HEARTBEAT;

    return 6;
}

/*
 * Enter group:
 *   [0]    session_id
 *   [1-4]  user_id
 *   [5]    cmd = 0x11
 *   [6-9]  group_id (big-endian)
 */
int poc_build_enter_group(poc_ctx_t *ctx, uint32_t group_id,
                          uint8_t *buf, int buflen)
{
    if (buflen < 10)
        return POC_ERR;

    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_NOTIFY_ENTER_GROUP;
    poc_write32(buf + 6, group_id);

    return 10;
}

/*
 * Leave group:
 *   [0]    session_id
 *   [1-4]  user_id
 *   [5]    cmd for leave (using end_ptt pattern, TBD from captures)
 */
int poc_build_leave_group(poc_ctx_t *ctx, uint8_t *buf, int buflen)
{
    if (buflen < 6)
        return POC_ERR;

    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = 0x17; /* leave/exit */

    return 6;
}

/*
 * Start PTT (cmd 0x5D):
 *   [0]    session_id
 *   [1-4]  user_id
 *   [5]    cmd = 0x5D
 *   [6]    codec type
 *   [7-8]  flags (big-endian uint16)
 *   [9..]  speaker name (UTF-8, null-terminated)
 */
int poc_build_start_ptt(poc_ctx_t *ctx, uint8_t *buf, int buflen)
{
    const char *name = ctx->account;
    int name_len = strlen(name) + 1;
    if (name_len > 32) name_len = 32;

    int total = 9 + name_len;
    if (buflen < total)
        return POC_ERR;

    ctx->session_id++;
    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_START_PTT;
    buf[6] = POC_CODEC_OPUS_SWB;
    poc_write16(buf + 7, 0x0000);  /* flags */
    memcpy(buf + 9, name, name_len);

    return total;
}

/*
 * End PTT (cmd 0x5E):
 *   [0]    session_id
 *   [1-4]  user_id
 *   [5]    cmd = 0x5E
 */
int poc_build_end_ptt(poc_ctx_t *ctx, uint8_t *buf, int buflen)
{
    if (buflen < 6)
        return POC_ERR;

    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_END_PTT;

    return 6;
}

/*
 * Send user message:
 *   [0]    session_id
 *   [1-4]  user_id (sender)
 *   [5]    cmd = 0x43 (ext data / message)
 *   [6-9]  target_user_id (big-endian)
 *   [10..] text (UTF-8, null-terminated)
 */
int poc_build_send_user_msg(poc_ctx_t *ctx, uint32_t user_id,
                            const char *text, uint8_t *buf, int buflen)
{
    int text_len = strlen(text) + 1;
    int total = 10 + text_len;
    if (total > buflen)
        return POC_ERR;

    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_NOTIFY_EXT_DATA;
    poc_write32(buf + 6, user_id);
    memcpy(buf + 10, text, text_len);

    return total;
}

/*
 * Send group message:
 *   [0]    session_id
 *   [1-4]  user_id (sender)
 *   [5]    cmd = 0x43 (ext data / message)
 *   [6-9]  target_group_id (big-endian)
 *   [10..] text (UTF-8, null-terminated)
 */
int poc_build_send_group_msg(poc_ctx_t *ctx, uint32_t group_id,
                             const char *text, uint8_t *buf, int buflen)
{
    int text_len = strlen(text) + 1;
    int total = 10 + text_len;
    if (total > buflen)
        return POC_ERR;

    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_NOTIFY_EXT_DATA;
    poc_write32(buf + 6, group_id);
    memcpy(buf + 10, text, text_len);

    return total;
}
