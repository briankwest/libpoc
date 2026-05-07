/*
 * poc_udp.c — UDP socket for voice audio transport
 *
 * UDP packet format:
 *   [0-1]  SeqNum (big-endian uint16)
 *   [2-5]  SenderID (big-endian uint32)
 *   [6]    padding/flags
 *   [7]    ContentType
 *   [8..]  Payload (encoded audio frames)
 */

#include "poc_internal.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

/* Jitter-buffer emit trampoline: pushes decoded PCM into rx_ring,
 * which the caller drains in poc_poll(). */
static void udp_jb_emit(const int16_t *pcm, int n_samples,
                        uint32_t speaker_id, void *ud)
{
    poc_ctx_t *ctx = (poc_ctx_t *)ud;
    if (!poc_ring_push(&ctx->rx_ring, pcm, n_samples,
                       speaker_id, ctx->active_group_id)) {
        poc_log_at(POC_LOG_WARNING, "udp: rx_ring full, dropping frame");
    }
}

int poc_udp_open(poc_ctx_t *ctx)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return POC_ERR_NETWORK;

    /* Non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Bind to ephemeral port */
    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = 0,
    };
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        close(fd);
        return POC_ERR_NETWORK;
    }

    ctx->udp_fd = fd;
    ctx->udp_seq = 0;
    ctx->udp_dedup_idx = 0;
    memset(ctx->udp_dedup, 0xFF, sizeof(ctx->udp_dedup));

    poc_log("udp: opened fd=%d", fd);
    return POC_OK;
}

/* Idempotent under concurrent calls — see comment on poc_tcp_close. */
void poc_udp_close(poc_ctx_t *ctx)
{
    pthread_mutex_lock(&ctx->sig_mutex);
    int fd = ctx->udp_fd;
    ctx->udp_fd = -1;
    pthread_mutex_unlock(&ctx->sig_mutex);
    if (fd >= 0) close(fd);
}

int poc_udp_send(poc_ctx_t *ctx, const uint8_t *data, int len)
{
    if (ctx->udp_fd < 0 || ctx->udp_server.sin_port == 0) {
        static int udp_skip_count = 0;
        if (++udp_skip_count <= 3)
            poc_log_at(POC_LOG_ERROR, "udp: send skipped — fd=%d port=%d",
                       ctx->udp_fd, ntohs(ctx->udp_server.sin_port));
        return POC_ERR_NETWORK;
    }

    /* Build UDP packet: SeqNum + SenderID + pad + type + payload */
    uint8_t pkt[UDP_MAX_PKT];
    if (len + UDP_HDR_LEN > UDP_MAX_PKT)
        return POC_ERR;

    poc_write16(pkt, ctx->udp_seq++);
    poc_write32(pkt + 2, ctx->user_id);
    pkt[6] = 0;       /* padding */
    pkt[7] = 0x80;    /* content type: audio */
    memcpy(pkt + UDP_HDR_LEN, data, len);

    int total = UDP_HDR_LEN + len;
    int n = sendto(ctx->udp_fd, pkt, total, 0,
                   (struct sockaddr *)&ctx->udp_server,
                   sizeof(ctx->udp_server));
    if (n < 0) {
        poc_log_at(POC_LOG_ERROR, "udp: send error: %s", strerror(errno));
        return POC_ERR_NETWORK;
    }

    static int udp_send_count = 0;
    udp_send_count++;
    if (udp_send_count <= 3 || (udp_send_count % 50) == 0)
        poc_log("udp: sent pkt #%d (%d bytes) to %s:%d seq=%u uid=%u",
                udp_send_count, total,
                inet_ntoa(ctx->udp_server.sin_addr),
                ntohs(ctx->udp_server.sin_port),
                ctx->udp_seq - 1, ctx->user_id);

    return POC_OK;
}

static bool udp_dedup_check(poc_ctx_t *ctx, uint16_t seq)
{
    for (int i = 0; i < UDP_DEDUP_SLOTS; i++) {
        if (ctx->udp_dedup[i] == seq)
            return true;  /* duplicate */
    }
    ctx->udp_dedup[ctx->udp_dedup_idx] = seq;
    ctx->udp_dedup_idx = (ctx->udp_dedup_idx + 1) % UDP_DEDUP_SLOTS;
    return false;
}

int poc_udp_recv(poc_ctx_t *ctx)
{
    if (ctx->udp_fd < 0)
        return POC_OK;

    uint8_t pkt[UDP_MAX_PKT];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    for (;;) {
        int n = recvfrom(ctx->udp_fd, pkt, sizeof(pkt), 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return POC_OK;
            return POC_ERR_NETWORK;
        }

        if (n < UDP_HDR_LEN) {
            poc_log_at(POC_LOG_WARNING, "udp: runt packet %d bytes", n);
            continue;
        }

        uint16_t seq = poc_read16(pkt);
        uint32_t sender_id = poc_read32(pkt + 2);
        /* uint8_t content_type = pkt[7]; — for future use */
        (void)pkt[7];

        if (udp_dedup_check(ctx, seq))
            continue;

        /* Skip our own packets */
        if (sender_id == ctx->user_id)
            continue;

        int payload_len = n - UDP_HDR_LEN;
        const uint8_t *payload = pkt + UDP_HDR_LEN;

        /* Decrypt → push into jitter buffer (which decodes in order
         * and FEC-recovers single-packet gaps from the next packet's
         * Opus LBRR redundancy). */
        if (atomic_load(&ctx->ptt_rx_active) && payload_len > 0) {
            const uint8_t *audio_data = payload;
            int audio_len = payload_len;
            uint8_t decrypted[POC_CODEC_MAX_ENCODED_SIZE + 16];

            if (ctx->encrypt.enabled) {
                int dlen = poc_decrypt_audio(&ctx->encrypt, ctx->active_group_id,
                                             payload, payload_len,
                                             decrypted, sizeof(decrypted));
                if (dlen > 0) {
                    audio_data = decrypted;
                    audio_len = dlen;
                } else {
                    poc_log_at(POC_LOG_WARNING, "udp: decrypt failed, dropping frame");
                    continue;
                }
            }

            poc_jb_push(&ctx->jb, ctx->codec, sender_id, seq,
                        audio_data, audio_len, udp_jb_emit, ctx);
        }
    }
}
