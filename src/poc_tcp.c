/*
 * poc_tcp.c — TCP connection and MS-frame send/recv
 *
 * Wire format:  'M' 'S' LEN_HI LEN_LO [payload...]
 *   LEN = payload length (big-endian uint16, excludes 4-byte header)
 */

#include "poc_internal.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <poll.h>

int poc_tcp_connect(poc_ctx_t *ctx)
{
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res;
    char port_str[8];

    snprintf(port_str, sizeof(port_str), "%u", ctx->server_port);

    int rc = getaddrinfo(ctx->server_host, port_str, &hints, &res);
    if (rc != 0) {
        poc_log("tcp: resolve failed: %s", gai_strerror(rc));
        return POC_ERR_NETWORK;
    }

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return POC_ERR_NETWORK;
    }

    /* Non-blocking connect */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return POC_ERR_NETWORK;
    }

    /* Wait for connect (up to 10s) */
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    rc = poll(&pfd, 1, 10000);
    if (rc <= 0) {
        close(fd);
        return POC_ERR_TIMEOUT;
    }

    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err) {
        close(fd);
        return POC_ERR_NETWORK;
    }

    ctx->tcp_fd = fd;
    ctx->tcp_recv_len = 0;
    poc_log("tcp: connected to %s:%u (fd=%d)", ctx->server_host, ctx->server_port, fd);
    return POC_OK;
}

void poc_tcp_close(poc_ctx_t *ctx)
{
    if (ctx->tcp_fd >= 0) {
        close(ctx->tcp_fd);
        poc_log("tcp: closed fd=%d", ctx->tcp_fd);
        ctx->tcp_fd = -1;
    }
    ctx->tcp_recv_len = 0;
}

int poc_tcp_send_frame(poc_ctx_t *ctx, const uint8_t *payload, uint16_t len)
{
    if (ctx->tcp_fd < 0)
        return POC_ERR_NETWORK;

    uint8_t hdr[MS_HDR_LEN];
    hdr[0] = MS_MAGIC_0;
    hdr[1] = MS_MAGIC_1;
    poc_write16(hdr + 2, len);

    /* Send header */
    int total = MS_HDR_LEN + len;
    uint8_t frame[MS_HDR_LEN + MS_MAX_PAYLOAD];
    memcpy(frame, hdr, MS_HDR_LEN);
    memcpy(frame + MS_HDR_LEN, payload, len);

    int sent = 0;
    while (sent < total) {
        int n = send(ctx->tcp_fd, frame + sent, total - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            poc_log("tcp: send error: %s", strerror(errno));
            return POC_ERR_NETWORK;
        }
        sent += n;
    }

    return POC_OK;
}

int poc_tcp_recv(poc_ctx_t *ctx)
{
    if (ctx->tcp_fd < 0)
        return POC_ERR_NETWORK;

    /* Read available data into buffer */
    int space = TCP_RECV_BUF_SZ - ctx->tcp_recv_len;
    if (space <= 0)
        return POC_ERR;

    int n = recv(ctx->tcp_fd, ctx->tcp_recv_buf + ctx->tcp_recv_len, space, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return POC_OK;
        poc_log("tcp: recv error: %s", strerror(errno));
        return POC_ERR_NETWORK;
    }
    if (n == 0) {
        poc_log("tcp: connection closed by server");
        return POC_ERR_NETWORK;
    }

    ctx->tcp_recv_len += n;

    /* Deframe: extract complete MS frames */
    uint8_t *buf = ctx->tcp_recv_buf;
    int remaining = ctx->tcp_recv_len;

    while (remaining >= MS_HDR_LEN + 1) {
        /* Validate magic */
        if (buf[0] != MS_MAGIC_0 || buf[1] != MS_MAGIC_1) {
            poc_log("tcp: bad magic %02x %02x, resetting buffer", buf[0], buf[1]);
            remaining = 0;
            break;
        }

        uint16_t payload_len = poc_read16(buf + 2);
        int frame_total = MS_HDR_LEN + payload_len;

        if (remaining < frame_total)
            break;  /* incomplete frame, wait for more data */

        /* Dispatch complete message */
        poc_parse_message(ctx, buf + MS_HDR_LEN, payload_len);

        buf += frame_total;
        remaining -= frame_total;
    }

    /* Move leftover to front */
    if (remaining > 0 && buf != ctx->tcp_recv_buf)
        memmove(ctx->tcp_recv_buf, buf, remaining);
    ctx->tcp_recv_len = remaining;

    return POC_OK;
}
