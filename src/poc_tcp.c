/*
 * poc_tcp.c — TCP connection and MS-frame send/recv
 *
 * Wire format:  'M' 'S' LEN_HI LEN_LO [payload...]
 *   LEN = payload length (big-endian uint16, excludes 4-byte header)
 */

#include "poc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

    /* Save resolved address for UDP (same host, same port) */
    if (res->ai_family == AF_INET) {
        memcpy(&ctx->udp_server, res->ai_addr, sizeof(ctx->udp_server));
        poc_log("udp: target set to %s:%d",
                inet_ntoa(ctx->udp_server.sin_addr),
                ntohs(ctx->udp_server.sin_port));
    } else {
        poc_log_at(POC_LOG_ERROR, "udp: resolved address is not AF_INET (family=%d)", res->ai_family);
    }

    rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return POC_ERR_NETWORK;
    }

    /* Wait for connect with short polls so we can be interrupted.
     * Total timeout ~5s, checked every 250ms. */
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int connected = 0;
    for (int attempt = 0; attempt < 20; attempt++) {
        rc = poll(&pfd, 1, 250);
        if (rc > 0) { connected = 1; break; }
        if (rc < 0 && errno != EINTR) break;
        /* During reconnect, check if shutdown requested */
    }
    if (!connected) {
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

    /* TLS handshake if enabled */
    if (ctx->tls_enabled) {
        ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx->ssl_ctx) {
            poc_log_at(POC_LOG_ERROR, "TLS: failed to create SSL context");
            close(fd); ctx->tcp_fd = -1;
            return POC_ERR_NETWORK;
        }
        SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_2_VERSION);

        if (ctx->tls_ca_path[0]) {
            if (SSL_CTX_load_verify_locations(ctx->ssl_ctx, ctx->tls_ca_path, NULL) != 1) {
                poc_log_at(POC_LOG_ERROR, "TLS: failed to load CA cert: %s", ctx->tls_ca_path);
                SSL_CTX_free(ctx->ssl_ctx); ctx->ssl_ctx = NULL;
                close(fd); ctx->tcp_fd = -1;
                return POC_ERR_NETWORK;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx->ssl_ctx);
        }

        if (ctx->tls_verify)
            SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);

        ctx->ssl = SSL_new(ctx->ssl_ctx);
        SSL_set_fd(ctx->ssl, fd);

        /* Non-blocking TLS handshake with poll */
        int tls_ok = 0;
        for (int attempt = 0; attempt < 40; attempt++) {  /* 40 × 250ms = 10s max */
            int ret = SSL_connect(ctx->ssl);
            if (ret == 1) { tls_ok = 1; break; }
            int err = SSL_get_error(ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                struct pollfd tp = { .fd = fd, .events = POLLIN };
                poll(&tp, 1, 250);
            } else if (err == SSL_ERROR_WANT_WRITE) {
                struct pollfd tp = { .fd = fd, .events = POLLOUT };
                poll(&tp, 1, 250);
            } else {
                poc_log_at(POC_LOG_ERROR, "TLS: handshake failed (SSL error %d)", err);
                break;
            }
        }
        if (!tls_ok) {
            SSL_free(ctx->ssl); ctx->ssl = NULL;
            SSL_CTX_free(ctx->ssl_ctx); ctx->ssl_ctx = NULL;
            close(fd); ctx->tcp_fd = -1;
            return POC_ERR_NETWORK;
        }
        poc_log("connected to %s:%u (TLS)", ctx->server_host, ctx->server_port);
    } else {
        poc_log("connected to %s:%u", ctx->server_host, ctx->server_port);
    }

    return POC_OK;
}

void poc_tcp_close(poc_ctx_t *ctx)
{
    if (ctx->ssl) {
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
    if (ctx->tcp_fd >= 0) {
        close(ctx->tcp_fd);
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

    /* Build frame: header + payload */
    int total = MS_HDR_LEN + len;
    uint8_t *frame = malloc(total);
    if (!frame) return POC_ERR_NOMEM;
    memcpy(frame, hdr, MS_HDR_LEN);
    memcpy(frame + MS_HDR_LEN, payload, len);

    int sent = 0;
    int retries = 0;
    while (sent < total) {
        int n;
        if (ctx->ssl) {
            n = SSL_write(ctx->ssl, frame + sent, total - sent);
            if (n <= 0) {
                int err = SSL_get_error(ctx->ssl, n);
                if ((err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) && retries++ < 50) {
                    usleep(1000);
                    continue;
                }
                poc_log_at(POC_LOG_ERROR, "TLS send error (SSL error %d)", err);
                free(frame);
                return POC_ERR_NETWORK;
            }
        } else {
            n = send(ctx->tcp_fd, frame + sent, total - sent, MSG_NOSIGNAL);
            if (n < 0) {
                if ((errno == EAGAIN || errno == EINTR) && retries++ < 50) {
                    usleep(1000);
                    continue;
                }
                poc_log_at(POC_LOG_ERROR, "tcp send error: %s", strerror(errno));
                free(frame);
                return POC_ERR_NETWORK;
            }
        }
        sent += n;
        retries = 0;
    }

    free(frame);
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

    int n;
    if (ctx->ssl) {
        n = SSL_read(ctx->ssl, ctx->tcp_recv_buf + ctx->tcp_recv_len, space);
        if (n <= 0) {
            int err = SSL_get_error(ctx->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                return POC_OK;
            if (err == SSL_ERROR_ZERO_RETURN) {
                poc_log_at(POC_LOG_WARNING, "TLS: connection closed by server");
                return POC_ERR_NETWORK;
            }
            poc_log_at(POC_LOG_ERROR, "TLS recv error (SSL error %d)", err);
            return POC_ERR_NETWORK;
        }
    } else {
        n = recv(ctx->tcp_fd, ctx->tcp_recv_buf + ctx->tcp_recv_len, space, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return POC_OK;
            poc_log_at(POC_LOG_ERROR, "tcp recv error: %s", strerror(errno));
            return POC_ERR_NETWORK;
        }
        if (n == 0) {
            poc_log_at(POC_LOG_WARNING, "connection closed by server");
            return POC_ERR_NETWORK;
        }
    }

    ctx->tcp_recv_len += n;

    /* Deframe: extract complete MS frames */
    uint8_t *buf = ctx->tcp_recv_buf;
    int remaining = ctx->tcp_recv_len;

    while (remaining >= MS_HDR_LEN + 1) {
        /* Validate magic */
        if (buf[0] != MS_MAGIC_0 || buf[1] != MS_MAGIC_1) {
            poc_log_at(POC_LOG_ERROR, "tcp: bad magic %02x %02x, resetting buffer", buf[0], buf[1]);
            remaining = 0;
            break;
        }

        uint16_t payload_len = poc_read16(buf + 2);
        if (payload_len < 2) {
            poc_log_at(POC_LOG_WARNING, "tcp: payload too short (%d), skipping", payload_len);
            remaining = 0;
            break;
        }
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
