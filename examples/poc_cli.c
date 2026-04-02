/*
 * poc_cli — Standalone test client for the PoC protocol library
 *
 * Usage: poc_cli <server> <account> <password> [group_id]
 *
 * Connects, logs in, enters a group, and dumps all messages.
 */

#include "poc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static volatile int running = 1;

static void on_signal(int sig) { (void)sig; running = 0; }

static void on_state(poc_ctx_t *ctx, poc_state_t state, void *ud)
{
    const char *names[] = { "OFFLINE", "CONNECTING", "ONLINE", "LOGOUT" };
    printf(">>> STATE: %s\n", names[state]);

    /* Auto-enter group if provided */
    if (state == POC_STATE_ONLINE && ud) {
        uint32_t gid = *(uint32_t *)ud;
        if (gid > 0) {
            printf(">>> Entering group %u\n", gid);
            poc_enter_group(ctx, gid);
        }
    }
}

static void on_login_error(poc_ctx_t *ctx, int code, const char *msg, void *ud)
{
    (void)ctx; (void)ud;
    printf(">>> LOGIN ERROR: %d — %s\n", code, msg);
}

static void on_ptt_start(poc_ctx_t *ctx, uint32_t speaker, const char *name,
                         uint32_t gid, void *ud)
{
    (void)ctx; (void)ud;
    printf(">>> PTT START: user=%u name=%s group=%u\n", speaker, name, gid);
}

static void on_ptt_end(poc_ctx_t *ctx, uint32_t speaker, uint32_t gid, void *ud)
{
    (void)ctx; (void)ud;
    printf(">>> PTT END: user=%u group=%u\n", speaker, gid);
}

static void on_audio(poc_ctx_t *ctx, const poc_audio_frame_t *frame, void *ud)
{
    (void)ctx; (void)ud;
    /* Just count frames */
    static int frame_count = 0;
    if (++frame_count % 50 == 0)
        printf(">>> AUDIO: %d frames from user %u (1 second)\n",
               frame_count, frame->speaker_id);
}

static void on_ptt_granted(poc_ctx_t *ctx, bool granted, void *ud)
{
    (void)ctx; (void)ud;
    printf(">>> PTT %s\n", granted ? "GRANTED" : "DENIED");
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server[:port]> <account> <password> [group_id]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* Parse server:port */
    char host[256];
    uint16_t port = 29999;
    snprintf(host, sizeof(host), "%s", argv[1]);
    char *colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }

    uint32_t group_id = 0;
    if (argc > 4)
        group_id = atoi(argv[4]);

    poc_config_t cfg = {
        .server_host = host,
        .server_port = port,
        .account = argv[2],
        .password = argv[3],
        .codec = POC_CODEC_SPEEX,
    };

    poc_callbacks_t cb = {
        .on_state_change = on_state,
        .on_login_error = on_login_error,
        .on_ptt_start = on_ptt_start,
        .on_ptt_end = on_ptt_end,
        .on_audio_frame = on_audio,
        .on_ptt_granted = on_ptt_granted,
        .userdata = group_id ? &group_id : NULL,
    };

    poc_ctx_t *ctx = poc_create(&cfg, &cb);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    printf("Connecting to %s:%u as %s...\n", host, port, argv[2]);

    int rc = poc_connect(ctx);
    if (rc != POC_OK) {
        fprintf(stderr, "Connect failed: %d\n", rc);
        poc_destroy(ctx);
        return 1;
    }

    printf("Connected. Polling... (Ctrl-C to quit)\n");

    while (running) {
        rc = poc_poll(ctx, 50);
        if (rc == POC_ERR_NETWORK) {
            printf("Connection lost, exiting.\n");
            break;
        }
    }

    printf("\nDisconnecting...\n");
    poc_destroy(ctx);
    return 0;
}
