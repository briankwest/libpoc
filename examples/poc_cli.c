/*
 * poc_cli — Interactive test client for the PoC protocol library
 *
 * Usage: poc_cli <server[:port]> <account> <password> [group_id]
 *
 * Commands (type at the prompt):
 *   ptt          Send 1 second of 440Hz tone via PTT
 *   msg <text>   Send group message
 *   dm <id> <text>  Send private message to user ID
 *   quit         Disconnect and exit
 *   Ctrl-C       Same as quit
 */

#include "poc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>

static volatile int running = 1;
static poc_ctx_t *g_ctx = NULL;
static uint32_t g_group_id = 0;

static void on_signal(int sig) { (void)sig; running = 0; }

static void on_state(poc_ctx_t *ctx, poc_state_t state, void *ud)
{
    (void)ud;
    const char *names[] = { "OFFLINE", "CONNECTING", "ONLINE", "LOGOUT" };
    printf("\n>>> STATE: %s\n", names[state]);

    if (state == POC_STATE_ONLINE && g_group_id > 0) {
        printf(">>> Entering group %u\n", g_group_id);
        poc_enter_group(ctx, g_group_id);
    }
    if (state == POC_STATE_ONLINE)
        printf(">>> Type: ptt, msg <text>, dm <id> <text>, quit\n");
    if (state == POC_STATE_CONNECTING)
        printf(">>> Reconnecting...\n");
}

static void on_login_error(poc_ctx_t *ctx, int code, const char *msg, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> LOGIN ERROR: %d — %s\n", code, msg);
    if (code == POC_ERR_NETWORK) {
        printf(">>> Server unreachable. Giving up.\n");
        running = 0;
    }
}

static void on_ptt_start(poc_ctx_t *ctx, uint32_t speaker, const char *name,
                         uint32_t gid, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> PTT START: user=%u name='%s' group=%u\n", speaker, name, gid);
}

static void on_ptt_end(poc_ctx_t *ctx, uint32_t speaker, uint32_t gid, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> PTT END: user=%u group=%u\n", speaker, gid);
}

static void on_audio(poc_ctx_t *ctx, const poc_audio_frame_t *frame, void *ud)
{
    (void)ctx; (void)ud;
    static int frame_count = 0;
    if (++frame_count % 50 == 0)
        printf("\n>>> AUDIO: %d frames from user %u\n", frame_count, frame->speaker_id);
}

static void on_ptt_granted(poc_ctx_t *ctx, bool granted, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> PTT %s\n", granted ? "GRANTED" : "DENIED");
}

static void on_message(poc_ctx_t *ctx, uint32_t from_id, const char *text, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> MESSAGE from user %u: %s\n", from_id, text);
}

static void on_groups(poc_ctx_t *ctx, const poc_group_t *groups, int count, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> GROUPS (%d):\n", count);
    for (int i = 0; i < count; i++)
        printf("    [%u] %s\n", groups[i].id, groups[i].name);
}

static void on_user_status(poc_ctx_t *ctx, uint32_t user_id, int status, void *ud)
{
    (void)ctx; (void)ud;
    if (status == -1)
        printf("\n>>> USER REMOVED: %u\n", user_id);
    else
        printf("\n>>> USER %u is now %s\n", user_id, status ? "ONLINE" : "OFFLINE");
}

static void on_pull(poc_ctx_t *ctx, uint32_t group_id, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> PULLED TO GROUP %u\n", group_id);
}

static void on_tmp_invite(poc_ctx_t *ctx, uint32_t group_id, uint32_t inviter, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> TEMP GROUP INVITE: group=%u from user=%u\n", group_id, inviter);
}

static void on_voice_msg(poc_ctx_t *ctx, uint32_t from, uint64_t note_id,
                         const char *desc, void *ud)
{
    (void)ctx; (void)ud;
    printf("\n>>> VOICE MESSAGE from %u: note=%llu desc=%s\n",
           from, (unsigned long long)note_id, desc);
}

static void on_sos_alert(poc_ctx_t *ctx, uint32_t user_id, int type, void *ud)
{
    (void)ctx; (void)ud;
    const char *names[] = {"SOS", "ManDown", "Fall", "CallAlarm"};
    printf("\n>>> EMERGENCY: user=%u type=%s\n", user_id,
           type < 4 ? names[type] : "unknown");
}

static void do_ptt(poc_ctx_t *ctx)
{
    printf(">>> Starting PTT (1 second 440Hz tone)...\n");
    int rc = poc_ptt_start(ctx);
    if (rc != POC_OK) {
        printf(">>> PTT start failed: %d\n", rc);
        return;
    }

    /* Wait for PTT grant before sending audio */
    for (int w = 0; w < 50 && running; w++) {
        poc_poll(ctx, 0);
        usleep(20000);
    }

    /* Generate and send 1 second of 440Hz tone (50 frames x 20ms) */
    for (int f = 0; f < 50 && running; f++) {
        int16_t pcm[160];
        for (int i = 0; i < 160; i++)
            pcm[i] = (int16_t)(16000.0 * sin(2.0 * M_PI * 440.0 * (f * 160 + i) / 8000.0));
        poc_ptt_send_audio(ctx, pcm, 160);
        poc_poll(ctx, 0);
        /* Real-time pacing: 20ms per frame — match codec cadence exactly */
        usleep(20000);
    }

    poc_ptt_stop(ctx);
    printf(">>> PTT done.\n");
}

static void do_msg(poc_ctx_t *ctx, const char *text)
{
    if (g_group_id == 0) {
        printf(">>> No group to send to. Specify group_id on command line.\n");
        return;
    }
    int rc = poc_send_group_msg(ctx, g_group_id, text);
    printf(">>> Group message sent (%d)\n", rc);
}

static void do_dm(poc_ctx_t *ctx, const char *args)
{
    uint32_t uid = 0;
    char text[256] = "";
    if (sscanf(args, "%u %255[^\n]", &uid, text) < 2) {
        printf(">>> Usage: dm <user_id> <text>\n");
        return;
    }
    int rc = poc_send_user_msg(ctx, uid, text);
    printf(">>> DM to user %u sent (%d)\n", uid, rc);
}

static void process_stdin(poc_ctx_t *ctx)
{
    char line[512];
    if (!fgets(line, sizeof(line), stdin)) {
        running = 0;
        return;
    }

    /* Strip newline */
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';
    if (!*line) return;

    if (strcmp(line, "ptt") == 0) {
        do_ptt(ctx);
    } else if (strncmp(line, "msg ", 4) == 0) {
        do_msg(ctx, line + 4);
    } else if (strncmp(line, "dm ", 3) == 0) {
        do_dm(ctx, line + 3);
    } else if (strcmp(line, "quit") == 0 || strcmp(line, "q") == 0) {
        running = 0;
    } else if (strcmp(line, "sos") == 0) {
        int rc = poc_send_sos(ctx, POC_ALERT_SOS);
        printf(">>> SOS sent (%d)\n", rc);
    } else if (strcmp(line, "sos cancel") == 0) {
        int rc = poc_cancel_sos(ctx);
        printf(">>> SOS cancel sent (%d)\n", rc);
    } else if (strcmp(line, "state") == 0) {
        const char *names[] = { "OFFLINE", "CONNECTING", "ONLINE", "LOGOUT" };
        printf(">>> State: %s  User ID: %u  Account: %s\n",
               names[poc_get_state(ctx)], poc_get_user_id(ctx), poc_get_account(ctx));
    } else {
        printf(">>> Unknown command. Try: ptt, msg <text>, dm <id> <text>, state, quit\n");
    }
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server[:port]> <account> <password> [group_id]\n", argv[0]);
        fprintf(stderr, "\nCommands once connected:\n");
        fprintf(stderr, "  ptt              Send 1s tone via PTT\n");
        fprintf(stderr, "  msg <text>       Send group message\n");
        fprintf(stderr, "  dm <id> <text>   Send private message\n");
        fprintf(stderr, "  state            Show connection state\n");
        fprintf(stderr, "  quit             Disconnect\n");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    char host[256];
    uint16_t port = 29999;
    snprintf(host, sizeof(host), "%s", argv[1]);
    char *colon = strchr(host, ':');
    if (colon) { *colon = '\0'; port = atoi(colon + 1); }

    if (argc > 4) g_group_id = atoi(argv[4]);

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
        .on_message = on_message,
        .on_groups_updated = on_groups,
        .on_user_status = on_user_status,
        .on_pull_to_group = on_pull,
        .on_tmp_group_invite = on_tmp_invite,
        .on_voice_message = on_voice_msg,
        .on_sos = on_sos_alert,
    };

    g_ctx = poc_create(&cfg, &cb);
    if (!g_ctx) { fprintf(stderr, "Failed to create context\n"); return 1; }

    printf("Connecting to %s:%u as %s...\n", host, port, argv[2]);
    int rc = poc_connect(g_ctx);
    if (rc != POC_OK) {
        fprintf(stderr, "Connect failed: %d\n", rc);
        poc_destroy(g_ctx);
        return 1;
    }

    /* Set stdin non-blocking for interleaved polling */
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);

    while (running) {
        /* Poll stdin + poc together */
        struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
        poll(&pfd, 1, 20);

        if (pfd.revents & POLLIN) {
            /* Restore blocking for fgets */
            fcntl(STDIN_FILENO, F_SETFL, stdin_flags);
            process_stdin(g_ctx);
            fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);
        }

        rc = poc_poll(g_ctx, 0);
        if (rc == POC_ERR_NETWORK) {
            printf("\nConnection lost.\n");
            break;
        }
    }

    /* Restore stdin */
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags);

    printf("\nDisconnecting...\n");
    poc_destroy(g_ctx);
    return 0;
}
