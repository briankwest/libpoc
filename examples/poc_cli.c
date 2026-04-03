/*
 * poc_cli — Interactive PoC protocol test client
 *
 * Usage: poc_cli [-v|-q] <server[:port]> <account> <password> [group_id]
 *
 * Features: linenoise line editing, tab completion, command history.
 */

#include "poc.h"
#include "linenoise.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <math.h>
#include <poll.h>

static volatile int running = 1;
static poc_ctx_t *g_ctx = NULL;
static uint32_t g_group_id = 0;
static int g_log_level = POC_LOG_INFO;
static struct linenoiseState *g_ls = NULL;  /* for async output */

/* Print a line safely without corrupting linenoise prompt */
static void async_printf(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));
static void async_printf(const char *fmt, ...)
{
    if (g_ls) linenoiseHide(g_ls);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (g_ls) linenoiseShow(g_ls);
}

static void on_signal(int sig) { (void)sig; running = 0; }

/* ── Logging callback ───────────────────────────────────────────── */

static void cli_log(int level, const char *msg, void *ud)
{
    (void)ud;
    static const char *tags[] = {"ERR", "WRN", "INF", "DBG"};
    const char *tag = (level >= 0 && level <= 3) ? tags[level] : "???";
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    if (g_ls) linenoiseHide(g_ls);
    fprintf(stderr, "[%02d:%02d:%02d.%03ld %s] %s\n",
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000,
            tag, msg);
    if (g_ls) linenoiseShow(g_ls);
}

/* ── Tab completion ─────────────────────────────────────────────── */

static const char *g_commands[] = {
    "ptt", "msg", "dm", "groups", "join", "leave",
    "sos", "sos cancel", "state", "quit", "help", NULL
};

static void completion(const char *buf, linenoiseCompletions *lc)
{
    size_t len = strlen(buf);
    for (int i = 0; g_commands[i]; i++)
        if (strncmp(buf, g_commands[i], len) == 0)
            linenoiseAddCompletion(lc, g_commands[i]);
}

/* ── Protocol callbacks ─────────────────────────────────────────── */

static void on_state(poc_ctx_t *ctx, poc_state_t state, void *ud)
{
    (void)ud;
    const char *names[] = {"OFFLINE", "CONNECTING", "ONLINE", "LOGOUT"};
    async_printf(">>> STATE: %s\n", names[state]);
    if (state == POC_STATE_ONLINE && g_group_id > 0) {
        async_printf(">>> Entering group %u\n", g_group_id);
        poc_enter_group(ctx, g_group_id);
    }
    if (state == POC_STATE_ONLINE)
        async_printf(">>> Type 'help' for commands\n");
    if (state == POC_STATE_CONNECTING)
        async_printf(">>> Reconnecting...\n");
}

static void on_login_error(poc_ctx_t *ctx, int code, const char *msg, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> LOGIN ERROR: %d — %s\n", code, msg);
    running = 0;
}

static void on_ptt_start(poc_ctx_t *ctx, uint32_t speaker, const char *name,
                         uint32_t gid, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> PTT START: user=%u name='%s' group=%u\n", speaker, name, gid);
}

static void on_ptt_end(poc_ctx_t *ctx, uint32_t speaker, uint32_t gid, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> PTT END: user=%u group=%u\n", speaker, gid);
}

static void on_audio(poc_ctx_t *ctx, const poc_audio_frame_t *frame, void *ud)
{
    (void)ctx; (void)ud;
    static int frame_count = 0;
    if (++frame_count % 50 == 0)
        async_printf(">>> AUDIO: %d frames from user %u\n", frame_count, frame->speaker_id);
}

static void on_ptt_granted(poc_ctx_t *ctx, bool granted, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> PTT %s\n", granted ? "GRANTED" : "DENIED");
}

static void on_message(poc_ctx_t *ctx, uint32_t from_id, const char *text, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> MESSAGE from user %u: %s\n", from_id, text);
}

static void on_groups(poc_ctx_t *ctx, const poc_group_t *groups, int count, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> GROUPS (%d):\n", count);
    for (int i = 0; i < count; i++)
        async_printf("    [%u] %s\n", groups[i].id, groups[i].name);
}

static void on_user_status(poc_ctx_t *ctx, uint32_t user_id, int status, void *ud)
{
    (void)ctx; (void)ud;
    if (status == -1)
        async_printf(">>> USER REMOVED: %u\n", user_id);
    else
        async_printf(">>> USER %u is now %s\n", user_id, status ? "ONLINE" : "OFFLINE");
}

static void on_pull(poc_ctx_t *ctx, uint32_t group_id, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> PULLED TO GROUP %u\n", group_id);
    g_group_id = group_id;
}

static void on_tmp_invite(poc_ctx_t *ctx, uint32_t group_id, uint32_t inviter, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> TEMP GROUP INVITE: group=%u from user=%u\n", group_id, inviter);
}

static void on_voice_msg(poc_ctx_t *ctx, uint32_t from, uint64_t note_id,
                         const char *desc, void *ud)
{
    (void)ctx; (void)ud;
    async_printf(">>> VOICE MESSAGE from %u: note=%llu desc=%s\n",
           from, (unsigned long long)note_id, desc);
}

static void on_sos_alert(poc_ctx_t *ctx, uint32_t user_id, int type, void *ud)
{
    (void)ctx; (void)ud;
    const char *names[] = {"SOS", "ManDown", "Fall", "CallAlarm"};
    async_printf(">>> EMERGENCY: user=%u type=%s\n", user_id,
           type < 4 ? names[type] : "unknown");
}

/* ── Command handlers ───────────────────────────────────────────── */

static void cmd_help(void)
{
    printf("Commands:\n");
    printf("  groups               List available groups\n");
    printf("  join <group_id>      Join/switch group\n");
    printf("  leave                Leave current group\n");
    printf("  ptt                  Send 1s tone via PTT\n");
    printf("  msg [gid] <text>     Send group message\n");
    printf("  dm <uid> <text>      Send private message\n");
    printf("  sos                  Send SOS alert\n");
    printf("  sos cancel           Cancel SOS\n");
    printf("  state                Show connection state\n");
    printf("  quit                 Disconnect and exit\n");
}

static void cmd_ptt(void)
{
    printf(">>> Starting PTT (1 second 440Hz tone)...\n");
    int rc = poc_ptt_start(g_ctx);
    if (rc != POC_OK) { printf(">>> PTT start failed: %d\n", rc); return; }

    /* Wait for grant */
    for (int w = 0; w < 50 && running; w++) { poc_poll(g_ctx, 0); usleep(20000); }

    for (int f = 0; f < 50 && running; f++) {
        int16_t pcm[160];
        for (int i = 0; i < 160; i++)
            pcm[i] = (int16_t)(16000.0 * sin(2.0 * M_PI * 440.0 * (f * 160 + i) / 8000.0));
        poc_ptt_send_audio(g_ctx, pcm, 160);
        poc_poll(g_ctx, 0);
        usleep(20000);
    }
    poc_ptt_stop(g_ctx);
    printf(">>> PTT done.\n");
}

static void cmd_msg(const char *args)
{
    uint32_t gid = 0;
    char text[256] = "";
    if (sscanf(args, "%u %255[^\n]", &gid, text) >= 2 && gid > 0) {
        int rc = poc_send_group_msg(g_ctx, gid, text);
        printf(">>> Message to group %u sent (%d)\n", gid, rc);
        return;
    }
    if (g_group_id == 0) {
        printf(">>> Usage: msg <group_id> <text>  or  msg <text> (if in a group)\n");
        return;
    }
    int rc = poc_send_group_msg(g_ctx, g_group_id, args);
    printf(">>> Message to group %u sent (%d)\n", g_group_id, rc);
}

static void cmd_dm(const char *args)
{
    uint32_t uid = 0;
    char text[256] = "";
    if (sscanf(args, "%u %255[^\n]", &uid, text) < 2)
        { printf(">>> Usage: dm <user_id> <text>\n"); return; }
    int rc = poc_send_user_msg(g_ctx, uid, text);
    printf(">>> DM to user %u sent (%d)\n", uid, rc);
}

static void process_line(const char *line)
{
    if (strcmp(line, "help") == 0 || strcmp(line, "?") == 0) {
        cmd_help();
    } else if (strcmp(line, "ptt") == 0) {
        cmd_ptt();
    } else if (strncmp(line, "msg ", 4) == 0) {
        cmd_msg(line + 4);
    } else if (strncmp(line, "dm ", 3) == 0) {
        cmd_dm(line + 3);
    } else if (strcmp(line, "groups") == 0) {
        poc_group_t grps[64];
        int n = poc_get_groups(g_ctx, grps, 64);
        printf("Groups (%d):\n", n);
        for (int i = 0; i < n; i++)
            printf("  [%u] %s%s\n", grps[i].id, grps[i].name,
                   grps[i].id == g_group_id ? " (active)" : "");
    } else if (strncmp(line, "join ", 5) == 0) {
        uint32_t gid = atoi(line + 5);
        if (gid == 0) { printf("Usage: join <group_id>\n"); return; }
        int rc = poc_enter_group(g_ctx, gid);
        if (rc == POC_OK) { g_group_id = gid; printf("Joined group %u\n", gid); }
        else printf("Join failed: %d\n", rc);
    } else if (strcmp(line, "leave") == 0) {
        poc_leave_group(g_ctx);
        g_group_id = 0;
        printf("Left group\n");
    } else if (strcmp(line, "sos") == 0) {
        printf("SOS sent (%d)\n", poc_send_sos(g_ctx, POC_ALERT_SOS));
    } else if (strcmp(line, "sos cancel") == 0) {
        printf("SOS cancel sent (%d)\n", poc_cancel_sos(g_ctx));
    } else if (strcmp(line, "state") == 0) {
        const char *names[] = {"OFFLINE", "CONNECTING", "ONLINE", "LOGOUT"};
        printf("State: %s  User ID: %u  Account: %s  Group: %u\n",
               names[poc_get_state(g_ctx)], poc_get_user_id(g_ctx),
               poc_get_account(g_ctx), g_group_id);
    } else if (strcmp(line, "quit") == 0 || strcmp(line, "q") == 0) {
        running = 0;
    } else {
        printf("Unknown command. Type 'help' for a list.\n");
    }
}

/* ── Main ───────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "vq")) != -1) {
        switch (opt) {
        case 'v': g_log_level = POC_LOG_DEBUG; break;
        case 'q': g_log_level = POC_LOG_ERROR; break;
        }
    }

    if (argc - optind < 3) {
        fprintf(stderr, "Usage: %s [-v|-q] <server[:port]> <account> <password> [group_id]\n", argv[0]);
        cmd_help();
        return 1;
    }

    poc_set_log_callback(cli_log, NULL);
    poc_set_log_level(g_log_level);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    char host[256];
    uint16_t port = 29999;
    snprintf(host, sizeof(host), "%s", argv[optind]);
    char *colon = strchr(host, ':');
    if (colon) { *colon = '\0'; port = atoi(colon + 1); }
    if (argc - optind > 3) g_group_id = atoi(argv[optind + 3]);

    poc_config_t cfg = {
        .server_host = host, .server_port = port,
        .account = argv[optind + 1], .password = argv[optind + 2],
        .codec = POC_CODEC_SPEEX,
    };

    poc_callbacks_t cb = {
        .on_state_change = on_state, .on_login_error = on_login_error,
        .on_ptt_start = on_ptt_start, .on_ptt_end = on_ptt_end,
        .on_audio_frame = on_audio, .on_ptt_granted = on_ptt_granted,
        .on_message = on_message, .on_groups_updated = on_groups,
        .on_user_status = on_user_status, .on_pull_to_group = on_pull,
        .on_tmp_group_invite = on_tmp_invite, .on_voice_message = on_voice_msg,
        .on_sos = on_sos_alert,
    };

    g_ctx = poc_create(&cfg, &cb);
    if (!g_ctx) { fprintf(stderr, "Failed to create context\n"); return 1; }

    printf("Connecting to %s:%u as %s...\n", host, port, argv[optind + 1]);
    int rc = poc_connect(g_ctx);
    if (rc != POC_OK) {
        fprintf(stderr, "Connect failed: %d\n", rc);
        poc_destroy(g_ctx);
        return 1;
    }

    /* Setup linenoise multiplexed (non-blocking) API */
    linenoiseSetCompletionCallback(completion);
    linenoiseHistorySetMaxLen(100);

    char lnbuf[512];
    struct linenoiseState ls;
    g_ls = &ls;
    linenoiseEditStart(&ls, STDIN_FILENO, STDOUT_FILENO, lnbuf, sizeof(lnbuf), "poc> ");

    while (running) {
        /* Poll stdin + poc events together */
        struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
        poll(&pfd, 1, 50);  /* 50ms — fast enough for audio, slow enough for idle */

        /* Drain poc events */
        poc_poll(g_ctx, 0);

        /* Process stdin if ready */
        if (pfd.revents & POLLIN) {
            char *line = linenoiseEditFeed(&ls);
            if (line == linenoiseEditMore) continue;

            /* Got a complete line (or NULL for EOF) */
            linenoiseEditStop(&ls);

            if (!line) { running = 0; break; }  /* Ctrl-D */
            if (line[0] != '\0') {
                linenoiseHistoryAdd(line);
                process_line(line);
                linenoiseFree(line);
            }

            if (running)
                linenoiseEditStart(&ls, STDIN_FILENO, STDOUT_FILENO,
                                   lnbuf, sizeof(lnbuf), "poc> ");
        }
    }

    linenoiseEditStop(&ls);
    g_ls = NULL;
    printf("\nDisconnecting...\n");
    poc_destroy(g_ctx);
    return 0;
}
