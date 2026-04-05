/*
 * poc_server — PoC protocol server example
 *
 * Uses the poc_server_t API from libpoc. The application provides
 * user/group configuration from an INI file and a linenoise console.
 * The library handles all protocol details.
 *
 * Usage: poc_server [-v|-q] [config.ini]
 */

#include "poc.h"
#include "poc_server.h"
#include "linenoise.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <poll.h>

static volatile int g_running = 1;
static int g_log_level = POC_LOG_INFO;
static struct linenoiseState *g_ls = NULL;
static poc_server_t *g_srv = NULL;

static void handle_sig(int s) { (void)s; g_running = 0; }

/* ── Logging ────────────────────────────────────────────────────── */

static void srv_log(int level, const char *msg, void *ud)
{
    (void)ud;
    static const char *tags[] = {"ERR", "WRN", "INF", "DBG"};
    const char *tag = (level >= 0 && level <= 3) ? tags[level] : "???";
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    if (g_ls) linenoiseHide(g_ls);
    fprintf(stderr, "[srv %02d:%02d:%02d.%03ld %s] %s\n",
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000, tag, msg);
    if (g_ls) linenoiseShow(g_ls);
}

/* ── Server callbacks ───────────────────────────────────────────── */

static void on_connect(poc_server_t *srv, uint32_t uid, const char *acct, void *ud)
{
    (void)srv; (void)ud;
    if (g_ls) linenoiseHide(g_ls);
    printf(">>> %s (user %u) connected\n", acct, uid);
    if (g_ls) linenoiseShow(g_ls);
}

static void on_disconnect(poc_server_t *srv, uint32_t uid, const char *acct, void *ud)
{
    (void)srv; (void)ud;
    if (g_ls) linenoiseHide(g_ls);
    printf(">>> %s (user %u) disconnected\n", acct, uid);
    if (g_ls) linenoiseShow(g_ls);
}

static void on_message(poc_server_t *srv, uint32_t from, uint32_t to,
                       const char *text, void *ud)
{
    (void)srv; (void)ud;
    if (g_ls) linenoiseHide(g_ls);
    printf(">>> MSG %u -> %u: %s\n", from, to, text);
    if (g_ls) linenoiseShow(g_ls);
}

static void on_sos(poc_server_t *srv, uint32_t uid, int type, void *ud)
{
    (void)srv; (void)ud;
    const char *names[] = {"SOS", "ManDown", "Fall", "CallAlarm"};
    if (g_ls) linenoiseHide(g_ls);
    printf(">>> *** %s from user %u ***\n", type < 4 ? names[type] : "ALERT", uid);
    if (g_ls) linenoiseShow(g_ls);
}

/* ── INI config loader ──────────────────────────────────────────── */

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        *end-- = '\0';
    return s;
}

static int load_config(poc_server_t *srv, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    char line[512], section[64] = "";
    uint32_t next_uid = 1000;

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (!*s || *s == ';' || *s == '#') continue;
        if (*s == '[') {
            char *e = strchr(s, ']');
            if (e) { *e = '\0'; snprintf(section, sizeof(section), "%s", s + 1); }
            continue;
        }
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(s), *val = trim(eq + 1);

        if (strcmp(section, "users") == 0) {
            poc_server_add_user(srv, &(poc_server_user_t){
                .account = key, .password = val, .user_id = next_uid++ });
        }
        else if (strcmp(section, "groups") == 0) {
            uint32_t gid = atoi(key);
            char *colon = strchr(val, ':');
            char name[64] = "";
            uint32_t members[32] = {0};
            int mcount = 0;
            (void)members; (void)mcount;

            if (colon) {
                *colon = '\0';
                snprintf(name, sizeof(name), "%s", trim(val));
                char *tok = strtok(trim(colon + 1), ",");
                while (tok && mcount < 32) {
                    /* Find user_id by account name */
                    /* Simple: assume user_ids start at 1000 in order */
                    char *acct = trim(tok);
                    /* poc_user_t clients[64]; — unused, config is simple */
                    /* We don't have a lookup — just use index-based IDs */
                    /* This is a limitation of the simple config format */
                    (void)acct;
                    tok = strtok(NULL, ",");
                }
            } else {
                snprintf(name, sizeof(name), "%s", val);
            }

            poc_server_add_group(srv, &(poc_server_group_t){
                .id = gid, .name = name, .member_ids = NULL, .member_count = 0
            });
        }
    }
    fclose(f);
    return 0;
}

/* ── Console commands ───────────────────────────────────────────── */

static const char *srv_cmds[] = {
    "clients", "groups", "users", "kick", "broadcast", "msg",
    "pull", "stun", "sos", "status", "shutdown", "help", NULL
};

static void srv_completion(const char *buf, linenoiseCompletions *lc)
{
    size_t len = strlen(buf);
    for (int i = 0; srv_cmds[i]; i++)
        if (strncmp(buf, srv_cmds[i], len) == 0)
            linenoiseAddCompletion(lc, srv_cmds[i]);
}

static void process_cmd(const char *line)
{
    if (strcmp(line, "clients") == 0) {
        poc_user_t clients[64];
        int n = poc_server_get_clients(g_srv, clients, 64);
        printf("Online clients (%d):\n", n);
        for (int i = 0; i < n; i++)
            printf("  [%u] %s\n", clients[i].id, clients[i].account);

    } else if (strcmp(line, "status") == 0) {
        printf("Online: %d clients\n", poc_server_client_count(g_srv));

    } else if (strncmp(line, "kick ", 5) == 0) {
        uint32_t uid = atoi(line + 5);
        printf("Kick %u: %s\n", uid, poc_server_kick(g_srv, uid) == POC_OK ? "ok" : "failed");

    } else if (strncmp(line, "stun ", 5) == 0) {
        uint32_t uid = atoi(line + 5);
        printf("Stun %u: %s\n", uid, poc_server_kick(g_srv, uid) == POC_OK ? "ok" : "failed");

    } else if (strncmp(line, "broadcast ", 10) == 0) {
        poc_server_broadcast(g_srv, line + 10);
        printf("Broadcast sent.\n");

    } else if (strncmp(line, "msg ", 4) == 0) {
        uint32_t target = 0; char text[256] = "";
        if (sscanf(line + 4, "%u %255[^\n]", &target, text) >= 2) {
            poc_server_send_message(g_srv, 0, target, text);
            printf("Message sent to %u.\n", target);
        } else printf("Usage: msg <uid|gid> <text>\n");

    } else if (strncmp(line, "pull ", 5) == 0) {
        uint32_t uid = 0, gid = 0;
        if (sscanf(line + 5, "%u %u", &uid, &gid) >= 2) {
            poc_server_pull_to_group(g_srv, uid, gid);
            printf("Pulled %u to group %u.\n", uid, gid);
        } else printf("Usage: pull <uid> <gid>\n");

    } else if (strncmp(line, "sos ", 4) == 0) {
        uint32_t uid = atoi(line + 4);
        poc_server_send_sos(g_srv, uid, 0);
        printf("SOS broadcast for user %u.\n", uid);

    } else if (strcmp(line, "shutdown") == 0 || strcmp(line, "quit") == 0) {
        g_running = 0;

    } else if (strcmp(line, "help") == 0 || strcmp(line, "?") == 0) {
        printf("Commands:\n");
        printf("  clients              Online clients\n");
        printf("  status               Server stats\n");
        printf("  kick <uid>           Disconnect user\n");
        printf("  stun <uid>           Force-exit user\n");
        printf("  broadcast <text>     Message all clients\n");
        printf("  msg <uid|gid> <text> Send message\n");
        printf("  pull <uid> <gid>     Force user into group\n");
        printf("  sos <uid>            Trigger SOS\n");
        printf("  shutdown             Stop server\n");

    } else {
        printf("Unknown command. Type 'help'.\n");
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
    const char *config = (optind < argc) ? argv[optind] : "poc_server.conf.ini";

    poc_set_log_callback(srv_log, NULL);
    poc_set_log_level(g_log_level);

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);
    signal(SIGPIPE, SIG_IGN);
    srandom(time(NULL));

    poc_server_config_t cfg = { .port = 29999 };
    poc_server_callbacks_t cb = {
        .on_client_connect = on_connect,
        .on_client_disconnect = on_disconnect,
        .on_message = on_message,
        .on_sos = on_sos,
    };

    g_srv = poc_server_create(&cfg, &cb);
    if (!g_srv) { fprintf(stderr, "Failed to create server\n"); return 1; }

    if (load_config(g_srv, config) < 0) {
        poc_server_destroy(g_srv);
        return 1;
    }

    if (poc_server_start(g_srv) != POC_OK) {
        poc_server_destroy(g_srv);
        return 1;
    }

    /* Console */
    linenoiseSetCompletionCallback(srv_completion);
    linenoiseHistorySetMaxLen(50);
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);

    char lnbuf[512];
    struct linenoiseState ls;
    g_ls = &ls;
    linenoiseEditStart(&ls, STDIN_FILENO, STDOUT_FILENO, lnbuf, sizeof(lnbuf), "srv> ");

    printf("Type 'help' for commands.\n");

    while (g_running) {
        struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
        poll(&pfd, 1, 50);

        poc_server_poll(g_srv, 0);

        if (pfd.revents & POLLIN) {
            char *line = linenoiseEditFeed(&ls);
            if (line == linenoiseEditMore) continue;
            linenoiseEditStop(&ls);
            if (line) {
                if (line[0]) { linenoiseHistoryAdd(line); process_cmd(line); }
                linenoiseFree(line);
            } else { g_running = 0; }
            if (g_running)
                linenoiseEditStart(&ls, STDIN_FILENO, STDOUT_FILENO, lnbuf, sizeof(lnbuf), "srv> ");
        }
    }

    linenoiseEditStop(&ls);
    g_ls = NULL;
    printf("\nShutting down...\n");
    poc_server_destroy(g_srv);
    return 0;
}
