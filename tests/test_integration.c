/*
 * test_integration.c — Server + client loopback integration tests
 *
 * Spins up a poc_server on 127.0.0.1, connects one or more poc_ctx
 * clients, and exercises the full protocol stack: login handshake,
 * group operations, PTT floor arbitration, audio roundtrip, and
 * text messaging.
 *
 * All tests run single-threaded — the I/O threads handle networking
 * while the test drives both server and client poll loops.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "poc.h"
#include "poc_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

/* ── Test harness (same as test_main.c) ────────────────────────── */

static int g_total, g_passed, g_failed, g_in_test;

static void test_begin(const char *name)
{
    int extra = 0;
    for (const char *p = name; *p; p++)
        if ((*p & 0xC0) == 0x80) extra++;
    printf("  %-*s ", 55 + extra, name);
    g_total++;
    g_in_test = 1;
}

static void test_pass(void)
{
    if (!g_in_test) return;
    printf("PASS\n");
    g_passed++;
    g_in_test = 0;
}

static void test_fail(const char *msg)
{
    if (!g_in_test) return;
    printf("FAIL: %s\n", msg);
    g_failed++;
    g_in_test = 0;
}

static void test_assert(int cond, const char *msg)
{
    if (cond) test_pass(); else test_fail(msg);
}

static void test_end(void)
{
    if (g_in_test) test_pass();
}

/* ── Test port allocation ──────────────────────────────────────── */

static uint16_t g_next_port = 39000;

static uint16_t next_port(void) { return g_next_port++; }

/* ── Polling helper ────────────────────────────────────────────── */

/*
 * Drive both server and client poll loops for up to timeout_ms.
 * Returns 0 if check() becomes true, -1 on timeout.
 */
static int poll_until(poc_ctx_t *cli, poc_server_t *srv,
                      int (*check)(void *ud), void *ud, int timeout_ms)
{
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 10) {
        if (srv) poc_server_poll(srv, 0);
        if (cli) poc_poll(cli, 0);
        if (check && check(ud)) return 0;
        usleep(10000);  /* 10ms */
    }
    return -1;
}

/* Drive two clients + server */
static int poll_until2(poc_ctx_t *c1, poc_ctx_t *c2, poc_server_t *srv,
                       int (*check)(void *ud), void *ud, int timeout_ms)
{
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 10) {
        if (srv) poc_server_poll(srv, 0);
        if (c1) poc_poll(c1, 0);
        if (c2) poc_poll(c2, 0);
        if (check && check(ud)) return 0;
        usleep(10000);
    }
    return -1;
}

/* ── Callback state capture ────────────────────────────────────── */

typedef struct {
    poc_state_t state;
    int         login_error_code;
    int         ptt_granted;    /* 1=granted, 0=denied, -1=no callback */
    int         ptt_start_count;
    int         ptt_end_count;
    int         audio_frame_count;
    int         audio_total_samples;
    int         message_count;
    char        last_message[256];
    uint32_t    last_message_from;
    int         groups_updated;
    int         group_count;
} client_state_t;

static void cb_state_change(poc_ctx_t *ctx, poc_state_t state, void *ud)
{
    (void)ctx;
    client_state_t *s = (client_state_t *)ud;
    s->state = state;
}

static void cb_login_error(poc_ctx_t *ctx, int code, const char *msg, void *ud)
{
    (void)ctx; (void)msg;
    client_state_t *s = (client_state_t *)ud;
    s->login_error_code = code;
}

static void cb_ptt_granted(poc_ctx_t *ctx, bool granted, void *ud)
{
    (void)ctx;
    client_state_t *s = (client_state_t *)ud;
    s->ptt_granted = granted ? 1 : 0;
}

static void cb_ptt_start(poc_ctx_t *ctx, uint32_t speaker_id,
                         const char *name, uint32_t group_id, void *ud)
{
    (void)ctx; (void)speaker_id; (void)name; (void)group_id;
    client_state_t *s = (client_state_t *)ud;
    s->ptt_start_count++;
}

static void cb_ptt_end(poc_ctx_t *ctx, uint32_t speaker_id,
                       uint32_t group_id, void *ud)
{
    (void)ctx; (void)speaker_id; (void)group_id;
    client_state_t *s = (client_state_t *)ud;
    s->ptt_end_count++;
}

static void cb_audio_frame(poc_ctx_t *ctx, const poc_audio_frame_t *frame, void *ud)
{
    (void)ctx;
    client_state_t *s = (client_state_t *)ud;
    s->audio_frame_count++;
    s->audio_total_samples += frame->n_samples;
}

static void cb_message(poc_ctx_t *ctx, uint32_t from_id, const char *text, void *ud)
{
    (void)ctx;
    client_state_t *s = (client_state_t *)ud;
    s->message_count++;
    s->last_message_from = from_id;
    snprintf(s->last_message, sizeof(s->last_message), "%s", text);
}

static void cb_groups_updated(poc_ctx_t *ctx, const poc_group_t *groups,
                              int count, void *ud)
{
    (void)ctx; (void)groups;
    client_state_t *s = (client_state_t *)ud;
    s->groups_updated++;
    s->group_count = count;
}

static poc_callbacks_t make_callbacks(client_state_t *s)
{
    memset(s, 0, sizeof(*s));
    s->ptt_granted = -1;
    return (poc_callbacks_t){
        .on_state_change  = cb_state_change,
        .on_login_error   = cb_login_error,
        .on_ptt_granted   = cb_ptt_granted,
        .on_ptt_start     = cb_ptt_start,
        .on_ptt_end       = cb_ptt_end,
        .on_audio_frame   = cb_audio_frame,
        .on_message        = cb_message,
        .on_groups_updated = cb_groups_updated,
        .userdata          = s,
    };
}

/* ── Server callback state ─────────────────────────────────────── */

typedef struct {
    int connect_count;
    int disconnect_count;
    int message_count;
    int audio_frame_count;
} server_state_t;

static void srv_cb_connect(poc_server_t *srv, uint32_t uid,
                           const char *account, void *ud)
{
    (void)srv; (void)uid; (void)account;
    server_state_t *s = (server_state_t *)ud;
    s->connect_count++;
}

static void srv_cb_disconnect(poc_server_t *srv, uint32_t uid,
                              const char *account, void *ud)
{
    (void)srv; (void)uid; (void)account;
    server_state_t *s = (server_state_t *)ud;
    s->disconnect_count++;
}

static void srv_cb_message(poc_server_t *srv, uint32_t from_id,
                           uint32_t target_id, const char *text, void *ud)
{
    (void)srv; (void)from_id; (void)target_id; (void)text;
    server_state_t *s = (server_state_t *)ud;
    s->message_count++;
}

static void srv_cb_audio(poc_server_t *srv, uint32_t speaker_id,
                         uint32_t group_id, const int16_t *pcm,
                         int n_samples, void *ud)
{
    (void)srv; (void)speaker_id; (void)group_id; (void)pcm; (void)n_samples;
    server_state_t *s = (server_state_t *)ud;
    s->audio_frame_count++;
}

/* ── Fixture: server + optional clients ────────────────────────── */

typedef struct {
    poc_server_t    *srv;
    server_state_t   srv_state;
    uint16_t         port;
} test_server_t;

static test_server_t create_test_server(void)
{
    test_server_t t;
    memset(&t, 0, sizeof(t));
    t.port = next_port();

    poc_server_config_t cfg = { .bind_addr = "127.0.0.1", .port = t.port };
    poc_server_callbacks_t cb = {
        .on_client_connect    = srv_cb_connect,
        .on_client_disconnect = srv_cb_disconnect,
        .on_message           = srv_cb_message,
        .on_audio             = srv_cb_audio,
        .userdata             = &t.srv_state,
    };
    t.srv = poc_server_create(&cfg, &cb);
    poc_server_add_user(t.srv, &(poc_server_user_t){
        .account = "alice", .password = "secret", .name = "Alice", .user_id = 1000 });
    poc_server_add_user(t.srv, &(poc_server_user_t){
        .account = "bob", .password = "secret", .name = "Bob", .user_id = 2000 });
    poc_server_add_group(t.srv, &(poc_server_group_t){
        .id = 100, .name = "Dispatch", .member_ids = NULL, .member_count = 0 });
    poc_server_start(t.srv);
    return t;
}

static void destroy_test_server(test_server_t *t)
{
    poc_server_destroy(t->srv);
    t->srv = NULL;
}

static poc_ctx_t *connect_client(test_server_t *t, const char *account,
                                 client_state_t *cs, poc_callbacks_t *cb)
{
    *cb = make_callbacks(cs);
    poc_config_t cfg = {
        .server_host = "127.0.0.1",
        .server_port = t->port,
        .account     = account,
        .password    = "secret",
    };
    poc_ctx_t *ctx = poc_create(&cfg, cb);
    poc_connect(ctx);
    return ctx;
}

/* ── Check helpers ─────────────────────────────────────────────── */

static client_state_t *g_check_cs;
static server_state_t *g_check_ss;
static int g_check_target;

static int check_client_online(void *ud)
{
    (void)ud;
    return g_check_cs->state == POC_STATE_ONLINE;
}

static int check_client_offline(void *ud)
{
    (void)ud;
    return g_check_cs->state == POC_STATE_OFFLINE;
}

static int check_ptt_granted(void *ud)
{
    (void)ud;
    return g_check_cs->ptt_granted >= 0;
}

static int check_message_received(void *ud)
{
    (void)ud;
    return g_check_cs->message_count >= g_check_target;
}

static int check_audio_received(void *ud)
{
    (void)ud;
    return g_check_cs->audio_frame_count >= g_check_target;
}

static int check_srv_connect(void *ud)
{
    (void)ud;
    return g_check_ss->connect_count >= g_check_target;
}

/* ── Tests ─────────────────────────────────────────────────────── */

static void test_login_success(void)
{
    test_begin("login: successful handshake");
    test_server_t t = create_test_server();
    client_state_t cs; poc_callbacks_t cb;
    poc_ctx_t *cli = connect_client(&t, "alice", &cs, &cb);

    g_check_cs = &cs;
    int rc = poll_until(cli, t.srv, check_client_online, NULL, 5000);
    test_assert(rc == 0 && cs.state == POC_STATE_ONLINE, "client should reach ONLINE");

    poc_destroy(cli);
    destroy_test_server(&t);
}

static void test_server_sees_client(void)
{
    test_begin("login: server sees connected client");
    test_server_t t = create_test_server();
    client_state_t cs; poc_callbacks_t cb;
    poc_ctx_t *cli = connect_client(&t, "alice", &cs, &cb);

    g_check_cs = &cs;
    poll_until(cli, t.srv, check_client_online, NULL, 5000);

    test_assert(poc_server_client_count(t.srv) >= 1, "on_client_connect should fire");

    poc_destroy(cli);
    destroy_test_server(&t);
}

static void test_login_invalid_password(void)
{
    test_begin("login: invalid password rejected");
    test_server_t t = create_test_server();
    client_state_t cs;
    poc_callbacks_t cb = make_callbacks(&cs);
    poc_config_t cfg = {
        .server_host = "127.0.0.1", .server_port = t.port,
        .account = "alice", .password = "wrongpassword",
    };
    poc_ctx_t *cli = poc_create(&cfg, &cb);
    poc_connect(cli);

    g_check_cs = &cs;
    poll_until(cli, t.srv, check_client_offline, NULL, 5000);
    test_assert(cs.login_error_code != 0, "should get login error");

    poc_destroy(cli);
    destroy_test_server(&t);
}

static void test_groups_received(void)
{
    test_begin("login: groups received after login");
    test_server_t t = create_test_server();
    client_state_t cs; poc_callbacks_t cb;
    poc_ctx_t *cli = connect_client(&t, "alice", &cs, &cb);

    g_check_cs = &cs;
    poll_until(cli, t.srv, check_client_online, NULL, 5000);
    test_assert(cs.groups_updated > 0 && cs.group_count >= 1, "should receive groups");

    poc_destroy(cli);
    destroy_test_server(&t);
}

static void test_enter_group(void)
{
    test_begin("group: enter group succeeds");
    test_server_t t = create_test_server();
    client_state_t cs; poc_callbacks_t cb;
    poc_ctx_t *cli = connect_client(&t, "alice", &cs, &cb);

    g_check_cs = &cs;
    poll_until(cli, t.srv, check_client_online, NULL, 5000);

    int rc = poc_enter_group(cli, 100);
    test_assert(rc == POC_OK, "enter_group should return OK");

    poc_destroy(cli);
    destroy_test_server(&t);
}

static void test_ptt_grant(void)
{
    test_begin("ptt: floor granted when free");
    test_server_t t = create_test_server();
    client_state_t cs; poc_callbacks_t cb;
    poc_ctx_t *cli = connect_client(&t, "alice", &cs, &cb);

    g_check_cs = &cs;
    poll_until(cli, t.srv, check_client_online, NULL, 5000);
    poc_enter_group(cli, 100);
    poll_until(cli, t.srv, NULL, NULL, 200);  /* let group enter propagate */

    poc_ptt_start(cli);
    poll_until(cli, t.srv, check_ptt_granted, NULL, 3000);
    test_assert(cs.ptt_granted == 1, "PTT should be granted");

    poc_ptt_stop(cli);
    poc_destroy(cli);
    destroy_test_server(&t);
}

static void test_ptt_denied_floor_busy(void)
{
    test_begin("ptt: floor denied when busy");
    test_server_t t = create_test_server();

    client_state_t cs1, cs2;
    poc_callbacks_t cb1, cb2;
    poc_ctx_t *alice = connect_client(&t, "alice", &cs1, &cb1);
    poc_ctx_t *bob   = connect_client(&t, "bob",   &cs2, &cb2);

    /* Wait for both online */
    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);

    /* Both enter same group */
    poc_enter_group(alice, 100);
    poc_enter_group(bob, 100);
    poll_until2(alice, bob, t.srv, NULL, NULL, 300);

    /* Alice takes floor */
    poc_ptt_start(alice);
    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 3000);

    /* Bob requests floor — should be denied */
    poc_ptt_start(bob);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 3000);
    test_assert(cs2.ptt_granted == 0, "Bob PTT should be denied");

    poc_ptt_stop(alice);
    poc_destroy(alice);
    poc_destroy(bob);
    destroy_test_server(&t);
}

static void test_audio_roundtrip(void)
{
    test_begin("audio: frames reach listener");
    test_server_t t = create_test_server();

    client_state_t cs1, cs2;
    poc_callbacks_t cb1, cb2;
    poc_ctx_t *alice = connect_client(&t, "alice", &cs1, &cb1);
    poc_ctx_t *bob   = connect_client(&t, "bob",   &cs2, &cb2);

    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);

    poc_enter_group(alice, 100);
    poc_enter_group(bob, 100);
    poll_until2(alice, bob, t.srv, NULL, NULL, 300);

    /* Alice starts PTT and sends audio */
    poc_ptt_start(alice);
    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 3000);

    /* Let PTT start propagate to Bob so ptt_rx_active is set */
    poll_until2(alice, bob, t.srv, NULL, NULL, 500);

    /* Generate and send 20 frames of 1kHz tone */
    int16_t tone[160];
    for (int i = 0; i < 160; i++)
        tone[i] = (int16_t)(8000.0 * sin(2.0 * 3.14159265 * 1000.0 * i / 8000.0));

    for (int f = 0; f < 20; f++) {
        poc_ptt_send_audio(alice, tone, 160);
        poll_until2(alice, bob, t.srv, NULL, NULL, 50);
    }

    /* Wait for Bob to receive some audio */
    g_check_cs = &cs2;
    g_check_target = 1;
    poll_until2(alice, bob, t.srv, check_audio_received, NULL, 5000);
    test_assert(cs2.audio_frame_count > 0, "Bob should receive audio frames");

    poc_ptt_stop(alice);
    poc_destroy(alice);
    poc_destroy(bob);
    destroy_test_server(&t);
}

static void test_group_message(void)
{
    test_begin("messaging: group message delivered");
    test_server_t t = create_test_server();

    client_state_t cs1, cs2;
    poc_callbacks_t cb1, cb2;
    poc_ctx_t *alice = connect_client(&t, "alice", &cs1, &cb1);
    poc_ctx_t *bob   = connect_client(&t, "bob",   &cs2, &cb2);

    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);

    poc_enter_group(alice, 100);
    poc_enter_group(bob, 100);
    poll_until2(alice, bob, t.srv, NULL, NULL, 300);

    poc_send_group_msg(alice, 100, "hello group");

    g_check_cs = &cs2;
    g_check_target = 1;
    poll_until2(alice, bob, t.srv, check_message_received, NULL, 3000);
    test_assert(cs2.message_count >= 1, "Bob should receive message");
    test_assert(strcmp(cs2.last_message, "hello group") == 0, "message text should match");

    poc_destroy(alice);
    poc_destroy(bob);
    destroy_test_server(&t);
}

static void test_disconnect(void)
{
    test_begin("disconnect: clean disconnect");
    test_server_t t = create_test_server();
    client_state_t cs; poc_callbacks_t cb;
    poc_ctx_t *cli = connect_client(&t, "alice", &cs, &cb);

    g_check_cs = &cs;
    poll_until(cli, t.srv, check_client_online, NULL, 5000);

    poc_disconnect(cli);
    test_assert(poc_get_state(cli) == POC_STATE_OFFLINE, "should be OFFLINE");

    poc_destroy(cli);
    destroy_test_server(&t);
}

static void test_server_client_count(void)
{
    test_begin("server: client count tracks connections");
    test_server_t t = create_test_server();

    client_state_t cs1, cs2;
    poc_callbacks_t cb1, cb2;
    poc_ctx_t *alice = connect_client(&t, "alice", &cs1, &cb1);

    g_check_cs = &cs1;
    poll_until(alice, t.srv, check_client_online, NULL, 5000);
    test_assert(poc_server_client_count(t.srv) == 1, "1 client");

    poc_ctx_t *bob = connect_client(&t, "bob", &cs2, &cb2);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);
    test_assert(poc_server_client_count(t.srv) == 2, "2 clients");

    poc_destroy(alice);
    poll_until(bob, t.srv, NULL, NULL, 500);
    /* After alice disconnects, server should have 1 client */
    test_assert(poc_server_client_count(t.srv) <= 1, "back to <=1 after disconnect");

    poc_destroy(bob);
    destroy_test_server(&t);
}

static void test_user_id_assigned(void)
{
    test_begin("login: user_id assigned after login");
    test_server_t t = create_test_server();
    client_state_t cs; poc_callbacks_t cb;
    poc_ctx_t *cli = connect_client(&t, "alice", &cs, &cb);

    g_check_cs = &cs;
    poll_until(cli, t.srv, check_client_online, NULL, 5000);

    uint32_t uid = poc_get_user_id(cli);
    test_assert(uid == 1000, "alice should get user_id 1000");

    poc_destroy(cli);
    destroy_test_server(&t);
}

static void test_ptt_stop_releases_floor(void)
{
    test_begin("ptt: stop releases floor for next user");
    test_server_t t = create_test_server();

    client_state_t cs1, cs2;
    poc_callbacks_t cb1, cb2;
    poc_ctx_t *alice = connect_client(&t, "alice", &cs1, &cb1);
    poc_ctx_t *bob   = connect_client(&t, "bob",   &cs2, &cb2);

    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);

    poc_enter_group(alice, 100);
    poc_enter_group(bob, 100);
    poll_until2(alice, bob, t.srv, NULL, NULL, 1000);

    /* Alice takes floor */
    cs1.ptt_granted = -1;
    poc_ptt_start(alice);
    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 5000);

    /* Alice releases floor */
    poc_ptt_stop(alice);
    /* We need Alice's END_PTT to reach server and clear the floor.
     * Also Bob needs to see PTT_END notification. Poll generously. */
    poll_until2(alice, bob, t.srv, NULL, NULL, 2000);

    /* Bob requests floor — should succeed now */
    cs2.ptt_granted = -1;
    poc_ptt_start(bob);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 5000);
    test_assert(cs2.ptt_granted == 1, "Bob should get floor after Alice releases");

    poc_ptt_stop(bob);
    poc_destroy(alice);
    poc_destroy(bob);
    destroy_test_server(&t);
}

/* ── Priority pre-emption helper ───────────────────────────────── */

static test_server_t create_priority_server(void)
{
    test_server_t t;
    memset(&t, 0, sizeof(t));
    t.port = next_port();

    poc_server_config_t cfg = { .bind_addr = "127.0.0.1", .port = t.port };
    poc_server_callbacks_t cb = {
        .on_client_connect    = srv_cb_connect,
        .on_client_disconnect = srv_cb_disconnect,
        .on_message           = srv_cb_message,
        .on_audio             = srv_cb_audio,
        .userdata             = &t.srv_state,
    };
    t.srv = poc_server_create(&cfg, &cb);
    /* Alice: normal priority (0), Bob: high priority (10) */
    poc_server_add_user(t.srv, &(poc_server_user_t){
        .account = "alice", .password = "secret", .name = "Alice",
        .user_id = 1000, .priority = 0 });
    poc_server_add_user(t.srv, &(poc_server_user_t){
        .account = "bob", .password = "secret", .name = "Bob",
        .user_id = 2000, .priority = 10 });
    poc_server_add_group(t.srv, &(poc_server_group_t){
        .id = 100, .name = "Dispatch", .member_ids = NULL, .member_count = 0 });
    poc_server_start(t.srv);
    return t;
}

static void test_ptt_preemption(void)
{
    test_begin("ptt: high-priority pre-empts low-priority");
    test_server_t t = create_priority_server();

    client_state_t cs1, cs2;
    poc_callbacks_t cb1, cb2;
    poc_ctx_t *alice = connect_client(&t, "alice", &cs1, &cb1);  /* pri=0 */
    poc_ctx_t *bob   = connect_client(&t, "bob",   &cs2, &cb2);  /* pri=10 */

    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);

    poc_enter_group(alice, 100);
    poc_enter_group(bob, 100);
    poll_until2(alice, bob, t.srv, NULL, NULL, 1000);

    /* Alice (pri=0) takes floor */
    cs1.ptt_granted = -1;
    poc_ptt_start(alice);
    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 5000);
    test_assert(cs1.ptt_granted == 1, "Alice should get floor (free)");

    /* Bob (pri=10) requests — should pre-empt Alice */
    cs2.ptt_granted = -1;
    poc_ptt_start(bob);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 5000);
    test_assert(cs2.ptt_granted == 1, "Bob should pre-empt Alice");

    poc_ptt_stop(bob);
    poc_destroy(alice);
    poc_destroy(bob);
    destroy_test_server(&t);
}

static void test_ptt_no_preempt_equal(void)
{
    test_begin("ptt: equal priority cannot pre-empt");
    test_server_t t = create_test_server();  /* both pri=0 */

    client_state_t cs1, cs2;
    poc_callbacks_t cb1, cb2;
    poc_ctx_t *alice = connect_client(&t, "alice", &cs1, &cb1);
    poc_ctx_t *bob   = connect_client(&t, "bob",   &cs2, &cb2);

    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_client_online, NULL, 5000);

    poc_enter_group(alice, 100);
    poc_enter_group(bob, 100);
    poll_until2(alice, bob, t.srv, NULL, NULL, 1000);

    /* Alice takes floor */
    cs1.ptt_granted = -1;
    poc_ptt_start(alice);
    g_check_cs = &cs1;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 5000);

    /* Bob (same priority) should be denied */
    cs2.ptt_granted = -1;
    poc_ptt_start(bob);
    g_check_cs = &cs2;
    poll_until2(alice, bob, t.srv, check_ptt_granted, NULL, 5000);
    test_assert(cs2.ptt_granted == 0, "equal priority should not pre-empt");

    poc_ptt_stop(alice);
    poc_destroy(alice);
    poc_destroy(bob);
    destroy_test_server(&t);
}

/* ── Entry point ───────────────────────────────────────────────── */

int main(void)
{
    printf("libpoc integration test suite\n");
    printf("==============================\n\n");

    printf("Login & connection:\n");
    test_login_success();
    test_server_sees_client();
    test_login_invalid_password();
    test_user_id_assigned();
    test_groups_received();
    test_disconnect();
    test_server_client_count();

    printf("\nGroup operations:\n");
    test_enter_group();

    printf("\nPTT floor arbitration:\n");
    test_ptt_grant();
    test_ptt_denied_floor_busy();
    test_ptt_stop_releases_floor();
    test_ptt_preemption();
    test_ptt_no_preempt_equal();

    printf("\nAudio:\n");
    test_audio_roundtrip();

    printf("\nMessaging:\n");
    test_group_message();

    printf("\n==============================\n");
    printf("Results: %d/%d passed", g_passed, g_total);
    if (g_failed > 0)
        printf(", %d FAILED", g_failed);
    printf("\n");

    return g_failed > 0 ? 1 : 0;
}
