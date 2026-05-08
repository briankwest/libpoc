/*
 * poc_proto.h — PoC protocol constants (shared between library and server)
 *
 * MS-frame wire format, command types, and protocol parameters.
 */

#ifndef POC_PROTO_H
#define POC_PROTO_H

/* ── MS-frame header ────────────────────────────────────────────── */

#define POC_MS_MAGIC_0       0x4D   /* 'M' */
#define POC_MS_MAGIC_1       0x53   /* 'S' */
#define POC_MS_HDR_LEN       4      /* 2 magic + 2 length */

/* ── Client → Server command types (byte at offset 5) ───────────── */

#define POC_CMD_LOGIN                0x01
#define POC_CMD_VALIDATE             0x04
#define POC_CMD_HEARTBEAT            0x06
#define POC_CMD_ENTER_GROUP          0x11
#define POC_CMD_INVITE_TMP           0x13
#define POC_CMD_ENTER_TMP            0x15
#define POC_CMD_LEAVE_GROUP          0x17  /* also leave temp group */
#define POC_CMD_REJECT_TMP           0x19
#define POC_CMD_MOD_STATUS           0x25
#define POC_CMD_FORCE_EXIT           0x2D
#define POC_CMD_EXT_DATA             0x43
#define POC_CMD_PULL_TO_GROUP        0x4D
#define POC_CMD_START_PTT            0x5D
#define POC_CMD_END_PTT              0x5E
#define POC_CMD_START_PTT_ALT        0x66
#define POC_CMD_END_PTT_ALT          0x67
#define POC_CMD_NOTE_INCOME          0x70
#define POC_CMD_VOICE_INCOME         0x72
#define POC_CMD_VOICE_MESSAGE        0x73
#define POC_CMD_REGISTER_PUSH_TOKEN  0x90  /* libpoc 1.1+ extension */

/* ── Server → Client notification types (byte at offset 1) ──────── */

#define POC_NOTIFY_RESPONSE          0x01
#define POC_NOTIFY_HEARTBEAT         0x06
#define POC_NOTIFY_CHALLENGE         0x07
#define POC_NOTIFY_USER_DATA         0x0B
#define POC_NOTIFY_START_PTT         0x0D
#define POC_NOTIFY_END_PTT           0x0F
#define POC_NOTIFY_ENTER_GROUP       0x11
#define POC_NOTIFY_INVITE_TMP        0x13
#define POC_NOTIFY_ENTER_TMP         0x15
#define POC_NOTIFY_LEAVE_TMP         0x17
#define POC_NOTIFY_REJECT_TMP        0x19
#define POC_NOTIFY_PKG_ACK           0x1D
#define POC_NOTIFY_MOD_NAME          0x1F
#define POC_NOTIFY_MOD_DEF_GRP       0x21
#define POC_NOTIFY_MOD_STATUS        0x25
#define POC_NOTIFY_MOD_PRIV          0x27
#define POC_NOTIFY_MOD_PRIORITY      0x29
#define POC_NOTIFY_REMOVE_USER       0x2B
#define POC_NOTIFY_FORCE_EXIT        0x2D
#define POC_NOTIFY_ADD_GROUP         0x33
#define POC_NOTIFY_DEL_GROUP         0x35
#define POC_NOTIFY_GRP_MOD_NAME      0x37
#define POC_NOTIFY_GRP_MOD_MSTR      0x39
#define POC_NOTIFY_GRP_ADD_USER      0x3B
#define POC_NOTIFY_GRP_DEL_USER      0x3D
#define POC_NOTIFY_EXT_DATA          0x43
#define POC_NOTIFY_PULL_TO_GROUP     0x4D
#define POC_NOTIFY_START_PTT_PRI     0x5D
#define POC_NOTIFY_END_PTT_PRI       0x5E
#define POC_NOTIFY_START_PTT_ALT     0x66
#define POC_NOTIFY_END_PTT_ALT       0x67
#define POC_NOTIFY_NOTE_INCOME       0x70
#define POC_NOTIFY_VOICE_INCOME      0x72
#define POC_NOTIFY_VOICE_MESSAGE     0x73
#define POC_NOTIFY_RECV_CONTENT      0x80
#define POC_NOTIFY_RECV_MCAST        0x84

/* ── UDP voice packet ───────────────────────────────────────────── */

#define POC_UDP_HDR_LEN       8    /* 2 seq + 4 sender + 1 pad + 1 type */

/* ── SOS markers inside EXT_DATA ────────────────────────────────── */

#define POC_SOS_MARKER        0xFF
#define POC_SOS_CANCEL_MARKER 0xFE

/* ── Default port ───────────────────────────────────────────────── */

#define POC_DEFAULT_PORT      29999

#endif /* POC_PROTO_H */
