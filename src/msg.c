#include "msg.h"
#include "net.h"   // net_send_all, net_recv_exact
#include "util.h" // read_u32_le, write_u32_le

#include <stdlib.h>
#include <string.h>
#include <limits.h>

int msg_send(int fd, uint8_t type,
             const uint8_t *payload, size_t payload_len)
{
    // frame_len includes type+version+payload
    size_t frame_len_sz = MSG_FRAME_HDR_SIZE + payload_len;

    if (frame_len_sz > MSG_MAX_FRAME_LEN) {
        return -1;
    }

    // total on wire = 4 + frame_len
    size_t total = 4 + frame_len_sz;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return -1;

    // length prefix
    write_u32_le(buf, (uint32_t)frame_len_sz);

    // frame header
    buf[4] = type;
    buf[5] = MSG_VERSION;

    // payload
    if (payload_len > 0 && payload) {
        memcpy(buf + 4 + MSG_FRAME_HDR_SIZE, payload, payload_len);
    }

    int rc = net_send_all(fd, buf, total);
    free(buf);
    return rc;
}

MsgResult msg_recv(int fd, uint8_t *type_out, uint8_t *version_out,
                   uint8_t **payload_out, size_t *payload_len_out)
{
    if (!type_out || !version_out || !payload_out || !payload_len_out) {
        return MSG_ERR;
    }

    *payload_out = NULL;
    *payload_len_out = 0;

    // Read length prefix
    uint8_t len_buf[4];
    int r = net_recv_exact(fd, len_buf, sizeof(len_buf));
    if (r == 1) return MSG_EOF;  // clean disconnect
    if (r != 0) return MSG_ERR;

    uint32_t frame_len = read_u32_le(len_buf);

    if (frame_len < MSG_FRAME_HDR_SIZE) {
        return MSG_ERR;
    }
    if (frame_len > MSG_MAX_FRAME_LEN) {
        return MSG_TOOLARGE;
    }

    // Read rest of frame (type+version+payload)
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame) return MSG_ERR;

    r = net_recv_exact(fd, frame, frame_len);
    if (r == 1) {
        free(frame);
        return MSG_EOF;
    }
    if (r != 0) {
        free(frame);
        return MSG_ERR;
    }

    uint8_t type = frame[0];
    uint8_t ver  = frame[1];

    // Payload is remaining bytes
    size_t payload_len = (size_t)frame_len - MSG_FRAME_HDR_SIZE;

    uint8_t *payload = NULL;
    if (payload_len > 0) {
        payload = (uint8_t *)malloc(payload_len);
        if (!payload) {
            free(frame);
            return MSG_ERR;
        }
        memcpy(payload, frame + MSG_FRAME_HDR_SIZE, payload_len);
    }

    free(frame);

    *type_out = type;
    *version_out = ver;
    *payload_out = payload;          // may be NULL if payload_len == 0
    *payload_len_out = payload_len;

    return MSG_OK;
}

int msg_build_entry_payload(uint8_t **payload_out, size_t *payload_len_out,
                            const uint8_t *entry_bytes, size_t entry_len)
{
    if (!payload_out || !payload_len_out || (!entry_bytes && entry_len > 0))
        return -1;

    if (entry_len == 0 || entry_len > MSG_MAX_ENTRY_BYTES)
        return -1;

    size_t total = 4 + entry_len;
    uint8_t *p = (uint8_t *)malloc(total);
    if (!p) return -1;

    write_u32_le(p, (uint32_t)entry_len);
    memcpy(p + 4, entry_bytes, entry_len);

    *payload_out = p;
    *payload_len_out = total;
    return 0;
}

int msg_parse_entry_payload(const uint8_t *payload, size_t payload_len,
                            const uint8_t **entry_bytes_out, size_t *entry_len_out)
{
    if (!payload || !entry_bytes_out || !entry_len_out)
        return -1;

    if (payload_len < 4) return -1;

    uint32_t entry_len = read_u32_le(payload);
    if (entry_len == 0 || entry_len > MSG_MAX_ENTRY_BYTES) return -1;

    if ((size_t)entry_len != payload_len - 4) return -1;

    *entry_len_out = (size_t)entry_len;
    *entry_bytes_out = payload + 4;
    return 0;
}

int msg_build_submit_payload(uint8_t **payload_out, size_t *payload_len_out,
                             uint32_t event_type, uint32_t player_id,
                             const char *desc, uint16_t desc_len,
                             uint64_t client_nonce)
{
    if (!payload_out || !payload_len_out) return -1;

    if (desc_len > 0 && !desc) return -1;
    if (desc_len > MSG_MAX_DESC_LEN) return -1;

    // Layout: 4 + 4 + 2 + desc_len + 8
    size_t total = MSG_EVENT_TYPE_SIZE + MSG_PLAYER_ID_SIZE + MSG_DESCRIPTION_LEN_SIZE + (size_t)desc_len + CLIENT_NONCE_SIZE;
    if (total > MSG_MAX_FRAME_LEN) return -1;

    uint8_t *p = (uint8_t *)malloc(total);
    if (!p) return -1;

    size_t off = 0;
    write_u32_le(p + off, event_type);
    off += MSG_EVENT_TYPE_SIZE;
    write_u32_le(p + off, player_id);
    off += MSG_PLAYER_ID_SIZE;
    write_u16_le(p + off, desc_len);
    off += MSG_DESCRIPTION_LEN_SIZE;

    if (desc_len > 0) {
        memcpy(p + off, desc, desc_len);
        off += desc_len;
    }

    write_u64_le(p + off, client_nonce);
    off += CLIENT_NONCE_SIZE;

    // sanity
    if (off != total) {
        free(p);
        return -1;
    }

    *payload_out = p;
    *payload_len_out = total;
    return 0;
}

int msg_parse_submit_payload(const uint8_t *payload, size_t payload_len,
                             uint32_t *event_type_out, uint32_t *player_id_out,
                             const char **desc_out, uint16_t *desc_len_out,
                             uint64_t *client_nonce_out)
{
    if (!payload || !event_type_out || !player_id_out ||
        !desc_out || !desc_len_out || !client_nonce_out) {
        return -1;
    }

    // Need at least 4+4+2+8 = 18 bytes
    if (payload_len < (MSG_EVENT_TYPE_SIZE + MSG_PLAYER_ID_SIZE + MSG_DESCRIPTION_LEN_SIZE + CLIENT_NONCE_SIZE)) return -1;

    size_t off = 0;
    uint32_t event_type = read_u32_le(payload + off);
    off += MSG_EVENT_TYPE_SIZE;
    uint32_t player_id  = read_u32_le(payload + off);
    off += MSG_PLAYER_ID_SIZE;
    uint16_t dlen       = read_u16_le(payload + off);
    off += MSG_DESCRIPTION_LEN_SIZE;

    if (dlen > MSG_MAX_DESC_LEN) return -1;

    // After desc, we need 8 bytes of nonce
    if (payload_len < off + (size_t)dlen + CLIENT_NONCE_SIZE) return -1;

    const char *desc_ptr = (const char *)(payload + off);
    off += (size_t)dlen;

    uint64_t nonce = read_u64_le(payload + off);
    off += CLIENT_NONCE_SIZE;

    // Require exact length match (prevents trailing junk ambiguity)
    if (off != payload_len) return -1;

    *event_type_out = event_type;
    *player_id_out  = player_id;
    *desc_out       = desc_ptr;
    *desc_len_out   = dlen;
    *client_nonce_out = nonce;
    return 0;
}

int msg_build_repl_ack_payload(uint8_t **payload_out, size_t *payload_len_out,
                               uint8_t ok,
                               uint64_t log_index,
                               const uint8_t entry_hash[HASH_SIZE],
                               uint8_t reason)
{
    if (!payload_out || !payload_len_out || !entry_hash) {
        return -1;
    }

    size_t total = ok ? REPL_ACK_OK_SIZE : REPL_ACK_FAIL_SIZE;
    uint8_t *p = (uint8_t *)malloc(total);
    if (!p) {
        return -1;
    }

    p[0] = ok ? 1 : 0;
    write_u64_le(p + 1, log_index);
    memcpy(p + 1 + 8, entry_hash, HASH_SIZE);

    if (!ok) {
        p[1 + 8 + HASH_SIZE] = reason;
    }

    *payload_out = p;
    *payload_len_out = total;
    return 0;
}

int msg_parse_repl_ack_payload(const uint8_t *payload, size_t payload_len,
                               uint8_t *ok_out,
                               uint64_t *log_index_out,
                               uint8_t entry_hash_out[HASH_SIZE],
                               uint8_t *reason_out)
{
    if (!payload || !ok_out || !log_index_out || !entry_hash_out || !reason_out) {
        return -1;
    }

    if (payload_len != REPL_ACK_OK_SIZE && payload_len != REPL_ACK_FAIL_SIZE) {
        return -1;
    }

    uint8_t ok = payload[0];
    if (ok != 0 && ok != 1) {
        return -1;
    }
    if (ok == 1 && payload_len != REPL_ACK_OK_SIZE) {
        return -1;
    }
    if (ok == 0 && payload_len != REPL_ACK_FAIL_SIZE) {
        return -1;
    }

    *ok_out = ok;
    *log_index_out = read_u64_le(payload + 1);
    memcpy(entry_hash_out, payload + 1 + 8, HASH_SIZE);
    *reason_out = ok ? 0 : payload[1 + 8 + HASH_SIZE];

    return 0;
}
