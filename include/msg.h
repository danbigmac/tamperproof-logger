#ifndef MSG_H
#define MSG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Protocol version
#define MSG_VERSION 1

// Frame header within the length-delimited data
#define MSG_FRAME_HDR_SIZE 2  // type (1) + version (1)

// Max bytes after the u32 length field (type+version+payload)
#define MSG_MAX_FRAME_LEN (1024 * 1024)  // 1 MiB; tune as you like

#define MSG_MAX_ENTRY_BYTES 4096

#define MSG_MAX_DESC_LEN 255

#define CLIENT_NONCE_SIZE 8

#define MSG_EVENT_TYPE_SIZE 4
#define MSG_PLAYER_ID_SIZE 4
#define MSG_DESCRIPTION_LEN_SIZE 2

typedef enum {
    MSG_SUBMIT   = 1,
    MSG_ENTRY    = 2,
    MSG_ACK      = 3,
    MSG_NACK     = 4,
    MSG_STATUS   = 5,  // optional for v1
    MSG_PUBKEY_REQ  = 6,
    MSG_PUBKEY_RESP = 7,
} MsgType;

// Receive result codes (so you can distinguish disconnect vs error)
typedef enum {
    MSG_OK = 0,
    MSG_EOF = 1,      // peer closed cleanly
    MSG_ERR = -1,     // IO or protocol error
    MSG_TOOLARGE = -2 // frame_len exceeds MSG_MAX_FRAME_LEN
} MsgResult;

typedef enum {
    NACK_BAD_SIGNATURE = 1,
    NACK_BAD_FORMAT = 2,
    NACK_DOES_NOT_EXTEND_CHAIN = 3,
    NACK_DUPLICATE = 4,
    NACK_INTERNAL_ERROR = 5,
    NACK_UNKNOWN_PEER = 6,
    NACK_NOT_LEADER       = 7,
    NACK_LEADER_UNREACH   = 8
} NackReason;

// Sends a frame: [u32_le frame_len][type][version][payload...]
int msg_send(int fd, uint8_t type,
             const uint8_t *payload, size_t payload_len);

// Receives a frame. Allocates *payload_out (caller must free).
// On success returns MSG_OK and sets:
//   *type_out, *version_out, *payload_out, *payload_len_out
MsgResult msg_recv(int fd, uint8_t *type_out, uint8_t *version_out,
                   uint8_t **payload_out, size_t *payload_len_out);

// ---- MSG_ENTRY payload helpers ----
// Payload format: u32_le entry_len | entry_bytes[entry_len]
int msg_build_entry_payload(uint8_t **payload_out, size_t *payload_len_out,
                            const uint8_t *entry_bytes, size_t entry_len);

int msg_parse_entry_payload(const uint8_t *payload, size_t payload_len,
                            const uint8_t **entry_bytes_out, size_t *entry_len_out);

// ---- MSG_SUBMIT payload helpers ----
// Payload format:
//   u32_le event_type
//   u32_le player_id
//   u16_le desc_len
//   u8     desc[desc_len]
//   u64_le client_nonce
//
// This is "client asks node to create & sign an entry".
int msg_build_submit_payload(uint8_t **payload_out, size_t *payload_len_out,
                             uint32_t event_type, uint32_t player_id,
                             const char *desc, uint16_t desc_len,
                             uint64_t client_nonce);

int msg_parse_submit_payload(const uint8_t *payload, size_t payload_len,
                             uint32_t *event_type_out, uint32_t *player_id_out,
                             const char **desc_out, uint16_t *desc_len_out,
                             uint64_t *client_nonce_out);

#ifdef __cplusplus
}
#endif

#endif
