# Tamperproof Logger

A lightweight, cryptographically secure append-only log in C with both local and distributed modes.

It uses:
- Hash chaining (`prev_hash`)
- Ed25519 signatures (libsodium)
- CRC32 integrity checks
- Explicit `log_index` per entry
- Leader/follower replication with quorum ACK

## Current Status

This project now supports a distributed leader-based replication flow.

Current behavior:
- Client submits to any node.
- Non-leader forwards to leader.
- Leader appends locally, then replicates.
- Leader returns `ACK` only after quorum is reached.
- After quorum ACK, leader continues asynchronous fanout retries to bring remaining followers up to date.
- Followers enforce chain extension and `log_index` continuity, and can truncate/replay to repair divergence.

## Build

```bash
make
```

Run unit tests:

```bash
make test
```

Run cluster integration scenarios:

```bash
./scripts/cluster_integration_tests.sh --scenario all --verbose
```

## CLI Commands

Local log commands:
- `./build/logger add <event_type> <player_id> <description> [--author N] [--nonce N] [--log PATH] [--pub PATH] [--priv PATH]`
- `./build/logger print [logfile] [--log PATH]`
- `./build/logger verify [logfile] [--log PATH] [--pub PATH] [--priv PATH]`
- `./build/logger verify-local --leader-id N [--log PATH] [--pub PATH] [--priv PATH]`
- `./build/logger verify-peers --peers PATH [--log PATH]`
- `./build/logger rotate_keys [--author N] [--nonce N] [--log PATH] [--pub PATH] [--priv PATH]`

Distributed commands:
- `./build/logger node --node-id N --leader-id N --listen HOST:PORT --log PATH --pub PATH --priv PATH --peers PATH`
- `./build/logger submit --host HOST --port PORT --event EVENT --player ID --desc TEXT [--nonce N]`
- `./build/logger show-pub --pub PATH`
- `./build/logger show-pub --host HOST --port PORT`

## peers.conf Format

One peer per line:

`<node_id> <host> <port> <pubkey_hex>`

Example:
`1 127.0.0.1 21596 <64-hex-char-ed25519-pubkey>`

Important:
- `peers.conf` must include the leader itself.
- All nodes should have the same `peers.conf`.

## Replication Semantics (Current)

- Quorum is `floor(N/2) + 1`, where `N` is total nodes in `peers.conf` (including leader).
- Leader counts its own local append as one ACK.
- If quorum is not reached, client gets `NACK_QUORUM_NOT_REACHED`.
- On success, client gets `ACK` after quorum, not after all followers.
- Remaining followers are retried asynchronously until convergence.
- Follower-side replication ACK includes `ok`, `log_index`, `entry_hash`, and optional reason code.

## NACK Codes

Client NACK reasons:
- `1` bad signature
- `2` bad format
- `3` does not extend chain
- `4` duplicate
- `5` internal error
- `6` unknown peer
- `7` not leader
- `8` leader unreachable
- `9` quorum not reached

Replication NACK reasons:
- `1` bad format
- `2` bad signature
- `3` does not extend chain
- `4` duplicate
- `5` internal error
- `6` unknown peer
- `7` index mismatch

## Integration Test Scenarios

`./scripts/cluster_integration_tests.sh` currently covers:
- `happy`: 3-node quorum replication + convergence
- `quorum`: fail-then-retry duplicate path
- `repair`: follower divergence truncate+replay repair

## Known Limitations

- No full Raft term/commit-index protocol yet.
- No snapshot/install-snapshot flow yet.
- Catch-up/repair exists, but not full consensus state machine semantics.
- Backward compatibility of old log formats/protocol versions is not currently a goal.
