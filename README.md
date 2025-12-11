A lightweight, cryptographically secure, append-only event logger written in C.
It uses a custom binary format, hash chaining, and Ed25519 signatures to ensure that once data is written, it cannot be modified or reordered without detection.
The project was originally designed around sports event data (timestamps, event types, player IDs, descriptions), but the structure is just an example - you can plug in any type of event data you want. The core idea is the same: provide a verifiable, tamper-evident log.
Still adding more features...


Some features:

- Append-only binary file format with length prefix & suffix.
- Cryptographic hash chaining
    - Each log entry stores the previous entry’s hash, forming a linked chain of integrity.
- Digital signatures (Ed25519 via libsodium)
    - Ensures every entry is authentic and was created by the holder of the private key.
- CRC32 checks for accidental corruption
- O(1) “read last entry” lookup
    - Enabled by footer-based length.
- Full verification
    - Detects tampering, corruption, reordering, or unsigned entries.


Example usage:

Build it:

make
./build/logger

Add an entry:

./build/logger add score 23 "Hit a three-pointer"

This command loads (or generates) signing keys, creates a new log entry, chains it to the previous entry, computes a hash, signs it, appends it to data/game.log.

Print entries:

./build/logger print

You’ll see output like:

Entry 0:
  time:   1733440100
  player: 23
  type:   SCORE
  desc:   Hit a three-pointer


Verify the entire log:

./build/logger verify

If the log has not been tampered with, you'll see output: "Log verified: all entries valid."

If you flip even one byte in the file, verification will detect it immediately.


The built-in event structure uses:

timestamp, 
event_type (e.g., SCORE / FOUL / SUB), 
player_id, 
description

This made sense for the sports-related experiments I wanted to play with - but the logger itself is generic and can support any event format. You can replace the fields, add new ones, or build an entirely different record schema without changing the core logging/verification pipeline.