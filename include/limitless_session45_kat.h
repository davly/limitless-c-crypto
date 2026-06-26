/*
 * limitless_session45_kat.h -- R151 KAT-1 cohort-canonical anchor
 *
 * Header-only constants module. Pins the cross-substrate KAT-1
 * HMAC-SHA256 hex anchor and the canonical 33-byte input + empty key
 * used to reproduce it.
 *
 * ## R151 cohort pin (cross-substrate-pinned)
 *
 * Every flagship in the R151 cohort publishes the exact 64-char hex
 * string `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca`.
 * A grep across the ecosystem for `239a7d0d3f1bbe3a` returns one
 * occurrence per flagship; any drift is a firewall break.
 *
 * Cohort siblings as of 2026-05-26:
 *
 *   - Go x 3:  apps/lore-mark-verify, apps/pulse, apps/baseline
 *   - Go x N:  folio, atelier, canvas, casino, ledger, howler, dipstick,
 *              pigeonhole, fleetworks-torque, counsel, cipher
 *   - Rust:    foundry, davly/lore-mark-verify
 *   - Python:  iris, haven, triage-hospital, alloy
 *   - Nim:     murmur (`src/murmur/kat1.nim`)
 *   - Gleam:   bastion (`src/bastion/kat1.gleam`)
 *   - Erlang:  THIS COHORT (via dispatch/limitless-beam-otp)
 *   - C11:     ember, bedrock-c (THIS HEADER -- shared)
 *   - C++20:   cortex (THIS HEADER -- shared)
 *
 * ## OpenSSL reproducer (regulator-side cold-verify)
 *
 *   printf '\x01' > /tmp/kat1.bin
 *   printf '\x00%.0s' $(seq 1 32) >> /tmp/kat1.bin
 *   openssl dgst -sha256 -hmac "" /tmp/kat1.bin
 *   # -> HMAC-SHA2-256(/tmp/kat1.bin)= 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
 *
 * ## Canonical input
 *
 *   key     = "" (empty 0-byte buffer)
 *   message = 0x01 || 32 x 0x00       (33 bytes total)
 *   output  = 32-byte HMAC-SHA256 with the hex form above
 *
 * ## Editing this constant
 *
 * Mutating LIMITLESS_KAT1_DIGEST_HEX requires a paired bump of every
 * cohort pin site + a wire-format migration note in `lore@v2:`. The
 * cohort-sabotage pre-commit hook (Phase 5 of the E24 brief) will fail
 * any commit that mutates this constant without a paired R145 ledger
 * entry.
 *
 * Apache 2.0 -- see LICENSE.
 */

#ifndef LIMITLESS_SESSION45_KAT_H
#define LIMITLESS_SESSION45_KAT_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * R151 KAT-1 canonical anchors
 * ============================================================ */

/* Cohort-canonical KAT-1 HMAC-SHA256 hex (lowercase, 64 chars, 32 bytes
 * binary). The R151 cohort cross-substrate firewall pin. */
#define LIMITLESS_KAT1_DIGEST_HEX \
    "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

/* Length of the canonical KAT-1 input in bytes (1 sentinel + 32 zero-fill). */
#define LIMITLESS_KAT1_INPUT_LEN 33

/* Length of the empty key (always 0). Exposed so consumers can pin the
 * invariant. */
#define LIMITLESS_KAT1_KEY_LEN 0

/* Length of the expected hex digest (64 chars, lowercase, no nul). */
#define LIMITLESS_KAT1_DIGEST_HEX_LEN 64

/* ============================================================
 * Canonical inputs (static const arrays so the compiler can detect any
 * use-after-end-of-array drift via -Warray-bounds)
 * ============================================================ */

/* The canonical 33-byte input: 0x01 followed by 32 x 0x00.
 * Declared static const so each translation unit gets a private copy
 * (no ODR issue from header-only include). */
static const uint8_t LIMITLESS_KAT1_CANONICAL_INPUT[LIMITLESS_KAT1_INPUT_LEN] = {
    0x01u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
};

/* The canonical KAT-1 key -- the empty byte string. Represented as a
 * pointer to a zero-byte buffer; the convention is to pass
 * LIMITLESS_KAT1_CANONICAL_KEY + LIMITLESS_KAT1_KEY_LEN to the HMAC
 * primitive. A one-byte storage with key_len == 0 is permitted (the
 * pointer is never dereferenced). */
static const uint8_t LIMITLESS_KAT1_CANONICAL_KEY[1] = { 0x00u };

#endif /* LIMITLESS_SESSION45_KAT_H */
