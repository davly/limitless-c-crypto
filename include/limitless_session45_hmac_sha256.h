/*
 * limitless_session45_hmac_sha256.h -- HMAC-SHA256 (RFC 2104 / FIPS 198-1)
 *
 * Pure C11 HMAC-SHA256 on top of limitless_session45_sha256.h.
 * Header-only, static inline throughout. Zero deps beyond <stdint.h> +
 * <stddef.h> + the SHA-256 sibling.
 *
 * Standards:
 *
 *   - RFC 2104 (1997) -- HMAC: Keyed-Hashing for Message Authentication.
 *   - FIPS PUB 198-1 (2008) -- The Keyed-Hash Message Authentication Code.
 *
 * Algorithm:
 *
 *   1. If key_len > B (block size = 64 for SHA-256), key' = SHA-256(key).
 *      Otherwise key' = key.
 *   2. Zero-pad key' to B bytes.
 *   3. Compute inner pad K_ipad = key' XOR (0x36 repeated B times).
 *   4. Compute outer pad K_opad = key' XOR (0x5c repeated B times).
 *   5. inner = SHA-256(K_ipad || data).
 *   6. output = SHA-256(K_opad || inner).
 *
 * RFC 4231 §4.2-4.4 test vectors are pinned in `test/test_session45_kat.c`.
 *
 * ## Macro-prefix discrimination (Q19 D4)
 *
 * Consumers define LIMITLESS_C_CRYPTO_PREFIX before include to rename
 * exported symbols. Default is `limitless`.
 *
 *   #define LIMITLESS_C_CRYPTO_PREFIX ember
 *   #include "limitless_session45_hmac_sha256.h"
 *   // -> ember_hmac_sha256(...)
 *
 * ## Cross-substrate parity oracle
 *
 * Go stdlib `crypto/hmac` + `crypto/sha256` is the canonical L43 oracle.
 * Rust mirror_mark/hmac.rs, Python hmac.new(...).digest(), Erlang
 * :crypto.mac(:hmac, :sha256, ...) -- all produce byte-identical output.
 * The cohort firewall is the R151 KAT-1 anchor
 * `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca`
 * verifiable via the OpenSSL reference command published in the cohort
 * memory doc:
 *
 *   printf '\x01' && printf '\x00%.0s' {1..32} | openssl dgst -sha256 \
 *     -mac hmac -macopt key:
 *
 * Apache 2.0 -- see LICENSE.
 */

#ifndef LIMITLESS_SESSION45_HMAC_SHA256_H
#define LIMITLESS_SESSION45_HMAC_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include "limitless_session45_sha256.h"

/* ============================================================
 * Constants
 * ============================================================ */

#define LIMITLESS_HMAC_SHA256_DIGEST_LEN LIMITLESS_SHA256_DIGEST_LEN
#define LIMITLESS_HMAC_SHA256_BLOCK_LEN  LIMITLESS_SHA256_BLOCK_LEN

#define LIMITLESS_HMAC_SHA256_IPAD_BYTE 0x36u
#define LIMITLESS_HMAC_SHA256_OPAD_BYTE 0x5cu

/* ============================================================
 * One-shot HMAC-SHA256.
 *
 * Computes HMAC-SHA256(key, data) into `out[32]`.
 *
 *   - `key` may be NULL iff `key_len == 0` (empty-key cohort case; valid
 *     per RFC 2104 -- HMAC over empty key is a defined cohort anchor;
 *     KAT-1 uses this case).
 *   - `data` may be NULL iff `data_len == 0` (empty-data case;
 *     SHA-256 of empty input is FIPS PUB 180-4 §A.1 reference).
 *   - `out` MUST be at least 32 bytes.
 *
 * The function never returns an error code -- by construction (no
 * malloc, no I/O, all stack-bounded), there is no failure mode.
 * ============================================================ */

static inline void LIMITLESS_C_CRYPTO_NAME(hmac_sha256)(const uint8_t *key, size_t key_len,
                                                          const uint8_t *data, size_t data_len,
                                                          uint8_t out[LIMITLESS_HMAC_SHA256_DIGEST_LEN]) {
    uint8_t key_block[LIMITLESS_HMAC_SHA256_BLOCK_LEN];
    uint8_t ipad[LIMITLESS_HMAC_SHA256_BLOCK_LEN];
    uint8_t opad[LIMITLESS_HMAC_SHA256_BLOCK_LEN];
    uint8_t inner[LIMITLESS_HMAC_SHA256_DIGEST_LEN];
    size_t i;

    /* Zero the working key block. */
    for (i = 0; i < LIMITLESS_HMAC_SHA256_BLOCK_LEN; i++) {
        key_block[i] = 0u;
    }

    /* RFC 2104 §2: if key_len > B, key' = SHA-256(key); else key' = key. */
    if (key_len > LIMITLESS_HMAC_SHA256_BLOCK_LEN) {
        uint8_t khash[LIMITLESS_SHA256_DIGEST_LEN];
        LIMITLESS_C_CRYPTO_NAME(sha256)(key, key_len, khash);
        for (i = 0; i < LIMITLESS_SHA256_DIGEST_LEN; i++) {
            key_block[i] = khash[i];
        }
    } else {
        if (key != NULL && key_len > 0) {
            for (i = 0; i < key_len; i++) {
                key_block[i] = key[i];
            }
        }
    }

    /* Compute K_ipad = key' XOR ipad-byte, K_opad = key' XOR opad-byte. */
    for (i = 0; i < LIMITLESS_HMAC_SHA256_BLOCK_LEN; i++) {
        ipad[i] = (uint8_t)(key_block[i] ^ LIMITLESS_HMAC_SHA256_IPAD_BYTE);
        opad[i] = (uint8_t)(key_block[i] ^ LIMITLESS_HMAC_SHA256_OPAD_BYTE);
    }

    /* inner = SHA-256(K_ipad || data). */
    {
        LIMITLESS_SHA256_CTX_T ctx;
        LIMITLESS_C_CRYPTO_NAME(sha256_init)(&ctx);
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, ipad, LIMITLESS_HMAC_SHA256_BLOCK_LEN);
        if (data_len > 0 && data != NULL) {
            LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, data, data_len);
        }
        LIMITLESS_C_CRYPTO_NAME(sha256_finalise)(&ctx, inner);
    }

    /* outer = SHA-256(K_opad || inner). */
    {
        LIMITLESS_SHA256_CTX_T ctx;
        LIMITLESS_C_CRYPTO_NAME(sha256_init)(&ctx);
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, opad, LIMITLESS_HMAC_SHA256_BLOCK_LEN);
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, inner, LIMITLESS_HMAC_SHA256_DIGEST_LEN);
        LIMITLESS_C_CRYPTO_NAME(sha256_finalise)(&ctx, out);
    }
}

#endif /* LIMITLESS_SESSION45_HMAC_SHA256_H */
