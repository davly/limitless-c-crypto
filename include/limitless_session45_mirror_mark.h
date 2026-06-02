/*
 * limitless_session45_mirror_mark.h -- L43 Mirror-Mark v1 cohort wire-form
 *
 * Pure C11 Mirror-Mark v1 sign + verify on top of
 * limitless_session45_hmac_sha256.h. Header-only, static inline
 * throughout. Zero deps beyond <stdint.h> + <stddef.h> + the HMAC
 * sibling.
 *
 * ## Cohort discipline (2026-05-26)
 *
 *   - L43 Mirror-Mark v1 wire format: byte-identical to iris-Python,
 *     pulse-Go, baseline-Go, foundry-Rust, canvas-Rust, atelier-Go,
 *     bastion-Gleam, dispatch-Erlang, murmur-Nim, and all other cohort
 *     siblings.
 *   - R151 KAT-1 cross-substrate pin: see `limitless_session45_kat.h`.
 *
 * ## Wire format (decoded body)
 *
 *   body[0..8]   = corpus_sha[0..8]                  -- 8-byte SHA prefix
 *   body[8..40]  = HMAC-SHA256(key, payload_signed)  -- 32-byte digest
 *
 *   where:
 *     payload_signed = 0x01 || corpus_sha[0..32] || payload[0..n]
 *
 *   The serialised mark string is:
 *
 *     "lore@v1:" + base64url_no_padding(body)
 *
 *   For KAT-1 (corpus = 32 x 0x00, payload = empty, key = empty):
 *     payload_signed = 0x01 || 32 x 0x00 || (empty) = 33 bytes
 *     HMAC-SHA256("", payload_signed) = 0x239a7d0d...
 *
 * ## Macro-prefix discrimination (Q19 D4)
 *
 *   #define LIMITLESS_C_CRYPTO_PREFIX ember
 *   #include "limitless_session45_mirror_mark.h"
 *   // -> ember_mirror_mark_sign(...), ember_mirror_mark_verify_payload(...)
 *
 * Apache 2.0 -- see LICENSE.
 */

#ifndef LIMITLESS_SESSION45_MIRROR_MARK_H
#define LIMITLESS_SESSION45_MIRROR_MARK_H

#include <stdint.h>
#include <stddef.h>
#include "limitless_session45_sha256.h"
#include "limitless_session45_hmac_sha256.h"

/* ============================================================
 * Cohort wire constants
 * ============================================================ */

/* Wire prefix, byte-identical to the cohort.  */
#define LIMITLESS_MIRROR_MARK_PREFIX     "lore@v1:"
#define LIMITLESS_MIRROR_MARK_PREFIX_LEN 8

/* Mark version byte (first byte of HMAC input). */
#define LIMITLESS_MIRROR_MARK_VERSION_BYTE 0x01u

/* Corpus-SHA prefix bytes embedded in mark body. */
#define LIMITLESS_MIRROR_MARK_CORPUS_PREFIX_LEN 8

/* HMAC-SHA256 digest length in mark body. */
#define LIMITLESS_MIRROR_MARK_DIGEST_LEN 32

/* Full corpus-SHA length (used in HMAC input). */
#define LIMITLESS_MIRROR_MARK_CORPUS_SHA_LEN 32

/* Total decoded body length: 8 corpus prefix + 32 digest. */
#define LIMITLESS_MIRROR_MARK_BODY_LEN 40

/* Base64URL-no-padding length for 40 bytes = ceil(40 * 4 / 3) = 54 chars. */
#define LIMITLESS_MIRROR_MARK_B64_LEN 54

/* Total string length = 8 prefix + 54 base64url. */
#define LIMITLESS_MIRROR_MARK_STR_LEN 62

/* Generous max for nul-terminated buffer. */
#define LIMITLESS_MIRROR_MARK_STR_MAX_LEN 64

/* Compile-time invariants. */
#ifdef __cplusplus
#define LIMITLESS_S45_STATIC_ASSERT(cond, msg) static_assert((cond), msg)
#else
#define LIMITLESS_S45_STATIC_ASSERT(cond, msg) _Static_assert((cond), msg)
#endif

LIMITLESS_S45_STATIC_ASSERT(LIMITLESS_MIRROR_MARK_CORPUS_PREFIX_LEN == 8,
                            "mirror-mark corpus prefix must be 8 bytes (cohort wire stability)");
LIMITLESS_S45_STATIC_ASSERT(LIMITLESS_MIRROR_MARK_DIGEST_LEN == 32,
                            "mirror-mark digest must be 32 bytes (HMAC-SHA256 cohort)");
LIMITLESS_S45_STATIC_ASSERT(LIMITLESS_MIRROR_MARK_BODY_LEN ==
                            (LIMITLESS_MIRROR_MARK_CORPUS_PREFIX_LEN + LIMITLESS_MIRROR_MARK_DIGEST_LEN),
                            "mirror-mark body length = corpus prefix + digest");
LIMITLESS_S45_STATIC_ASSERT(LIMITLESS_MIRROR_MARK_VERSION_BYTE == 0x01u,
                            "mirror-mark version byte must be 0x01 (L43 wire v1)");
LIMITLESS_S45_STATIC_ASSERT(LIMITLESS_MIRROR_MARK_CORPUS_SHA_LEN == 32,
                            "mirror-mark corpus-sha length must be 32 bytes");
LIMITLESS_S45_STATIC_ASSERT(LIMITLESS_MIRROR_MARK_PREFIX_LEN == 8,
                            "mirror-mark prefix is exactly 'lore@v1:' (8 bytes)");
LIMITLESS_S45_STATIC_ASSERT(LIMITLESS_MIRROR_MARK_STR_LEN ==
                            (LIMITLESS_MIRROR_MARK_PREFIX_LEN + LIMITLESS_MIRROR_MARK_B64_LEN),
                            "mirror-mark string len = prefix + b64 body");

/* ============================================================
 * Base64URL encode (RFC 4648 §5, no padding)
 * ============================================================ */

static inline char LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)(uint8_t v) {
    /* v in [0, 63] */
    if (v < 26u) return (char)('A' + v);          /* 0..25  -> A..Z */
    if (v < 52u) return (char)('a' + (v - 26u));  /* 26..51 -> a..z */
    if (v < 62u) return (char)('0' + (v - 52u));  /* 52..61 -> 0..9 */
    if (v == 62u) return '-';
    return '_'; /* v == 63 */
}

static inline uint8_t LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(char c) {
    if (c >= 'A' && c <= 'Z') return (uint8_t)(c - 'A');
    if (c >= 'a' && c <= 'z') return (uint8_t)(26 + (c - 'a'));
    if (c >= '0' && c <= '9') return (uint8_t)(52 + (c - '0'));
    if (c == '-') return 62u;
    if (c == '_') return 63u;
    return 0xFFu;
}

static inline size_t LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_encode)(const uint8_t *in, size_t in_len,
                                                                          char *out) {
    size_t i = 0;
    size_t o = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16)
                   | ((uint32_t)in[i + 1] << 8)
                   | ((uint32_t)in[i + 2]);
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)((v >> 18) & 0x3Fu));
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)((v >> 12) & 0x3Fu));
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)((v >> 6)  & 0x3Fu));
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)(v         & 0x3Fu));
        i += 3;
    }
    if (i + 1 == in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)((v >> 18) & 0x3Fu));
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)((v >> 12) & 0x3Fu));
    } else if (i + 2 == in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)((v >> 18) & 0x3Fu));
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)((v >> 12) & 0x3Fu));
        out[o++] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_alphabet)((uint8_t)((v >> 6)  & 0x3Fu));
    }
    return o;
}

static inline size_t LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode)(const char *in, size_t in_len,
                                                                         uint8_t *out, size_t out_max) {
    size_t i = 0;
    size_t o = 0;
    while (i + 4 <= in_len) {
        uint8_t a = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i]);
        uint8_t b = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i + 1]);
        uint8_t c = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i + 2]);
        uint8_t d = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i + 3]);
        if (a == 0xFFu || b == 0xFFu || c == 0xFFu || d == 0xFFu) return 0u;
        if (o + 3 > out_max) return 0u;
        uint32_t v = ((uint32_t)a << 18)
                   | ((uint32_t)b << 12)
                   | ((uint32_t)c << 6)
                   | ((uint32_t)d);
        out[o++] = (uint8_t)((v >> 16) & 0xFFu);
        out[o++] = (uint8_t)((v >> 8)  & 0xFFu);
        out[o++] = (uint8_t)(v         & 0xFFu);
        i += 4;
    }
    size_t rem = in_len - i;
    if (rem == 2u) {
        uint8_t a = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i]);
        uint8_t b = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i + 1]);
        if (a == 0xFFu || b == 0xFFu) return 0u;
        if (o + 1 > out_max) return 0u;
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12);
        /* Canonical-form check: a 2-char tail encodes exactly 1 byte, so the
         * low 4 bits of `b` (= bits 0..3 of the byte's continuation) MUST be
         * zero. Strict base64url decoders (Go RawURLEncoding, Rust base64
         * strict) reject non-zero trailing bits; accepting them here would
         * make the mark wire-form malleable (distinct strings verifying as
         * the same mark) and break cohort cross-substrate parity. */
        if ((b & 0x0Fu) != 0u) return 0u;
        out[o++] = (uint8_t)((v >> 16) & 0xFFu);
    } else if (rem == 3u) {
        uint8_t a = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i]);
        uint8_t b = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i + 1]);
        uint8_t c = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode_char)(in[i + 2]);
        if (a == 0xFFu || b == 0xFFu || c == 0xFFu) return 0u;
        if (o + 2 > out_max) return 0u;
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6);
        /* Canonical-form check: a 3-char tail encodes exactly 2 bytes, so the
         * low 2 bits of `c` MUST be zero (same malleability/parity rationale
         * as the 2-char tail above). */
        if ((c & 0x03u) != 0u) return 0u;
        out[o++] = (uint8_t)((v >> 16) & 0xFFu);
        out[o++] = (uint8_t)((v >> 8)  & 0xFFu);
    } else if (rem != 0u) {
        return 0u;
    }
    return o;
}

/* ============================================================
 * Hex serialise (for KAT-1 byte-for-byte verification)
 * ============================================================ */

static inline char LIMITLESS_C_CRYPTO_NAME(mirror_mark_hex_nibble)(uint8_t n) {
    if (n < 10u) return (char)('0' + n);
    return (char)('a' + (n - 10u));
}

static inline void LIMITLESS_C_CRYPTO_NAME(mirror_mark_hex_encode)(const uint8_t *in, size_t in_len,
                                                                     char *out) {
    size_t i;
    for (i = 0; i < in_len; i++) {
        out[i * 2]     = LIMITLESS_C_CRYPTO_NAME(mirror_mark_hex_nibble)((uint8_t)((in[i] >> 4) & 0x0Fu));
        out[i * 2 + 1] = LIMITLESS_C_CRYPTO_NAME(mirror_mark_hex_nibble)((uint8_t)(in[i] & 0x0Fu));
    }
}

/* ============================================================
 * Sign / verify
 * ============================================================ */

/* Constant-time byte-array equality.
 *
 * Returns 1 iff a[0..n] == b[0..n], scanning all n bytes regardless of
 * where (or whether) a mismatch occurs. The branch-free XOR accumulator
 * means the running time and control flow are independent of the secret
 * data, so verify_payload cannot leak the position of the first
 * differing digest byte via an early-exit timing side channel.
 *
 * Cohort parity: matches the foundry-Rust reference
 * `constant_time_eq` / `hmac.rs:89` (accumulate `diff |= a^b`, return
 * `diff == 0`). */
static inline int LIMITLESS_C_CRYPTO_NAME(mirror_mark_ct_eq)(
        const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0u;
    size_t i;
    for (i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0u;
}

/* Compute the cohort-canonical HMAC input for a (corpus, payload)
 * triple and produce the 32-byte digest in `out_digest`.
 *
 *   payload_signed = 0x01 || corpus_sha[0..32] || payload[0..n]
 *   out_digest      = HMAC-SHA256(key, payload_signed)
 */
static inline void LIMITLESS_C_CRYPTO_NAME(mirror_mark_compute_digest)(
        const uint8_t corpus_sha[LIMITLESS_MIRROR_MARK_CORPUS_SHA_LEN],
        const uint8_t *payload, size_t payload_len,
        const uint8_t *key, size_t key_len,
        uint8_t out_digest[LIMITLESS_MIRROR_MARK_DIGEST_LEN]) {
    /* Manual HMAC streaming to avoid an intermediate buffer for the
     * full (version || corpus || payload) input. Algorithm matches
     * RFC 2104:
     *   key' = key (if key_len <= 64) or SHA-256(key) (if > 64)
     *   key' padded with zeros to 64 bytes
     *   K_ipad = key' XOR 0x36
     *   K_opad = key' XOR 0x5c
     *   inner  = SHA-256(K_ipad || version_byte || corpus_sha || payload)
     *   output = SHA-256(K_opad || inner)
     */
    uint8_t key_block[LIMITLESS_HMAC_SHA256_BLOCK_LEN];
    uint8_t ipad[LIMITLESS_HMAC_SHA256_BLOCK_LEN];
    uint8_t opad[LIMITLESS_HMAC_SHA256_BLOCK_LEN];
    uint8_t inner[LIMITLESS_SHA256_DIGEST_LEN];
    uint8_t version_byte = LIMITLESS_MIRROR_MARK_VERSION_BYTE;
    size_t i;

    for (i = 0; i < LIMITLESS_HMAC_SHA256_BLOCK_LEN; i++) {
        key_block[i] = 0u;
    }
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
    for (i = 0; i < LIMITLESS_HMAC_SHA256_BLOCK_LEN; i++) {
        ipad[i] = (uint8_t)(key_block[i] ^ LIMITLESS_HMAC_SHA256_IPAD_BYTE);
        opad[i] = (uint8_t)(key_block[i] ^ LIMITLESS_HMAC_SHA256_OPAD_BYTE);
    }

    /* inner = SHA-256(K_ipad || version || corpus || payload). */
    {
        LIMITLESS_SHA256_CTX_T ctx;
        LIMITLESS_C_CRYPTO_NAME(sha256_init)(&ctx);
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, ipad, LIMITLESS_HMAC_SHA256_BLOCK_LEN);
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, &version_byte, 1u);
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, corpus_sha, LIMITLESS_MIRROR_MARK_CORPUS_SHA_LEN);
        if (payload_len > 0 && payload != NULL) {
            LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, payload, payload_len);
        }
        LIMITLESS_C_CRYPTO_NAME(sha256_finalise)(&ctx, inner);
    }

    /* output = SHA-256(K_opad || inner). */
    {
        LIMITLESS_SHA256_CTX_T ctx;
        LIMITLESS_C_CRYPTO_NAME(sha256_init)(&ctx);
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, opad, LIMITLESS_HMAC_SHA256_BLOCK_LEN);
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, inner, LIMITLESS_SHA256_DIGEST_LEN);
        LIMITLESS_C_CRYPTO_NAME(sha256_finalise)(&ctx, out_digest);
    }
}

/* Sign a (corpus, payload, key) triple into a Mirror-Mark v1 string.
 *
 *   out_str -- caller-supplied buffer, MUST be >= LIMITLESS_MIRROR_MARK_STR_MAX_LEN
 *
 * Returns the number of chars written (excluding the trailing nul) on
 * success, or 0 if `out_str_max < LIMITLESS_MIRROR_MARK_STR_LEN + 1`. */
static inline size_t LIMITLESS_C_CRYPTO_NAME(mirror_mark_sign)(
        const uint8_t corpus_sha[LIMITLESS_MIRROR_MARK_CORPUS_SHA_LEN],
        const uint8_t *payload, size_t payload_len,
        const uint8_t *key, size_t key_len,
        char *out_str, size_t out_str_max) {
    if (out_str == NULL || out_str_max < (LIMITLESS_MIRROR_MARK_STR_LEN + 1u)) return 0u;

    uint8_t body[LIMITLESS_MIRROR_MARK_BODY_LEN];
    uint8_t digest[LIMITLESS_MIRROR_MARK_DIGEST_LEN];
    size_t i;

    for (i = 0; i < LIMITLESS_MIRROR_MARK_CORPUS_PREFIX_LEN; i++) {
        body[i] = corpus_sha[i];
    }
    LIMITLESS_C_CRYPTO_NAME(mirror_mark_compute_digest)(corpus_sha, payload, payload_len,
                                                          key, key_len, digest);
    for (i = 0; i < LIMITLESS_MIRROR_MARK_DIGEST_LEN; i++) {
        body[LIMITLESS_MIRROR_MARK_CORPUS_PREFIX_LEN + i] = digest[i];
    }

    {
        const char *p = LIMITLESS_MIRROR_MARK_PREFIX;
        for (i = 0; i < LIMITLESS_MIRROR_MARK_PREFIX_LEN; i++) {
            out_str[i] = p[i];
        }
    }
    size_t b64_written = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_encode)(
        body, LIMITLESS_MIRROR_MARK_BODY_LEN,
        out_str + LIMITLESS_MIRROR_MARK_PREFIX_LEN);
    size_t total = LIMITLESS_MIRROR_MARK_PREFIX_LEN + b64_written;
    out_str[total] = '\0';
    return total;
}

/* Verify a mark string against a (corpus, payload, key) triple.
 *
 * Returns 1 if the mark byte-matches what would be produced by sign();
 * 0 otherwise (including malformed prefix / wrong length / bad base64 /
 * digest mismatch / corpus-prefix mismatch). */
static inline int LIMITLESS_C_CRYPTO_NAME(mirror_mark_verify_payload)(
        const char *mark_str,
        const uint8_t corpus_sha[LIMITLESS_MIRROR_MARK_CORPUS_SHA_LEN],
        const uint8_t *payload, size_t payload_len,
        const uint8_t *key, size_t key_len) {
    if (mark_str == NULL) return 0;

    size_t i;
    const char *p = LIMITLESS_MIRROR_MARK_PREFIX;
    for (i = 0; i < LIMITLESS_MIRROR_MARK_PREFIX_LEN; i++) {
        if (mark_str[i] != p[i]) return 0;
    }
    size_t b64_len = 0;
    while (mark_str[LIMITLESS_MIRROR_MARK_PREFIX_LEN + b64_len] != '\0') {
        b64_len++;
        if (b64_len > LIMITLESS_MIRROR_MARK_B64_LEN) return 0;
    }
    if (b64_len != LIMITLESS_MIRROR_MARK_B64_LEN) return 0;

    uint8_t body[LIMITLESS_MIRROR_MARK_BODY_LEN];
    size_t decoded = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode)(
        mark_str + LIMITLESS_MIRROR_MARK_PREFIX_LEN, b64_len,
        body, LIMITLESS_MIRROR_MARK_BODY_LEN);
    if (decoded != LIMITLESS_MIRROR_MARK_BODY_LEN) return 0;

    uint8_t expected_digest[LIMITLESS_MIRROR_MARK_DIGEST_LEN];
    LIMITLESS_C_CRYPTO_NAME(mirror_mark_compute_digest)(corpus_sha, payload, payload_len,
                                                          key, key_len, expected_digest);

    /* Constant-time, non-short-circuiting compare of BOTH the secret-
     * derived 8-byte corpus prefix and the 32-byte HMAC digest. Both
     * ct_eq calls run to full length and are AND-combined into a single
     * return so neither path leaks the position of a mismatch through a
     * data-dependent early exit. (The prefix/length/base64 structural
     * checks above stay early-exit -- they are not secret-dependent.) */
    int corpus_ok = LIMITLESS_C_CRYPTO_NAME(mirror_mark_ct_eq)(
        body, corpus_sha, LIMITLESS_MIRROR_MARK_CORPUS_PREFIX_LEN);
    int digest_ok = LIMITLESS_C_CRYPTO_NAME(mirror_mark_ct_eq)(
        body + LIMITLESS_MIRROR_MARK_CORPUS_PREFIX_LEN, expected_digest,
        LIMITLESS_MIRROR_MARK_DIGEST_LEN);
    return (corpus_ok & digest_ok);
}

/* Extract the 32-byte HMAC digest from a Mirror-Mark v1 string.
 *
 * Returns 1 on success, 0 if the mark is malformed. */
static inline int LIMITLESS_C_CRYPTO_NAME(mirror_mark_extract_digest)(
        const char *mark_str,
        uint8_t out_digest[LIMITLESS_MIRROR_MARK_DIGEST_LEN]) {
    if (mark_str == NULL) return 0;

    size_t i;
    const char *p = LIMITLESS_MIRROR_MARK_PREFIX;
    for (i = 0; i < LIMITLESS_MIRROR_MARK_PREFIX_LEN; i++) {
        if (mark_str[i] != p[i]) return 0;
    }
    size_t b64_len = 0;
    while (mark_str[LIMITLESS_MIRROR_MARK_PREFIX_LEN + b64_len] != '\0') {
        b64_len++;
        if (b64_len > LIMITLESS_MIRROR_MARK_B64_LEN) return 0;
    }
    if (b64_len != LIMITLESS_MIRROR_MARK_B64_LEN) return 0;

    uint8_t body[LIMITLESS_MIRROR_MARK_BODY_LEN];
    size_t decoded = LIMITLESS_C_CRYPTO_NAME(mirror_mark_b64url_decode)(
        mark_str + LIMITLESS_MIRROR_MARK_PREFIX_LEN, b64_len,
        body, LIMITLESS_MIRROR_MARK_BODY_LEN);
    if (decoded != LIMITLESS_MIRROR_MARK_BODY_LEN) return 0;

    for (i = 0; i < LIMITLESS_MIRROR_MARK_DIGEST_LEN; i++) {
        out_digest[i] = body[LIMITLESS_MIRROR_MARK_CORPUS_PREFIX_LEN + i];
    }
    return 1;
}

#endif /* LIMITLESS_SESSION45_MIRROR_MARK_H */
