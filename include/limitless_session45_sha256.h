/*
 * limitless_session45_sha256.h -- SHA-256 (FIPS PUB 180-4) shared cohort header
 *
 * Pure C11 SHA-256 reference implementation. Header-only, static inline
 * throughout. Zero deps beyond <stdint.h> + <stddef.h>. No libc, no
 * malloc, no printf, no math.h.
 *
 * ## Purpose -- shared C-substrate cohort header
 *
 * Three cohort flagships (ember C11 RISC-V, bedrock-c C11, cortex C++20)
 * each carry their own session45 cluster of SHA-256 + HMAC-SHA256 +
 * Mirror-Mark + KAT-1 headers. Q19 of the 2026-05-25 cross-poll review
 * identified the convergence: byte-identical algorithm, identical
 * structure, three substrate-specific symbol prefixes (EMBER_ /
 * BEDROCK_C_ / CORTEX_). This file is the single source of truth that
 * each consumer can include with a custom prefix via the
 * LIMITLESS_C_CRYPTO_PREFIX macro discriminator.
 *
 * ## Macro-prefix discrimination (Q19 D4 finding)
 *
 * Consumers define LIMITLESS_C_CRYPTO_PREFIX before #include to rename
 * exported symbols. Default is `limitless` (so direct use without rename
 * works for any consumer that doesn't need a per-flagship namespace).
 *
 *   #define LIMITLESS_C_CRYPTO_PREFIX ember
 *   #include "limitless_session45_sha256.h"
 *   // -> ember_sha256_ctx, ember_sha256, ember_sha256_init, ...
 *
 *   #define LIMITLESS_C_CRYPTO_PREFIX bedrock_c
 *   #include "limitless_session45_sha256.h"
 *   // -> bedrock_c_sha256_ctx, bedrock_c_sha256, ...
 *
 *   #define LIMITLESS_C_CRYPTO_PREFIX cortex
 *   #include "limitless_session45_sha256.h"
 *   // -> cortex_sha256_ctx, cortex_sha256, ...
 *
 * If no prefix is defined, symbols use the `limitless_` namespace.
 *
 * ## Cross-substrate parity oracle
 *
 * Go stdlib `crypto/sha256` is the canonical L43 oracle. Rust
 * mirror_mark/sha256.rs, Python hashlib.sha256(), Erlang :crypto.hash --
 * all produce byte-identical output on the same input. This C11 header
 * joins that cohort as a shared substrate-portable implementation.
 *
 * ## Algorithm correctness pin
 *
 * The test rig `test/test_session45_kat.c::test_sha256_fips_pub_180_4_*`
 * asserts FIPS PUB 180-4 §B.1-B.2 example vectors byte-for-byte. The
 * cohort cross-substrate firewall (R151 KAT-1) cross-checks this
 * implementation against the published canonical hex
 * `239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca`
 * -- any drift in this file fails KAT-1.
 *
 * ## What this file is NOT
 *
 *   - A production cryptographic library. There is no constant-time
 *     compare here; no zeroize-on-drop; no FIPS validation suite; no
 *     side-channel hardening for cache-timing attacks. The
 *     `limitless_session45_mirror_mark.h` sibling carries a constant-
 *     time-compare verify path.
 *
 * Apache 2.0 -- see LICENSE.
 */

#ifndef LIMITLESS_SESSION45_SHA256_H
#define LIMITLESS_SESSION45_SHA256_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * Macro-prefix discrimination (Q19 D4)
 * ============================================================ */

#ifndef LIMITLESS_C_CRYPTO_PREFIX
#define LIMITLESS_C_CRYPTO_PREFIX limitless
#endif

/* Token-pasting helpers. Two levels of indirection are required so that
 * the prefix macro expands BEFORE concatenation (per C11 §6.10.3.5). */
#define LIMITLESS_C_CRYPTO_CONCAT_INNER(a, b) a##_##b
#define LIMITLESS_C_CRYPTO_CONCAT(a, b) LIMITLESS_C_CRYPTO_CONCAT_INNER(a, b)
#define LIMITLESS_C_CRYPTO_NAME(suffix) LIMITLESS_C_CRYPTO_CONCAT(LIMITLESS_C_CRYPTO_PREFIX, suffix)

/* ============================================================
 * Constants (always identical across consumers -- not prefixed)
 * ============================================================ */

/* SHA-256 output length in bytes. */
#define LIMITLESS_SHA256_DIGEST_LEN 32

/* SHA-256 input compression block length in bytes. */
#define LIMITLESS_SHA256_BLOCK_LEN 64

/* ============================================================
 * Context type (prefix-renamed)
 * ============================================================ */

#define LIMITLESS_SHA256_CTX_T LIMITLESS_C_CRYPTO_NAME(sha256_ctx)

typedef struct {
    uint32_t state[8];                            /* H(0)..H(7) state */
    uint8_t  buf[LIMITLESS_SHA256_BLOCK_LEN];     /* partial-block buffer */
    size_t   buf_len;                             /* bytes currently in buf */
    uint64_t total_len;                           /* total input bytes ever */
} LIMITLESS_SHA256_CTX_T;

/* ============================================================
 * Helpers (inline, prefix-renamed)
 * ============================================================ */

static inline uint32_t LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static inline uint32_t LIMITLESS_C_CRYPTO_NAME(sha256_load_be32)(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

static inline void LIMITLESS_C_CRYPTO_NAME(sha256_store_be32)(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void LIMITLESS_C_CRYPTO_NAME(sha256_store_be64)(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

/* ============================================================
 * Compression function (FIPS 180-4 §6.2.2)
 * ============================================================ */

static inline void LIMITLESS_C_CRYPTO_NAME(sha256_compress)(uint32_t state[8],
                                                              const uint8_t block[LIMITLESS_SHA256_BLOCK_LEN]) {
    /* SHA-256 round constants K (FIPS 180-4 §4.2.2). */
    static const uint32_t K[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
        0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
        0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
        0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
        0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
        0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
        0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
        0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
        0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
    };

    uint32_t w[64];
    unsigned i;

    /* Message schedule prepare W[0..15] from block big-endian. */
    for (i = 0; i < 16; i++) {
        w[i] = LIMITLESS_C_CRYPTO_NAME(sha256_load_be32)(block + i * 4);
    }
    /* W[16..63] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16] */
    for (i = 16; i < 64; i++) {
        uint32_t s0 = LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(w[i - 15], 7)
                    ^ LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(w[i - 15], 18)
                    ^ (w[i - 15] >> 3);
        uint32_t s1 = LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(w[i - 2], 17)
                    ^ LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(w[i - 2], 19)
                    ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(e, 6)
                    ^ LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(e, 11)
                    ^ LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(a, 2)
                    ^ LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(a, 13)
                    ^ LIMITLESS_C_CRYPTO_NAME(sha256_rotr32)(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/* ============================================================
 * Surface (init / update / finalise / one-shot)
 * ============================================================ */

static inline void LIMITLESS_C_CRYPTO_NAME(sha256_init)(LIMITLESS_SHA256_CTX_T *ctx) {
    /* SHA-256 H(0) (FIPS 180-4 §5.3.3). */
    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;
    ctx->buf_len = 0;
    ctx->total_len = 0;
    {
        size_t j;
        for (j = 0; j < LIMITLESS_SHA256_BLOCK_LEN; j++) {
            ctx->buf[j] = 0;
        }
    }
}

static inline void LIMITLESS_C_CRYPTO_NAME(sha256_update)(LIMITLESS_SHA256_CTX_T *ctx,
                                                            const uint8_t *data, size_t len) {
    ctx->total_len += (uint64_t)len;

    /* Fill partial-block buffer first if any bytes are pending. */
    if (ctx->buf_len > 0) {
        size_t want = LIMITLESS_SHA256_BLOCK_LEN - ctx->buf_len;
        size_t take = (len < want) ? len : want;
        size_t k;
        for (k = 0; k < take; k++) {
            ctx->buf[ctx->buf_len + k] = data[k];
        }
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == LIMITLESS_SHA256_BLOCK_LEN) {
            LIMITLESS_C_CRYPTO_NAME(sha256_compress)(ctx->state, ctx->buf);
            ctx->buf_len = 0;
        }
    }

    /* Compress full blocks directly from caller's buffer. */
    while (len >= LIMITLESS_SHA256_BLOCK_LEN) {
        LIMITLESS_C_CRYPTO_NAME(sha256_compress)(ctx->state, data);
        data += LIMITLESS_SHA256_BLOCK_LEN;
        len -= LIMITLESS_SHA256_BLOCK_LEN;
    }

    /* Stash any remaining tail bytes for the next call. */
    if (len > 0) {
        size_t k;
        for (k = 0; k < len; k++) {
            ctx->buf[k] = data[k];
        }
        ctx->buf_len = len;
    }
}

static inline void LIMITLESS_C_CRYPTO_NAME(sha256_finalise)(LIMITLESS_SHA256_CTX_T *ctx,
                                                              uint8_t out[LIMITLESS_SHA256_DIGEST_LEN]) {
    /* FIPS 180-4 §5.1.1 padding: append 0x80, then zeros, then 64-bit
     * big-endian total bit length. */
    uint64_t bit_len = ctx->total_len * 8u;
    size_t pad_pos = ctx->buf_len;

    ctx->buf[pad_pos++] = 0x80u;
    if (pad_pos > LIMITLESS_SHA256_BLOCK_LEN - 8) {
        while (pad_pos < LIMITLESS_SHA256_BLOCK_LEN) {
            ctx->buf[pad_pos++] = 0u;
        }
        LIMITLESS_C_CRYPTO_NAME(sha256_compress)(ctx->state, ctx->buf);
        pad_pos = 0;
    }
    while (pad_pos < LIMITLESS_SHA256_BLOCK_LEN - 8) {
        ctx->buf[pad_pos++] = 0u;
    }
    LIMITLESS_C_CRYPTO_NAME(sha256_store_be64)(ctx->buf + LIMITLESS_SHA256_BLOCK_LEN - 8, bit_len);
    LIMITLESS_C_CRYPTO_NAME(sha256_compress)(ctx->state, ctx->buf);

    /* Serialize state to output big-endian. */
    {
        unsigned i;
        for (i = 0; i < 8; i++) {
            LIMITLESS_C_CRYPTO_NAME(sha256_store_be32)(out + i * 4, ctx->state[i]);
        }
    }
}

/* One-shot SHA-256: hash `data[0..len)` into `out[32]`. */
static inline void LIMITLESS_C_CRYPTO_NAME(sha256)(const uint8_t *data, size_t len,
                                                     uint8_t out[LIMITLESS_SHA256_DIGEST_LEN]) {
    LIMITLESS_SHA256_CTX_T ctx;
    LIMITLESS_C_CRYPTO_NAME(sha256_init)(&ctx);
    if (len > 0 && data != NULL) {
        LIMITLESS_C_CRYPTO_NAME(sha256_update)(&ctx, data, len);
    }
    LIMITLESS_C_CRYPTO_NAME(sha256_finalise)(&ctx, out);
}

#endif /* LIMITLESS_SESSION45_SHA256_H */
