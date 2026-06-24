/*
 * test_session45_kat.c -- KAT-1 verification + macro-prefix discrimination
 *
 * Builds three independent instantiations of the limitless_session45_*
 * header cluster -- using LIMITLESS_C_CRYPTO_PREFIX = ember,
 * bedrock_c, and cortex -- and verifies that each one independently
 * reproduces the R151 cohort-canonical KAT-1 hex anchor.
 *
 * The test exits 0 on success; non-zero on any KAT-1 drift or macro-
 * prefix discrimination drift.
 *
 * Build: `gcc -std=c11 -Wall -Wextra -I../include -o test_session45_kat \
 *         test_session45_kat.c`
 *
 * Run:   `./test_session45_kat`
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* ============================================================
 * Instantiation 1: ember prefix
 * ============================================================ */

#define LIMITLESS_C_CRYPTO_PREFIX ember
#include "limitless_session45_sha256.h"
#include "limitless_session45_hmac_sha256.h"
#include "limitless_session45_kat.h"
#include "limitless_session45_mirror_mark.h"
#undef LIMITLESS_C_CRYPTO_PREFIX
/* Undef the auto-generated context macro so the next instantiation has
 * a clean redefine. */
#undef LIMITLESS_SHA256_CTX_T

/* ============================================================
 * Instantiation 2: bedrock_c prefix
 * ============================================================ */

#define LIMITLESS_C_CRYPTO_PREFIX bedrock_c
/* The header has a header-guard; we need to bypass the guard to get the
 * inline definitions re-emitted under the new prefix. We do this by
 * #undef'ing the guard before the next include. This is a quirk of the
 * macro-prefix-discrimination scheme: each instantiation needs the
 * inline functions emitted with the per-prefix symbol names. */
#undef LIMITLESS_SESSION45_SHA256_H
#undef LIMITLESS_SESSION45_HMAC_SHA256_H
#undef LIMITLESS_SESSION45_MIRROR_MARK_H
#include "limitless_session45_sha256.h"
#include "limitless_session45_hmac_sha256.h"
#include "limitless_session45_mirror_mark.h"
#undef LIMITLESS_C_CRYPTO_PREFIX
#undef LIMITLESS_SHA256_CTX_T

/* ============================================================
 * Instantiation 3: cortex prefix
 * ============================================================ */

#define LIMITLESS_C_CRYPTO_PREFIX cortex
#undef LIMITLESS_SESSION45_SHA256_H
#undef LIMITLESS_SESSION45_HMAC_SHA256_H
#undef LIMITLESS_SESSION45_MIRROR_MARK_H
#include "limitless_session45_sha256.h"
#include "limitless_session45_hmac_sha256.h"
#include "limitless_session45_mirror_mark.h"
#undef LIMITLESS_C_CRYPTO_PREFIX
#undef LIMITLESS_SHA256_CTX_T

/* ============================================================
 * Instantiation 4: default (limitless) prefix -- the unprefixed case
 * ============================================================ */

#undef LIMITLESS_SESSION45_SHA256_H
#undef LIMITLESS_SESSION45_HMAC_SHA256_H
#undef LIMITLESS_SESSION45_MIRROR_MARK_H
#include "limitless_session45_sha256.h"
#include "limitless_session45_hmac_sha256.h"
#include "limitless_session45_mirror_mark.h"

/* ============================================================
 * Test scaffolding
 * ============================================================ */

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define CHECK(label, cond) do {                                          \
        g_tests_run++;                                                   \
        if (!(cond)) {                                                   \
            g_tests_failed++;                                            \
            fprintf(stderr, "FAIL %s @ %s:%d\n", (label), __FILE__, __LINE__); \
        } else {                                                         \
            fprintf(stdout, "  ok %s\n", (label));                       \
        }                                                                \
    } while (0)

static int hex_equal(const uint8_t *bin, size_t bin_len, const char *expected_hex) {
    if (strlen(expected_hex) != bin_len * 2u) return 0;
    char buf[256];
    if (bin_len > sizeof(buf) / 2u) return 0;
    for (size_t i = 0; i < bin_len; i++) {
        static const char hex[] = "0123456789abcdef";
        buf[i * 2]     = hex[(bin[i] >> 4) & 0x0F];
        buf[i * 2 + 1] = hex[bin[i] & 0x0F];
    }
    return memcmp(buf, expected_hex, bin_len * 2u) == 0;
}

/* ============================================================
 * Tests
 * ============================================================ */

static void test_kat1_constant_pinned(void) {
    /* The KAT-1 hex constant is pinned across all four instantiations
     * (the header is shared; the constant is not prefix-renamed). */
    CHECK("KAT-1 hex literal length is 64",
          strlen(LIMITLESS_KAT1_DIGEST_HEX) == 64);
    CHECK("KAT-1 hex literal matches cohort anchor",
          strcmp(LIMITLESS_KAT1_DIGEST_HEX,
                 "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca") == 0);
    CHECK("KAT-1 canonical input length is 33",
          LIMITLESS_KAT1_INPUT_LEN == 33);
    CHECK("KAT-1 key length is 0",
          LIMITLESS_KAT1_KEY_LEN == 0);
    CHECK("KAT-1 canonical input byte 0 is 0x01",
          LIMITLESS_KAT1_CANONICAL_INPUT[0] == 0x01u);
    {
        int all_zero = 1;
        for (size_t i = 1; i < LIMITLESS_KAT1_INPUT_LEN; i++) {
            if (LIMITLESS_KAT1_CANONICAL_INPUT[i] != 0x00u) { all_zero = 0; break; }
        }
        CHECK("KAT-1 canonical input bytes 1..32 are all 0x00", all_zero);
    }
}

static void test_ember_kat1_reproduces(void) {
    /* Reproduce KAT-1 via the ember-prefixed HMAC entry point. */
    uint8_t digest[32];
    ember_hmac_sha256(NULL, 0,
                      LIMITLESS_KAT1_CANONICAL_INPUT, LIMITLESS_KAT1_INPUT_LEN,
                      digest);
    CHECK("ember_hmac_sha256 reproduces KAT-1 hex",
          hex_equal(digest, 32, LIMITLESS_KAT1_DIGEST_HEX));
}

static void test_bedrock_c_kat1_reproduces(void) {
    /* Reproduce KAT-1 via the bedrock_c-prefixed HMAC entry point. */
    uint8_t digest[32];
    bedrock_c_hmac_sha256(NULL, 0,
                          LIMITLESS_KAT1_CANONICAL_INPUT, LIMITLESS_KAT1_INPUT_LEN,
                          digest);
    CHECK("bedrock_c_hmac_sha256 reproduces KAT-1 hex",
          hex_equal(digest, 32, LIMITLESS_KAT1_DIGEST_HEX));
}

static void test_cortex_kat1_reproduces(void) {
    /* Reproduce KAT-1 via the cortex-prefixed HMAC entry point. */
    uint8_t digest[32];
    cortex_hmac_sha256(NULL, 0,
                       LIMITLESS_KAT1_CANONICAL_INPUT, LIMITLESS_KAT1_INPUT_LEN,
                       digest);
    CHECK("cortex_hmac_sha256 reproduces KAT-1 hex",
          hex_equal(digest, 32, LIMITLESS_KAT1_DIGEST_HEX));
}

static void test_limitless_default_kat1_reproduces(void) {
    /* Reproduce KAT-1 via the default (limitless) prefix entry point. */
    uint8_t digest[32];
    limitless_hmac_sha256(NULL, 0,
                          LIMITLESS_KAT1_CANONICAL_INPUT, LIMITLESS_KAT1_INPUT_LEN,
                          digest);
    CHECK("limitless_hmac_sha256 reproduces KAT-1 hex",
          hex_equal(digest, 32, LIMITLESS_KAT1_DIGEST_HEX));
}

static void test_sha256_fips_180_4_abc(void) {
    /* FIPS PUB 180-4 §B.1 example: SHA-256("abc") =
     * ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    const uint8_t input[] = { 'a', 'b', 'c' };
    uint8_t digest[32];
    ember_sha256(input, 3, digest);
    CHECK("SHA-256('abc') matches FIPS 180-4 §B.1 reference",
          hex_equal(digest, 32,
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

static void test_sha256_fips_180_4_empty(void) {
    /* FIPS PUB 180-4 §A.1 example: SHA-256("") =
     * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    uint8_t digest[32];
    ember_sha256(NULL, 0, digest);
    CHECK("SHA-256('') matches FIPS 180-4 §A.1 reference",
          hex_equal(digest, 32,
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

static void test_sha256_long_input(void) {
    /* FIPS PUB 180-4 §B.2 example: SHA-256 of the 448-bit
     * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" =
     * 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 */
    const char *input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t digest[32];
    bedrock_c_sha256((const uint8_t *)input, strlen(input), digest);
    CHECK("SHA-256 of FIPS 180-4 §B.2 multi-block reference",
          hex_equal(digest, 32,
                    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

static void test_mirror_mark_sign_verify_roundtrip(void) {
    /* Construct a mark for (corpus = 32 x 0x00, payload = empty, key = empty);
     * verify it round-trips. */
    uint8_t corpus[32];
    memset(corpus, 0, 32);

    char mark_str[64];
    size_t written = limitless_mirror_mark_sign(corpus, NULL, 0, NULL, 0,
                                                  mark_str, sizeof(mark_str));
    CHECK("mirror_mark_sign writes 62 chars", written == 62);
    CHECK("mirror_mark string starts with 'lore@v1:'",
          strncmp(mark_str, "lore@v1:", 8) == 0);

    int ok = limitless_mirror_mark_verify_payload(mark_str, corpus, NULL, 0, NULL, 0);
    CHECK("mirror_mark verify round-trips", ok == 1);
}

static void test_mirror_mark_kat1_digest_match(void) {
    /* For (corpus = 32 x 0x00, payload = empty, key = empty), the digest
     * extracted from the mark MUST equal the KAT-1 canonical hex. */
    uint8_t corpus[32];
    memset(corpus, 0, 32);

    char mark_str[64];
    limitless_mirror_mark_sign(corpus, NULL, 0, NULL, 0,
                                 mark_str, sizeof(mark_str));

    uint8_t digest[32];
    int extracted = limitless_mirror_mark_extract_digest(mark_str, digest);
    CHECK("mirror_mark_extract_digest succeeds on canonical mark", extracted == 1);
    CHECK("mirror_mark KAT-1 digest = R151 cohort anchor",
          hex_equal(digest, 32, LIMITLESS_KAT1_DIGEST_HEX));
}

static void test_mirror_mark_verify_rejects_tampered_digest(void) {
    /* Sign the canonical KAT-1 triple (corpus = 32 x 0x00, payload =
     * empty, key = empty), then tamper the digest region of the mark and
     * assert verify rejects. Because the digest occupies body[8..40] and
     * the body is base64url-encoded after the 8-char "lore@v1:" prefix,
     * the digest bytes live well past the first ~10 base64 chars; we flip
     * chars near the start vs near the end of the digest region to lock
     * in NON-SHORT-CIRCUIT semantics: a tampered FIRST digest byte and a
     * tampered LAST digest byte must BOTH be rejected. The old early-exit
     * loop would reject regardless too -- but this regression guards the
     * verdict so a future constant-time refactor cannot silently break
     * rejection at either position. */
    uint8_t corpus[32];
    memset(corpus, 0, 32);

    char mark_str[64];
    size_t written = limitless_mirror_mark_sign(corpus, NULL, 0, NULL, 0,
                                                  mark_str, sizeof(mark_str));
    CHECK("tamper-test: sign produced 62-char mark", written == 62);

    /* Sanity: pristine mark verifies. */
    CHECK("tamper-test: pristine mark verifies",
          limitless_mirror_mark_verify_payload(mark_str, corpus, NULL, 0, NULL, 0) == 1);

    /* (a) Flip one base64 char in the digest region (a char late in the
     * string, which decodes into a late body byte == late digest byte).
     * mark_str[8..62] is the 54-char base64 body; index 60 is near the
     * end -> a digest byte. Pick a char and bump it to a different valid
     * base64url char so the decode still succeeds (decoded == 40) but the
     * digest bytes differ. */
    {
        char saved = mark_str[60];
        char repl = (saved == 'A') ? 'B' : 'A';
        mark_str[60] = repl;
        CHECK("tamper-test (a): flipped LAST-region base64 char -> verify rejects",
              limitless_mirror_mark_verify_payload(mark_str, corpus, NULL, 0, NULL, 0) == 0);
        mark_str[60] = saved; /* restore */
    }

    /* Verify restoration brought it back to a valid mark. */
    CHECK("tamper-test: mark restored after (a)",
          limitless_mirror_mark_verify_payload(mark_str, corpus, NULL, 0, NULL, 0) == 1);

    /* (b) Decode the body, tamper the FIRST digest byte (body[8]) and the
     * LAST digest byte (body[39]) independently, re-encode, and assert
     * BOTH reject. This directly exercises the non-short-circuit property:
     * a mismatch at the first digest byte and a mismatch at the last
     * digest byte are each rejected. */
    {
        uint8_t body[40];
        size_t decoded = limitless_mirror_mark_b64url_decode(
            mark_str + 8, 54, body, 40);
        CHECK("tamper-test (b): body decodes to 40 bytes", decoded == 40);

        /* Tamper FIRST digest byte (body index 8). */
        {
            uint8_t orig = body[8];
            body[8] = (uint8_t)(orig ^ 0xFFu);
            char tampered[64];
            for (int k = 0; k < 8; k++) tampered[k] = mark_str[k]; /* "lore@v1:" */
            size_t enc = limitless_mirror_mark_b64url_encode(body, 40, tampered + 8);
            tampered[8 + enc] = '\0';
            CHECK("tamper-test (b): FIRST digest byte flipped -> verify rejects",
                  limitless_mirror_mark_verify_payload(tampered, corpus, NULL, 0, NULL, 0) == 0);
            body[8] = orig; /* restore */
        }

        /* Tamper LAST digest byte (body index 39). */
        {
            uint8_t orig = body[39];
            body[39] = (uint8_t)(orig ^ 0xFFu);
            char tampered[64];
            for (int k = 0; k < 8; k++) tampered[k] = mark_str[k];
            size_t enc = limitless_mirror_mark_b64url_encode(body, 40, tampered + 8);
            tampered[8 + enc] = '\0';
            CHECK("tamper-test (b): LAST digest byte flipped -> verify rejects",
                  limitless_mirror_mark_verify_payload(tampered, corpus, NULL, 0, NULL, 0) == 0);
            body[39] = orig; /* restore */
        }
    }
}

static void test_mirror_mark_rejects_noncanonical_b64(void) {
    /* Wire-form non-malleability / cross-substrate parity regression.
     *
     * The mark body is 40 bytes -> 54 base64url chars. The final char of a
     * canonical encoding carries only the top 2 bits of body[39]; its low 4
     * bits are unused and MUST be zero. Strict cohort decoders (Go
     * RawURLEncoding, Rust base64 strict) reject any non-zero trailing bits.
     *
     * Before the fix, this C decoder silently discarded those bits, so
     * mutating the last char to a value sharing the same top 2 bits produced
     * a DIFFERENT, non-canonical string that nonetheless decoded to the SAME
     * body and verified TRUE -- a malleable wire form. This test pins that
     * such non-canonical strings are now rejected (verify == 0 AND decode
     * returns 0), while the canonical mark still verifies. */
    uint8_t corpus[32];
    memset(corpus, 0, 32);

    char mark_str[64];
    size_t written = limitless_mirror_mark_sign(corpus, NULL, 0, NULL, 0,
                                                  mark_str, sizeof(mark_str));
    CHECK("noncanon-b64: sign produced 62-char mark", written == 62);
    CHECK("noncanon-b64: pristine canonical mark verifies",
          limitless_mirror_mark_verify_payload(mark_str, corpus, NULL, 0, NULL, 0) == 1);

    /* The last char of the string is mark_str[61] (body chars are
     * mark_str[8..62)). Find an alternative base64url char that shares the
     * same top 2 bits (same decoded value >> 4) but differs in the low bits,
     * so a non-strict decoder would yield the same body. */
    char last = mark_str[61];
    uint8_t dv = limitless_mirror_mark_b64url_decode_char(last);
    int found_alt = 0;
    for (int c = 0; c < 128; c++) {
        uint8_t v = limitless_mirror_mark_b64url_decode_char((char)c);
        if (v == 0xFFu) continue;
        if (v != dv && (uint8_t)(v >> 4) == (uint8_t)(dv >> 4)) {
            char m2[64];
            memcpy(m2, mark_str, sizeof(m2));
            m2[61] = (char)c;
            found_alt = 1;
            /* Non-canonical string must be rejected by verify ... */
            CHECK("noncanon-b64: alt-last-char string rejected by verify",
                  limitless_mirror_mark_verify_payload(m2, corpus, NULL, 0, NULL, 0) == 0);
            /* ... and decode must fail outright (return 0), not silently
             * discard the non-zero trailing bits. */
            uint8_t body[40];
            size_t dec = limitless_mirror_mark_b64url_decode(m2 + 8, 54, body, 40);
            CHECK("noncanon-b64: decode of non-canonical tail returns 0", dec == 0u);
            break;
        }
    }
    CHECK("noncanon-b64: found an alternative trailing char to test", found_alt == 1);

    /* The canonical mark is unaffected: it still decodes to 40 bytes. */
    {
        uint8_t body[40];
        size_t dec = limitless_mirror_mark_b64url_decode(mark_str + 8, 54, body, 40);
        CHECK("noncanon-b64: canonical mark still decodes to 40 bytes", dec == 40u);
    }
}

static void test_cross_prefix_byte_identical(void) {
    /* The three instantiations MUST produce byte-identical output for
     * the same input. This pins the macro-prefix-discrimination property
     * that the prefix is purely a symbol-namespacing concern, not an
     * algorithmic one. */
    const uint8_t input[33] = {
        0x01,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    uint8_t d_ember[32], d_bedrock[32], d_cortex[32], d_default[32];
    ember_hmac_sha256(NULL, 0, input, 33, d_ember);
    bedrock_c_hmac_sha256(NULL, 0, input, 33, d_bedrock);
    cortex_hmac_sha256(NULL, 0, input, 33, d_cortex);
    limitless_hmac_sha256(NULL, 0, input, 33, d_default);
    CHECK("ember == bedrock_c", memcmp(d_ember, d_bedrock, 32) == 0);
    CHECK("ember == cortex",    memcmp(d_ember, d_cortex,  32) == 0);
    CHECK("ember == limitless", memcmp(d_ember, d_default, 32) == 0);
}

static void test_rfc_4231_4_2(void) {
    /* RFC 4231 §4.2: HMAC-SHA256( key = 20 x 0x0b, data = "Hi There" )
     * = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 */
    const uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const char *data = "Hi There";
    uint8_t digest[32];
    limitless_hmac_sha256(key, sizeof(key), (const uint8_t *)data, strlen(data), digest);
    CHECK("RFC 4231 §4.2 test vector",
          hex_equal(digest, 32,
                    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
}

static void test_rfc_4231_4_4_longkey(void) {
    /* RFC 4231 §4.4 -- "Test Using Larger Than Block-Size Key - Hash Key
     * First". key = 131 x 0xaa (> 64-byte SHA-256 block), data = the test
     * string. This exercises the RFC 2104 §2 key-is-hashed-first branch
     * (key' = SHA-256(key)) in the ONE-SHOT limitless_hmac_sha256, which is
     * otherwise NEVER hit by the suite (every other keyed test uses a
     * <=64-byte or empty key).
     *
     * HMAC-SHA256(131 x 0xaa, "Test Using Larger Than Block-Size Key - Hash
     * Key First") =
     *   60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54 */
    uint8_t key[131];
    memset(key, 0xaa, sizeof(key));
    const char *data = "Test Using Larger Than Block-Size Key - Hash Key First";
    uint8_t digest[32];
    limitless_hmac_sha256(key, sizeof(key), (const uint8_t *)data, strlen(data), digest);
    CHECK("RFC 4231 §4.4 long-key (131-byte) test vector",
          hex_equal(digest, 32,
                    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

static void test_rfc_4231_4_5_longkey(void) {
    /* RFC 4231 §4.5 -- same 131 x 0xaa long key, with a larger-than-block-
     * size data block. Pins the key-is-hashed-first branch a second time,
     * with multi-block data, against the published vector.
     *
     * HMAC-SHA256(131 x 0xaa, "This is a test using a larger than
     * block-size key and a larger than block-size data. The key needs to
     * be hashed before being used by the HMAC algorithm.") =
     *   9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2 */
    uint8_t key[131];
    memset(key, 0xaa, sizeof(key));
    const char *data =
        "This is a test using a larger than block-size key and a larger "
        "than block-size data. The key needs to be hashed before being "
        "used by the HMAC algorithm.";
    uint8_t digest[32];
    limitless_hmac_sha256(key, sizeof(key), (const uint8_t *)data, strlen(data), digest);
    CHECK("RFC 4231 §4.5 long-key (131-byte key, multi-block data) test vector",
          hex_equal(digest, 32,
                    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
}

static void test_mirror_mark_longkey_crossimpl_agreement(void) {
    /* Cross-implementation agreement on the key_len > 64 branch.
     *
     * The else-branch key' = SHA-256(key) is implemented TWICE and
     * independently: once in the one-shot limitless_hmac_sha256
     * (limitless_session45_hmac_sha256.h) and once in the manually-streamed
     * limitless_mirror_mark_compute_digest used by sign/verify
     * (limitless_session45_mirror_mark.h). Every other keyed test uses an
     * empty/short key, so the two long-key copies are never cross-checked
     * against each other. This pins them in lockstep: a future off-by-one
     * in the 32-byte key-hash copy, a wrong khash length, or a divergence
     * between the two copies on a long key would break this test.
     *
     * The mark digest is HMAC-SHA256(key, 0x01 || corpus_sha[0..32] ||
     * payload), so we compute the one-shot HMAC over exactly that
     * 0x01-prefixed input and assert the streamed digest extracted from a
     * signed mark equals it -- using a >64-byte key so BOTH take the
     * key-is-hashed-first path. */
    uint8_t corpus[32];
    for (size_t i = 0; i < 32; i++) corpus[i] = (uint8_t)(i + 1u); /* non-trivial corpus */

    const uint8_t payload[5] = { 'h', 'e', 'l', 'l', 'o' };

    uint8_t key[131];
    memset(key, 0xaa, sizeof(key)); /* 131 > 64 -> key-is-hashed-first branch */

    /* Streamed path: sign the mark, then extract the 32-byte digest. */
    char mark_str[64];
    size_t written = limitless_mirror_mark_sign(corpus, payload, sizeof(payload),
                                                 key, sizeof(key),
                                                 mark_str, sizeof(mark_str));
    CHECK("longkey-crossimpl: sign produced 62-char mark", written == 62);

    uint8_t streamed_digest[32];
    int extracted = limitless_mirror_mark_extract_digest(mark_str, streamed_digest);
    CHECK("longkey-crossimpl: extract_digest succeeds", extracted == 1);

    /* One-shot path: HMAC-SHA256(key, 0x01 || corpus || payload). */
    uint8_t signed_input[1 + 32 + sizeof(payload)];
    signed_input[0] = 0x01u;
    memcpy(signed_input + 1, corpus, 32);
    memcpy(signed_input + 1 + 32, payload, sizeof(payload));

    uint8_t oneshot_digest[32];
    limitless_hmac_sha256(key, sizeof(key),
                          signed_input, sizeof(signed_input),
                          oneshot_digest);

    CHECK("longkey-crossimpl: streamed mirror_mark digest == one-shot hmac_sha256 (>64-byte key)",
          memcmp(streamed_digest, oneshot_digest, 32) == 0);

    /* Belt-and-braces: the mark must also verify against the same triple. */
    CHECK("longkey-crossimpl: long-key mark verifies",
          limitless_mirror_mark_verify_payload(mark_str, corpus, payload, sizeof(payload),
                                               key, sizeof(key)) == 1);
}

int main(void) {
    fprintf(stdout, "test_session45_kat -- limitless-c-crypto R151 KAT-1 + macro-prefix verification\n");
    fprintf(stdout, "==============================================================================\n");

    test_kat1_constant_pinned();
    test_sha256_fips_180_4_abc();
    test_sha256_fips_180_4_empty();
    test_sha256_long_input();
    test_rfc_4231_4_2();
    test_rfc_4231_4_4_longkey();
    test_rfc_4231_4_5_longkey();
    test_mirror_mark_longkey_crossimpl_agreement();
    test_ember_kat1_reproduces();
    test_bedrock_c_kat1_reproduces();
    test_cortex_kat1_reproduces();
    test_limitless_default_kat1_reproduces();
    test_mirror_mark_sign_verify_roundtrip();
    test_mirror_mark_kat1_digest_match();
    test_mirror_mark_verify_rejects_tampered_digest();
    test_mirror_mark_rejects_noncanonical_b64();
    test_cross_prefix_byte_identical();

    fprintf(stdout, "==============================================================================\n");
    fprintf(stdout, "Ran %d tests, %d failed.\n", g_tests_run, g_tests_failed);
    return (g_tests_failed == 0) ? 0 : 1;
}
