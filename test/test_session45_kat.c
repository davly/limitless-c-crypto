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

int main(void) {
    fprintf(stdout, "test_session45_kat -- limitless-c-crypto R151 KAT-1 + macro-prefix verification\n");
    fprintf(stdout, "==============================================================================\n");

    test_kat1_constant_pinned();
    test_sha256_fips_180_4_abc();
    test_sha256_fips_180_4_empty();
    test_sha256_long_input();
    test_rfc_4231_4_2();
    test_ember_kat1_reproduces();
    test_bedrock_c_kat1_reproduces();
    test_cortex_kat1_reproduces();
    test_limitless_default_kat1_reproduces();
    test_mirror_mark_sign_verify_roundtrip();
    test_mirror_mark_kat1_digest_match();
    test_cross_prefix_byte_identical();

    fprintf(stdout, "==============================================================================\n");
    fprintf(stdout, "Ran %d tests, %d failed.\n", g_tests_run, g_tests_failed);
    return (g_tests_failed == 0) ? 0 : 1;
}
