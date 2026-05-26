# limitless-c-crypto -- CONTEXT

## Scope (what this repo is)

Four header-only C11 files implementing:

1. **SHA-256** (FIPS PUB 180-4)
2. **HMAC-SHA256** (RFC 2104 / FIPS PUB 198-1)
3. **R151 KAT-1 constants** (cohort cross-substrate anchor)
4. **L43 Mirror-Mark v1** (cohort wire-form sign / verify)

Plus a single-translation-unit test rig that instantiates the cluster
four times under four different macro-prefix discriminations
(`LIMITLESS_C_CRYPTO_PREFIX = ember | bedrock_c | cortex | limitless`
default) and verifies each one independently reproduces the KAT-1
cohort anchor.

## Substrate purity discipline

- **Zero non-stdlib dependencies.** The headers include only
  `<stdint.h>` + `<stddef.h>` (freestanding C11). The test rig adds
  `<stdio.h>` + `<string.h>` (test-only, never #included in production
  headers).
- **No malloc.** All buffers are stack-allocated. The largest stack
  frame is the HMAC working block (192 B for key_block + ipad + opad).
- **No FPU.** No `<math.h>`, no float, no double.
- **No printf in production headers.** Production headers contain pure
  computation and stack-bounded I/O on caller buffers.
- **No global mutable state.** All state is in caller-supplied context
  buffers. The KAT-1 canonical input / key arrays are `static const`
  (each translation unit gets its own private copy at compile time
  per the macro-prefix scheme).
- **Header-only.** No `.c` files; no shared library to link. Consumers
  `#include` the headers and the inline functions are emitted per
  translation unit.

## Macro-prefix discrimination (Q19 D4)

The cohort surfaced three independent flagships (ember / bedrock-c /
cortex) each shipping a verbatim copy of the same algorithm with a
different symbol prefix. Q19 identified the convergence; D4 named the
fix as macro-prefix-rename.

```c
#define LIMITLESS_C_CRYPTO_PREFIX ember
#include "limitless_session45_sha256.h"
// -> static inline void ember_sha256_init(ember_sha256_ctx *ctx);
//    static inline void ember_sha256(...);
//    static inline void ember_hmac_sha256(...);
//    etc.
```

The scheme works because:

1. **Symbol-renaming is the only difference** between the three existing
   per-flagship copies (verified by Q19 byte-by-byte diff modulo prefix
   substitution).
2. **Header-guard structure** uses one header guard per file
   (LIMITLESS_SESSION45_*_H) plus per-symbol prefix expansion at the
   call sites. The test rig `#undef`s the guard between instantiations
   to re-emit the inline definitions under each prefix.
3. **Constants are NOT prefixed.** Wire-format constants
   (LIMITLESS_KAT1_DIGEST_HEX, LIMITLESS_MIRROR_MARK_PREFIX, etc.) are
   cohort-canonical regardless of which consumer is including the
   header -- mutating them is a wire-format change and a firewall break.

## Cohort consumers (deferred migration)

This repo is the precondition for three consumer migrations:

- **flagships/ember** -- replace `ember_session45_*.h` cluster with
  `#define LIMITLESS_C_CRYPTO_PREFIX ember` + this shared library.
- **flagships/bedrock-c** -- replace `bedrock_c_session45_*.h` cluster
  with `#define LIMITLESS_C_CRYPTO_PREFIX bedrock_c` + this shared
  library.
- **flagships/cortex** -- replace `cortex/session45/session45_*.hpp`
  cluster with `#define LIMITLESS_C_CRYPTO_PREFIX cortex` + this
  shared library (C++ build accepts the C11 headers via `extern "C"`).

Each migration is a per-consumer additive branch (R145.B
SIBLING-NOT-STACKED). The migrations are OUT OF SCOPE for this
initial commit.

## Apache 2.0

All files are Apache-2.0, matching the rest of the davly cohort.

## File index

```
include/limitless_session45_sha256.h        -- SHA-256 (FIPS 180-4)
include/limitless_session45_hmac_sha256.h   -- HMAC-SHA256 (RFC 2104)
include/limitless_session45_kat.h           -- R151 KAT-1 constants
include/limitless_session45_mirror_mark.h   -- L43 Mirror-Mark v1
test/test_session45_kat.c                   -- KAT-1 + macro-prefix tests
Makefile                                    -- `make test`
README.md                                   -- consumer overview
CONTEXT.md                                  -- this file (scope + purity)
LICENSE                                     -- Apache-2.0
```

## R-rule lineage

- **L43** Mirror-Mark v1 -- algorithm shipped in this repo
- **R151** KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN -- KAT-1 hex
  literal + canonical inputs pinned
- **R145.B** SIBLING-NOT-STACKED -- shared library lives in its own
  repo; per-consumer migrations are independent additive branches
- **R145.C** FIREWALL-TEST-DISCIPLINE -- test/test_session45_kat.c
  pins KAT-1 byte-identically across four instantiations + FIPS 180-4
  reference vectors + RFC 4231 §4.2 vector + Mirror-Mark round-trip
