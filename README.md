# limitless-c-crypto

Header-only C-substrate shared crypto cohort -- SHA-256 + HMAC-SHA256 +
L43 Mirror-Mark v1 + R151 KAT-1 anchor.

Single source of truth for the Limitless C-substrate cohort (ember /
bedrock-c / cortex) consumed via **macro-prefix discrimination**: a
consumer defines `LIMITLESS_C_CRYPTO_PREFIX` before include to rename
exported symbols to its preferred namespace.

**Zero external dependencies.** Pure C11. No libc beyond `<stdint.h>` +
`<stddef.h>`. No malloc. No printf. No FPU. Header-only -- no shared
library to link.

## Cohort consumers

| Substrate | Repo                                     | Prefix       |
|-----------|------------------------------------------|--------------|
| C11       | `flagships/ember`                        | `ember`      |
| C11       | `flagships/bedrock-c`                    | `bedrock_c`  |
| C++20     | `flagships/cortex`                       | `cortex`     |
| (default) | direct callers                           | `limitless`  |

Three flagships today each carry an independent copy of the session45
cluster. Q19 of the 2026-05-25 cross-poll review identified the
convergence: byte-identical algorithm, identical structure, three
substrate-specific symbol prefixes. This repo consolidates the cluster.

## Macro-prefix discrimination (Q19 D4)

```c
#define LIMITLESS_C_CRYPTO_PREFIX ember
#include "limitless_session45_sha256.h"
#include "limitless_session45_hmac_sha256.h"
#include "limitless_session45_kat.h"
#include "limitless_session45_mirror_mark.h"

// -> ember_sha256_ctx, ember_sha256, ember_sha256_init, ...
// -> ember_hmac_sha256, ember_mirror_mark_sign, ember_mirror_mark_verify_payload
```

Symbol prefixes that are macro-renamed include:

- `<prefix>_sha256_ctx` (typedef struct)
- `<prefix>_sha256_init / _update / _finalise / _compress`
- `<prefix>_sha256` (one-shot)
- `<prefix>_hmac_sha256` (one-shot)
- `<prefix>_mirror_mark_sign / _verify_payload / _compute_digest / _extract_digest`
- `<prefix>_mirror_mark_b64url_encode / _decode`
- `<prefix>_mirror_mark_hex_encode`

Symbol prefixes that are NOT macro-renamed (cohort-canonical constants):

- `LIMITLESS_SHA256_DIGEST_LEN` / `_BLOCK_LEN`
- `LIMITLESS_HMAC_SHA256_*`
- `LIMITLESS_MIRROR_MARK_*` (prefix string, version byte, body length, etc.)
- `LIMITLESS_KAT1_*` (the R151 cohort anchor + canonical inputs)

The constant namespace is intentionally shared: every consumer pins the
exact same wire-format constants regardless of prefix. If a consumer
mutates one of these, the firewall test fails.

## R151 KAT-1 anchor

The cohort-canonical HMAC-SHA256 hex anchor:

```
239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

Reproduce via OpenSSL on any UNIX:

```sh
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' $(seq 1 32) >> /tmp/kat1.bin
openssl dgst -sha256 -hmac "" /tmp/kat1.bin
# -> HMAC-SHA2-256(/tmp/kat1.bin)= 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

Or via this repo's test:

```sh
make test
```

## Build

```sh
git clone https://github.com/davly/limitless-c-crypto.git
cd limitless-c-crypto
make test
```

The test rig instantiates the headers four times (ember / bedrock_c /
cortex / default `limitless` prefix) in a single translation unit and
verifies each one independently reproduces the KAT-1 anchor + FIPS PUB
180-4 reference vectors + RFC 4231 §4.2 HMAC test vector + a Mirror-Mark
sign/verify round-trip.

Tested under gcc 16.1.0 (MinGW-W64 ucrt64 x86_64) on Windows + Linux.

## Mirror-Mark v1 wire format

Decoded mark body (40 bytes):

```
body[0..8]   = corpus_sha[0..8]                  -- 8-byte SHA prefix
body[8..40]  = HMAC-SHA256(key, payload_signed)  -- 32-byte digest
```

where `payload_signed = 0x01 || corpus_sha[0..32] || payload[0..n]`.

Wire-encoded mark string:

```
"lore@v1:" + base64url_no_padding(body)
```

For KAT-1 (corpus = 32 x 0x00, payload = empty, key = empty), the digest
matches the cohort anchor `0x239a7d0d…`.

## File index

```
include/
  limitless_session45_sha256.h         -- ~250 LoC -- SHA-256 (FIPS 180-4)
  limitless_session45_hmac_sha256.h    -- ~80 LoC  -- HMAC-SHA256 (RFC 2104)
  limitless_session45_kat.h            -- ~60 LoC  -- R151 KAT-1 constants
  limitless_session45_mirror_mark.h    -- ~280 LoC -- L43 Mirror-Mark v1
test/
  test_session45_kat.c                 -- ~250 LoC -- KAT-1 + cross-prefix + RFC vectors
Makefile                                 -- 30 LoC
README.md                                -- this file
CONTEXT.md                               -- scope + substrate purity discipline
LICENSE                                  -- Apache-2.0
```

Total: ~640 LoC across 4 headers + ~250 LoC test.

## R-rule lineage

- **L43** -- Mirror-Mark v1 (this repo's headers ship the algorithm)
- **R151** -- KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN (KAT-1 anchor
  hex literal + canonical inputs pinned cohort-wide)
- **R145.B** -- SIBLING-NOT-STACKED (each consumer migrates on its own
  additive branch; this shared library lives in its own repo and
  consumers can pin a tag)
- **R145.C** -- FIREWALL-TEST-DISCIPLINE (test/test_session45_kat.c
  pins the KAT-1 hex literal byte-identically across all four
  instantiations)

## What this is NOT

- A production cryptographic library. There is no constant-time compare
  here; no zeroize-on-drop; no FIPS validation suite; no side-channel
  hardening for cache-timing attacks. The Mirror-Mark verify path uses
  early-exit on mismatch (adequate for the verdict-producer-zero-emit-
  surface threat model; defence-in-depth follow-up is documented in
  the cohort impl logs).
- A drop-in replacement for the consumers today. Each consumer (ember /
  bedrock-c / cortex) currently carries its own copy of the cluster;
  migration to this shared library is a per-consumer additive branch
  (replace `<flagship>_session45_*.h` includes with
  `limitless_session45_*.h` + macro prefix). Migration is OUT OF SCOPE
  for this initial commit -- the shared library is the precondition,
  not the migration.
- A new wire format. The wire-format constants are byte-identical to
  the existing cohort.

## License

Apache-2.0 -- same as the rest of the davly cohort.
