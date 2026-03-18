# PQClean Patches

This directory tracks every modification made to vendored PQClean sources
under `ext/ml_dsa/ml-dsa-{44,65,87}/`.

## Why we patch

FIPS 204 §3 allows both **hedged** signing (randomised `rnd`) and
**deterministic** signing (`rnd = 0^{32}`).  The upstream PQClean
`crypto_sign_signature_ctx` function generates `rnd` internally via
`randombytes`.  That couples the randomness source to the signing function and
makes deterministic testing impossible without mocking.

Our patch adds an explicit `const uint8_t *rnd_in` parameter so that:

* The **caller** (i.e. `ml_dsa_ext.c`) controls whether signing is hedged or
  deterministic.
* The C implementation stays free of any Ruby-level state.
* Deterministic KAT vectors can be reproduced without patching `randombytes`.

## Files modified

For each of `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`:

| File | Change |
|------|--------|
| `clean/api.h` | Added `const uint8_t *rnd_in` as last argument to `crypto_sign_signature_ctx` |
| `clean/sign.h` | Same declaration change |
| `clean/sign.c` | Implementation: replaced internal `randombytes(rnd, RNDBYTES)` call with `memcpy(rnd, rnd_in, RNDBYTES)` |

## Applying the patch

```sh
patch -p1 < patches/pqclean-explicit-rnd.patch
```

Run from the repository root.  After applying, recompile with:

```sh
bundle exec rake compile
```

## Verifying the patch matches vendored sources

```sh
bundle exec rake pqclean:verify
```

This task diffs the three `sign.c` / `sign.h` / `api.h` files against the
patch to confirm no untracked drift has occurred.

## PQClean upstream commit

Vendored from PQClean commit `main` as of initial gem creation.  No other
changes were made to the PQClean sources.
