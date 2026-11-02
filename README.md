# SafeOTA

A power-loss-safe, authenticated A/B firmware updater in C11, verified by cutting power at every flash write.

**Results** (`make test`, `make asan`, `make mutants`):

| Check | Result |
|---|---|
| Injected power cuts during install, recovery boot, first trial boot and confirm | 414 scenarios (58 single cut, 348 double fault, 8 boot/confirm) |
| Bricked devices after any of them | **0** |
| AddressSanitizer + UBSan | clean |
| Seeded design bugs caught by the tests (mutation testing) | **3 of 3** |

## How it works

```
flash: [meta A][meta B][slot 0][slot 1]
update: authenticate image in RAM -> erase + write inactive slot -> read back and verify
        -> commit metadata atomically (ping-pong, CRC32) -> trial boots -> app confirms
        -> unconfirmed after 3 boots = automatic rollback
```

- **Atomic commit.** Metadata is two CRC-protected records written alternately; the older sector is overwritten, so a cut always leaves one valid record.
- **Verify before and after writing.** Images carry SHA-256 and HMAC-SHA256; they are checked in RAM before any flash write, read back from flash, and re-checked at every boot, with fallback to the other slot if the active one is damaged.
- **Anti-rollback.** Versions at or below the confirmed floor are rejected.
- **Constant-time comparison** for digests and MACs.

## How it is tested

- **Simulated NOR flash** with real semantics: erase sets 0xFF, programming can only clear bits, so code that forgets to erase produces garbage.
- **Exhaustive fault injection.** Power is cut before and halfway through every erase and program, then again during the recovery boot.
- **Independent oracle.** After every scenario the test re-verifies the booted slot with its own hash and MAC code, not the updater's.
- **Mutation testing.** `-DMUT_A` commits before writing and skips boot verification (devices brick), `-DMUT_C` removes anti-rollback, `-DMUT_D` skips authentication. The suite must fail on all three.
- Also covered: forged, tampered and oversized images (flash must stay untouched), downgrade attempts, and silent bit corruption of the active slot.

## Limitations

- Runs on a **host-side flash simulator**, not real hardware.
- Authentication is **HMAC-SHA256 with a shared device key**. A production design would use asymmetric signatures (for example Ed25519) with the public key in ROM and a verified boot chain.
- Torn writes are modeled at byte granularity, not individual bits; no wear leveling, delta updates or encryption.
- SHA-256 and HMAC are included for portability and checked against standard test vectors; production code should use a vetted library.

## Roadmap

Port the flash layer to Linux MTD/eMMC, add Ed25519 verification, resumable downloads, a Yocto recipe, and an update server.

```
make test        # unit, power-cut and attack tests
make asan        # same tests under AddressSanitizer and UBSan
make mutants     # the tests must fail on each seeded bug
```

See [THREAT_MODEL.md](THREAT_MODEL.md) for the STRIDE analysis and known gaps.
