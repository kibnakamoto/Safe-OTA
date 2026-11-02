# SafeOTA threat model

**Assets:** firmware integrity, device availability (never bricked), version monotonicity, the device key.
**Attacker can:** supply arbitrary update images (malicious server or man-in-the-middle), replay old images, cut power at any moment, and corrupt stored flash bits.
**Assumed out of the attacker's reach:** the device key and the updater code itself.

| STRIDE | Threat | Mitigation | Test that covers it |
|---|---|---|---|
| Spoofing | Forged image from an attacker | HMAC-SHA256 over the header, checked in RAM before any flash write and again from flash at every boot | forged MAC rejected, flash untouched |
| Tampering | Edited payload or header (including the version field) | SHA-256 digest inside the MAC'd header; length and bounds checks | tampered payload, edited version, oversized image |
| Tampering | Silent corruption of stored firmware | Boot-time re-verification, fall back to the other slot | bit-rot test boots v1 |
| Denial of service | Power loss during update or recovery | Verify before commit, ping-pong CRC metadata, single atomic commit | 414 injected power cuts, 0 bricked |
| Denial of service | Authentic but broken image | Trial boots with automatic rollback if never confirmed | crash-loop test rolls back to v1 |
| Elevation of privilege | Downgrade or replay of an old vulnerable image | Anti-rollback version floor, raised on confirm | downgrade and same-version re-install rejected |

**Mutation testing** shows the tests have teeth: removing atomic commit, anti-rollback, or authentication each makes the suite fail.

## Known gaps (not addressed)

- **Shared-key HMAC:** compromise of one device key compromises the update channel. A real design uses asymmetric signatures (for example Ed25519) with the public key in ROM.
- **No verified boot chain:** the updater itself is not authenticated by ROM.
- **No confidentiality:** images are not encrypted.
- **No key rotation or revocation**, and no defense against voltage or clock glitching beyond power loss.
- **Side channels:** only the constant-time comparison is addressed.
