# Family0 golden vectors

Fixtures for the legacy S7-1200/1500 (`00:`/`01:` key family) authentication in
`src/legacy/family0/`.

- `auth/` — the byte-exact `AuthenticateRealPlc` vectors (S7-1500 and two S7-1200 cases) from
  [`bonk-dev/HarpoS7`](https://github.com/bonk-dev/HarpoS7)'s
  `LegacyAuthenticationSchemeTests.cs`: the 180-byte blob, the session key and the request.
- `transforms/` — HarpoS7 `HarpoS7.Family0.Tests/Blobs` vectors for `PreSeedTransform`
  (`transform1-src`: key1), `LutGenerator` (`transform3`), `ChecksumTransform` (`transform4`) and
  `SeedTransform` (`transform6`).
- `differential.txt` — 48 handshakes recorded from HarpoS7's original monolith implementation
  (Transform7, Monolith1–11, Transform12/13) before it was replaced by the ECDH/PRESENT-80 code,
  covering all 16 bundled public keys and random curve/twist x-coordinates. One case per line:
  `family fill_seed public_key challenge blob session_key` (hex; `fill_seed` seeds the
  SplitMix64 fill in the test).

The HarpoS7 fixtures are MIT-licensed; see `LICENSE-HarpoS7` at the repo root.
