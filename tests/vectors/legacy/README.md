# Legacy transport vectors

- `plcsim-session-key.bin`, `plcsim-response-telegram{1,2}.bin` — one response captured from
  PLCSIM Advanced (CPU 1511-1 PN, FW V2.8) over `connect_legacy` on 2026-10-02: the 24-byte
  session key of that (since closed) session and the two COTP payloads the response arrived in.
  The first holds a 975-byte digest chunk, the second a 209-byte chunk and the `72 03 00 00`
  trailer, so the second chunk's digest is the chained one (see `src/legacy/digest.rs`).
