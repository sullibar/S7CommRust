# TLS test vectors

- `mock-plc-cert.der`, `mock-plc-key.pk8.der` — a self-signed P-256 certificate (CN `mock-plc`)
  and its PKCS#8 private key, generated with OpenSSL for the test-only mock TLS PLC
  (`src/mock_tls.rs`). They protect nothing: never use them outside the tests.
