# Security Policy

AirBridge exists to move private photos and videos safely across a local
network, so security reports are taken seriously and handled with priority.

## Reporting a vulnerability

Please **do not open a public issue** for anything you believe is exploitable.
Instead use GitHub's private **"Report a vulnerability"** button under the
*Security* tab of this repository (GitHub Security Advisories). You should
receive a response within a few days. Coordinated disclosure is appreciated;
credit will be given in the release notes unless you prefer otherwise.

Reports very welcome, including but not limited to:

- key agreement / derivation flaws (ECDH, HKDF usage)
- AES-GCM nonce or AAD misuse, chunk splicing across files or sessions
- pairing-token bypass, rate-limit bypass, session fixation
- path traversal or file-write escapes despite sanitization
- TLS/certificate-generation weaknesses
- anything that lets a same-network attacker read or alter media in transit

## Scope notes (known, documented trade-offs)

- Without installing the local CA on the phone, a *full active MITM that
  rewrites the delivered JavaScript* is theoretically possible on first
  contact — this is inherent to browser-delivered crypto over an untrusted
  certificate and is documented in the README, along with the CA-install
  procedure that closes it. Reports demonstrating attacks that work *despite*
  the QR-fragment fingerprint check are absolutely in scope.
- Denial of service by flooding the port from the local network is out of
  scope (LAN-local tool), though bypasses of the built-in rate limits are
  still interesting.

## Supported versions

Only the latest release/main branch receives security fixes.

## Design summary (what you are attacking)

Ephemeral ECDH P-256 per session → HKDF-SHA256 (both public-key hashes bound
into `info`) → AES-256-GCM per 4 MiB chunk with random 96-bit nonces; AAD
binds `protocol | session | file | chunk index | total`. Server key
fingerprint travels out-of-band in the QR URL **fragment**. One-time pairing
tokens (constant-time compare, TTL), per-IP rate limits, strict size caps,
sandboxed filenames, whole-file SHA-256 for files ≤ 64 MiB. TLS 1.2+ from a
locally generated CA underneath everything.
