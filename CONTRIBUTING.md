# Contributing to AirBridge

Thanks for your interest! AirBridge is deliberately a **single-file server**
(`server.py`, with the browser client embedded) plus tests — please keep that
property unless there's a very strong reason not to. Zero-dependency-beyond-
`cryptography`/`qrcode`, zero build step, copy-one-file-and-run is the point.

## Dev setup

```bash
git clone <your-fork>
cd airbridge
./run.sh --help          # creates .venv and installs deps on first run
```

## Running the tests

```bash
source .venv/bin/activate
python3 test_e2e.py      # 25 checks incl. the shipped browser JS under Node
python3 test_stress.py   # concurrent multi-device upload
```

`test_e2e.py` executes the **actual embedded JavaScript** under Node's
WebCrypto (Node ≥ 18 required for the full suite; the Python-only checks run
without it). Both suites must pass before a PR is merged — CI runs them on
every push.

## Invariants you must not break

The Python server and the embedded JS client implement the same wire
protocol. These constants/behaviors are mirrored on both sides — change them
in lockstep or interop silently breaks:

- `PROTO = "AB1"`, `CHUNK_SIZE = 4 MiB`, 12-byte GCM nonces, 16-byte tags
- HKDF output length 64; `info = "AirBridge-v1|sha256(clientPub)|sha256(serverPub)"` (hex)
- ECDH public keys as raw uncompressed 65-byte P-256 points, base64 (standard alphabet)
- chunk AAD `AB1|{sid}|chunk|{fid}|{idx}|{total}`; envelope AAD `AB1|{sid}|{purpose}`
- `SAS_EMOJIS`: same 32 emojis in the same order in Python and JS — never reorder
- the fingerprint travels only in the URL **fragment** — never move it into a
  query parameter or header

Any change to the protocol should bump `AirBridge-v1` in the HKDF info string.

## Security-sensitive changes

Anything touching crypto, pairing, file paths, or headers needs:

1. a test demonstrating the new behavior (and, for defenses, a test proving
   the attack now fails),
2. a short note in the PR describing the threat-model impact,
3. no new third-party dependencies without prior discussion.

For suspected vulnerabilities, see [SECURITY.md](SECURITY.md) — please don't
open public issues.

## Style

- Python: standard library first; keep functions small; no framework
  imports. `ruff`/`flake8` clean is appreciated but not enforced.
- JS: vanilla, no build step, must run in Safari iOS 15+ and under Node ≥ 18
  (that's how the tests execute it).
- Commit messages: imperative mood, first line ≤ 72 chars.

## Ideas that would make good first PRs

- resumable transfers after a dropped connection
- optional Zeroconf/Bonjour advertisement (still QR-verified)
- desktop notification on completed file
- translations of the phone UI
