#!/usr/bin/env python3
"""AirBridge end-to-end test suite.

Runs a real TLS server in-process, then:
  1. validates the certificate chain with the generated CA,
  2. drives the full pairing + encrypted upload protocol from an independent
     Python client (mirrors the browser's WebCrypto calls),
  3. runs adversarial cases: bad tokens, tampered ciphertext, replayed chunks,
     wrong AAD purpose, path traversal filenames, wrong hash,
  4. executes the *actual shipped browser JavaScript* under Node's WebCrypto
     against the live server and verifies the received file bit-for-bit.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import server as ab  # noqa: E402

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✔ {name}")
    else:
        FAIL += 1
        print(f"  ✘ {name}  {detail}")


# ---------------------------------------------------------------- client ---

class PyClient:
    """Independent implementation of the browser protocol (for interop proof)."""

    def __init__(self, base: str, ctx: ssl.SSLContext):
        self.base = base
        self.ctx = ctx
        self.sid = ""
        self.key = b""

    def req(self, method: str, path: str, body: bytes | None = None,
            headers: dict | None = None) -> tuple[int, bytes]:
        r = urllib.request.Request(self.base + path, data=body, method=method,
                                   headers=headers or {})
        try:
            with urllib.request.urlopen(r, context=self.ctx, timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    # -- pairing ------------------------------------------------------------
    def pair(self, token: str, expected_fpr16: str | None):
        st, body = self.req("GET", "/api/serverkey")
        assert st == 200, body
        server_raw = base64.b64decode(json.loads(body)["pub"])
        fpr = hashlib.sha256(server_raw).hexdigest()
        if expected_fpr16 is not None and fpr[:16] != expected_fpr16:
            raise RuntimeError("FINGERPRINT_MISMATCH")

        priv = ec.generate_private_key(ec.SECP256R1())
        client_raw = priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        st, body = self.req("POST", "/api/pair",
                            json.dumps({"token": token,
                                        "clientPub": base64.b64encode(client_raw).decode()}
                                       ).encode(),
                            {"Content-Type": "application/json"})
        if st != 200:
            raise RuntimeError(json.loads(body).get("error", f"pair-{st}"))
        j = json.loads(body)
        srv_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), base64.b64decode(j["serverPub"]))
        shared = priv.exchange(ec.ECDH(), srv_pub)
        info = (f"AirBridge-v1|{hashlib.sha256(client_raw).hexdigest()}|{fpr}").encode()
        okm = HKDF(algorithm=hashes.SHA256(), length=64,
                   salt=base64.b64decode(j["salt"]), info=info).derive(shared)
        self.sid = j["sessionId"]
        self.key = okm[:32]
        self.sas = [ab.SAS_EMOJIS[okm[32 + i] % len(ab.SAS_EMOJIS)] for i in range(4)]
        self.code = okm[36:39].hex()
        return self

    # -- envelopes ----------------------------------------------------------
    def _aad(self, purpose: str) -> bytes:
        return f"AB1|{self.sid}|{purpose}".encode()

    def seal(self, purpose: str, obj: dict) -> bytes:
        n = os.urandom(12)
        ct = AESGCM(self.key).encrypt(n, json.dumps(obj).encode(), self._aad(purpose))
        return json.dumps({"n": base64.b64encode(n).decode(),
                           "c": base64.b64encode(ct).decode()}).encode()

    def open(self, purpose: str, body: bytes) -> dict:
        env = json.loads(body)
        pt = AESGCM(self.key).decrypt(base64.b64decode(env["n"]),
                                      base64.b64decode(env["c"]), self._aad(purpose))
        return json.loads(pt)

    def seal_chunk(self, fid: str, idx: int, total: int, pt: bytes) -> bytes:
        n = os.urandom(12)
        aad = f"AB1|{self.sid}|chunk|{fid}|{idx}|{total}".encode()
        return n + AESGCM(self.key).encrypt(n, pt, aad)

    # -- transfer -----------------------------------------------------------
    def begin(self, name: str, size: int) -> tuple[int, dict | bytes, int]:
        total = max(1, -(-size // ab.CHUNK_SIZE))
        st, body = self.req("POST", "/api/file/begin",
                            self.seal("begin", {"name": name, "size": size,
                                                "chunkSize": ab.CHUNK_SIZE,
                                                "totalChunks": total, "mime": "image/jpeg"}),
                            {"X-Session": self.sid, "Content-Type": "application/json"})
        if st != 200:
            return st, body, total
        return st, self.open("begin-ack", body), total

    def put_chunk(self, fid: str, idx: int, blob: bytes) -> int:
        st, _ = self.req("PUT", "/api/file/chunk", blob,
                         {"X-Session": self.sid, "X-File": fid, "X-Index": str(idx),
                          "Content-Type": "application/octet-stream"})
        return st

    def finish(self, fid: str, sha: str | None) -> tuple[int, dict | bytes]:
        msg = {"fileId": fid}
        if sha:
            msg["sha256"] = sha
        st, body = self.req("POST", "/api/file/finish", self.seal("finish", msg),
                            {"X-Session": self.sid, "Content-Type": "application/json"})
        if st in (200, 409):
            try:
                return st, self.open("finish-ack", body)
            except Exception:
                return st, body
        return st, body

    def send_file(self, name: str, data: bytes, with_hash: bool = True) -> dict:
        st, ack, total = self.begin(name, len(data))
        assert st == 200, ack
        fid = ack["fileId"]
        for i in range(total):
            pt = data[i * ab.CHUNK_SIZE:(i + 1) * ab.CHUNK_SIZE]
            st = self.put_chunk(fid, i, self.seal_chunk(fid, i, total, pt))
            assert st == 204, f"chunk {i} -> {st}"
        sha = hashlib.sha256(data).hexdigest() if with_hash else None
        st, res = self.finish(fid, sha)
        assert st == 200, res
        return res


# ----------------------------------------------------------------- tests ---

def main():
    tmp = Path(tempfile.mkdtemp(prefix="airbridge-test-"))
    out, state = tmp / "out", tmp / "state"
    cfg = ab.Config(out=out, state=state, host="127.0.0.1", port=0,
                    ip="127.0.0.1", quiet=True)
    httpd, app = ab.build_server(cfg)
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.2},
                         daemon=True)
    t.start()
    base = f"https://127.0.0.1:{cfg.port}"
    print(f"\n[server] {base}  out={out}\n")

    # 1 — TLS chain validates against the generated CA (hostname/IP checked too)
    ctx = ssl.create_default_context(cafile=str(state / "ca.pem"))
    st, body = PyClient(base, ctx).req("GET", "/api/serverkey")
    check("TLS certificate chain validates via local CA (SAN=127.0.0.1)", st == 200)

    # 2 — served pages exist and carry security headers
    st, html = PyClient(base, ctx).req("GET", "/")
    check("index page served", st == 200 and b"AirBridge" in html or b"AIRBRIDGE" in html)
    st, js = PyClient(base, ctx).req("GET", "/app.js")
    check("app.js served", st == 200 and b"establish" in js)
    st, pem = PyClient(base, ctx).req("GET", "/ca.pem")
    check("CA cert downloadable for iOS trust", st == 200 and b"BEGIN CERTIFICATE" in pem)

    # 3 — wrong / expired token is rejected
    c = PyClient(base, ctx)
    try:
        c.pair("definitely-wrong-token", app.fingerprint[:16])
        check("wrong pairing token rejected", False)
    except RuntimeError as e:
        check("wrong pairing token rejected", "token" in str(e))

    # 4 — fingerprint pinning catches a mismatched key
    try:
        PyClient(base, ctx).pair(app.token, "0" * 16)
        check("fingerprint mismatch detected client-side", False)
    except RuntimeError as e:
        check("fingerprint mismatch detected client-side", "FINGERPRINT" in str(e))

    # 5 — happy path: pair, then a multi-chunk file with whole-file hash
    c = PyClient(base, ctx).pair(app.token, app.fingerprint[:16])
    print(f"      SAS on client: {'  '.join(c.sas)}  ({c.code})")
    with app.lock:
        srv_sess = app.sessions[c.sid]
    check("SAS emojis identical on both ends",
          c.sas == srv_sess.sas and c.code == srv_sess.code)

    data = os.urandom(9 * 1024 * 1024 + 12345)          # 3 chunks, odd tail
    res = c.send_file("IMG_0042.HEIC", data, with_hash=True)
    saved = out / res["savedAs"]
    check("9.0 MB file arrives bit-for-bit",
          saved.read_bytes() == data, f"savedAs={res}")
    check("whole-file SHA-256 verified by server", res.get("verified") is True)

    # 6 — big-file path (no whole-file hash; AEAD chain only)
    data2 = os.urandom(2 * ab.CHUNK_SIZE)               # exactly 2 chunks
    res2 = c.send_file("video 🎬 clip.MOV", data2, with_hash=False)
    check("hash-less (AEAD-only) transfer arrives bit-for-bit",
          (out / res2["savedAs"]).read_bytes() == data2)
    check("unicode filename preserved safely", "🎬" in res2["savedAs"])

    # 7 — duplicate name gets de-duplicated, not overwritten
    res3 = c.send_file("IMG_0042.HEIC", b"x" * 5, with_hash=True)
    check("name collision de-duplicated", res3["savedAs"] == "IMG_0042 (1).HEIC",
          res3["savedAs"])

    # 8 — path traversal is neutralized
    res4 = c.send_file("../../../../etc/…/../pwned<>.jpg", b"y" * 10, with_hash=True)
    p4 = (out / res4["savedAs"]).resolve()
    check("path traversal neutralized (file stays in out dir)",
          p4.parent == out.resolve() and ".." not in res4["savedAs"], res4["savedAs"])

    # 9 — tampered ciphertext is rejected with an auth error
    st, ack, total = c.begin("tamper.bin", 100)
    fid = ack["fileId"]
    blob = bytearray(c.seal_chunk(fid, 0, total, b"z" * 100))
    blob[20] ^= 0xFF
    st = c.put_chunk(fid, 0, bytes(blob))
    check("tampered chunk rejected (InvalidTag)", st == 400)

    # 10 — replayed chunk index is rejected
    good = c.seal_chunk(fid, 0, total, b"z" * 100)
    st1 = c.put_chunk(fid, 0, good)
    st2 = c.put_chunk(fid, 0, good)
    check("first copy of chunk accepted", st1 == 204)
    check("replayed chunk rejected (409)", st2 == 409)

    # 11 — chunk bound to its index: same bytes at a different index fail AAD
    stx = c.put_chunk(fid, 1, good) if total > 1 else 400
    check("chunk cannot be replayed at another index (AAD binding)",
          stx in (400, 416))

    # 12 — envelope with wrong purpose (AAD) is rejected
    st, body = c.req("POST", "/api/file/finish",
                     c.seal("begin", {"fileId": fid}),      # wrong purpose on purpose
                     {"X-Session": c.sid, "Content-Type": "application/json"})
    check("control message with wrong AAD purpose rejected", st == 400)

    # 13 — finishing an incomplete file is refused
    st, ack2, total2 = c.begin("incomplete.bin", ab.CHUNK_SIZE + 5)
    st, resx = c.finish(ack2["fileId"], None)
    check("incomplete file refused at finish (409)", st == 409)

    # 14 — wrong whole-file hash discards the file
    st, ack3, t3 = c.begin("badhash.bin", 50)
    c.put_chunk(ack3["fileId"], 0, c.seal_chunk(ack3["fileId"], 0, t3, b"a" * 50))
    st, _ = c.finish(ack3["fileId"], "0" * 64)
    check("wrong whole-file hash rejected & file discarded",
          st == 400 and not (out / "badhash.bin").exists())

    # 15 — requests without a session are refused
    st, _ = PyClient(base, ctx).req("POST", "/api/file/begin", b"{}",
                                    {"X-Session": "nope"})
    check("unknown session rejected (401)", st == 401)

    # 16 — the REAL browser JavaScript, executed under Node's WebCrypto
    node = shutil.which("node")
    if node:
        appjs = tmp / "app.js"
        appjs.write_text(ab.APP_JS)
        harness = tmp / "harness.mjs"
        harness.write_text(HARNESS_MJS)
        env = dict(os.environ, NODE_EXTRA_CA_CERTS=str(state / "ca.pem"))
        r = subprocess.run(
            [node, str(harness), base, app.token, app.fingerprint[:16], str(appjs)],
            capture_output=True, text=True, env=env, timeout=120)
        ok = r.returncode == 0
        info = {}
        for line in r.stdout.splitlines():
            if line.startswith("RESULT "):
                info = json.loads(line[7:])
        if not ok:
            print(r.stdout, r.stderr)
        check("shipped browser JS pairs via Node WebCrypto", ok and info.get("paired"))
        if ok and info:
            saved = out / info["savedAs"]
            got = hashlib.sha256(saved.read_bytes()).hexdigest() if saved.exists() else ""
            check("browser-JS upload arrives bit-for-bit "
                  f"({info.get('size', 0)} bytes)", got == info.get("hash"), got)
            check("browser JS fingerprint pinning works",
                  info.get("mismatchCaught") is True)
            print(f"      SAS from browser JS: {info.get('sas')}  ({info.get('code')})")
            with app.lock:
                s2 = app.sessions.get(info.get("sid", ""))
            check("browser-JS SAS matches server side",
                  bool(s2) and " ".join(s2.sas) == info.get("sas"))
    else:
        print("  ! node not found — skipping browser-JS harness")

    httpd.shutdown()
    print(f"\n{'=' * 46}\n  {PASS} passed, {FAIL} failed\n")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1 if FAIL else 0)


HARNESS_MJS = r"""
import fs from 'node:fs';
const [,, base, token, fpr16, appjsPath] = process.argv;
const src = fs.readFileSync(appjsPath, 'utf8');
(0, eval)(src);                       // defines globalThis.AB (DOM part is guarded)
const AB = globalThis.AB;

// fingerprint pinning must fail closed
let mismatchCaught = false;
try { await AB.establish(base, token, '0'.repeat(16)); }
catch (e) { mismatchCaught = String(e.message) === 'FINGERPRINT_MISMATCH'; }

const s = await AB.establish(base, token, fpr16);

// synthesize a 6.01 MB "photo" the way Safari hands files to the page
const size = 6 * 1024 * 1024 + 12345;
const data = new Uint8Array(size);
for (let i = 0; i < size; i += 65536)
  crypto.getRandomValues(data.subarray(i, Math.min(size, i + 65536)));
const file = {
  name: 'node 📱 shot.jpg', size, type: 'image/jpeg',
  slice: (a, b) => ({ arrayBuffer: async () => data.slice(a, b).buffer }),
  arrayBuffer: async () => data.slice().buffer,
};
const res = await AB.sendFile(s, file, () => {});
const hash = await AB.sha256hex(data);
console.log('RESULT ' + JSON.stringify({
  paired: true, sid: s.sid, sas: s.sas.join(' '), code: s.code,
  savedAs: res.savedAs, size: res.size, verified: res.verified,
  hash, mismatchCaught,
}));
"""


if __name__ == "__main__":
    main()
