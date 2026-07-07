#!/usr/bin/env python3
"""
AirBridge — end-to-end encrypted iPhone → Linux media transfer over local Wi-Fi.

  Run:      python3 server.py
  Then:     scan the QR code with the iPhone camera, accept the certificate,
            verify the four emojis match, and pick photos/videos.

Security model (layered):
  1. TLS 1.2+ using a locally generated CA (optionally installable on iOS for
     fully validated transport).
  2. Application-level end-to-end encryption *independent of TLS*:
       - Ephemeral ECDH (NIST P-256) key agreement per session.
       - The server key's SHA-256 fingerprint travels inside the QR code's URL
         *fragment* (never sent over the network), so the phone authenticates
         the server out-of-band — an on-network man-in-the-middle cannot forge it.
       - HKDF-SHA256 -> AES-256-GCM. Every chunk is sealed with additional
         authenticated data binding (session | file | chunk index | total),
         preventing tampering, reordering, replay and truncation.
       - A 4-emoji Short Authentication String is derived on both ends for
         human verification.
  3. One-time pairing tokens with expiry, per-IP rate limiting, strict size
     caps, filename sandboxing, and constant-time comparisons.

Dependencies: cryptography (required), qrcode (optional, for the terminal QR).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.exceptions import InvalidTag
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:  # pragma: no cover
    sys.exit("AirBridge needs the 'cryptography' package:  pip install cryptography")

APP_NAME = "AirBridge"
VERSION = "1.0.0"
PROTO = "AB1"                      # wire protocol tag used in all AAD strings
CHUNK_SIZE = 4 * 1024 * 1024       # 4 MiB plaintext chunks
GCM_NONCE = 12
GCM_TAG = 16
MAX_JSON_BODY = 64 * 1024
MAX_SESSIONS = 16
MAX_FILES_PER_SESSION = 1000
PAIR_RATE = (10, 60.0)             # max pair attempts per IP per window seconds

# Emoji alphabet for the Short Authentication String.
# The JavaScript client embeds the *identical* list — do not reorder.
SAS_EMOJIS = [
    "🦊", "🐙", "🦉", "🐢", "🦋", "🐳", "🌵", "🍄",
    "🌻", "🍀", "🌊", "⛰️", "🌙", "⭐", "🔥", "❄️",
    "🍎", "🍋", "🥑", "🍩", "🎈", "🎩", "🎲", "🎸",
    "🚀", "⚓", "🔑", "🧭", "🛰️", "💎", "🧲", "☂️",
]


# --------------------------------------------------------------------------
# small utilities
# --------------------------------------------------------------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str, max_len: int = 10 * 1024 * 1024) -> bytes:
    if not isinstance(s, str) or len(s) > max_len:
        raise ValueError("bad base64 field")
    return base64.b64decode(s, validate=True)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def sas_from(seed: bytes) -> tuple[list[str], str]:
    """4-emoji SAS + 6-hex-char code, derived from HKDF output bytes 32..38."""
    emojis = [SAS_EMOJIS[seed[i] % len(SAS_EMOJIS)] for i in range(4)]
    return emojis, seed[4:7].hex()


def safe_filename(name: str) -> str:
    """Reduce an untrusted filename to a safe basename (no traversal, no control chars)."""
    name = str(name).replace("\\", "/")
    name = os.path.basename(name).strip()
    name = re.sub(r'[\x00-\x1f\x7f<>:"|?*]', "_", name)
    name = name.lstrip(". ").rstrip(". ")
    if not name:
        name = f"file-{secrets.token_hex(4)}"
    if len(name) > 180:
        stem, dot, ext = name.rpartition(".")
        if dot and len(ext) <= 12:
            name = stem[: 180 - len(ext) - 1] + "." + ext
        else:
            name = name[:180]
    return name


def lan_ips() -> list[str]:
    """Best-effort discovery of this machine's LAN IPv4 addresses."""
    ips: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                ips.append(ip)
        finally:
            s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips or ["127.0.0.1"]


# --------------------------------------------------------------------------
# terminal UI (thread-safe single status line + log lines)
# --------------------------------------------------------------------------

class UI:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self._lock = threading.Lock()
        self._status = ""
        self._tty = sys.stdout.isatty()

    def _clear(self):
        if self._status and self._tty:
            sys.stdout.write("\r\x1b[K")

    def _paint(self):
        if self._status and self._tty:
            sys.stdout.write("\r\x1b[K" + self._status)
            sys.stdout.flush()

    def log(self, msg: str):
        if self.quiet:
            return
        with self._lock:
            self._clear()
            print(msg)
            self._paint()

    def warn(self, msg: str):
        # warnings are printed even in quiet mode (tests want to see security events)
        with self._lock:
            self._clear()
            print(msg, file=sys.stderr)
            self._paint()

    def status(self, text: str):
        if self.quiet:
            return
        with self._lock:
            if text == self._status:
                return
            self._status = text
            if self._tty:
                self._paint()

    def clear_status(self):
        if self.quiet:
            return
        with self._lock:
            self._clear()
            self._status = ""
            sys.stdout.flush()


# --------------------------------------------------------------------------
# local certificate authority + server certificate
# --------------------------------------------------------------------------

class CertStore:
    """Creates and persists a tiny local CA and a server certificate whose
    SubjectAltNames cover this machine's current LAN IPs."""

    def __init__(self, state_dir: Path):
        self.dir = state_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        self.ca_key_path = self.dir / "ca.key"
        self.ca_pem_path = self.dir / "ca.pem"
        self.srv_key_path = self.dir / "server.key"
        self.srv_pem_path = self.dir / "server.pem"

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _write_key(path: Path, key):
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _ensure_ca(self):
        if self.ca_key_path.exists() and self.ca_pem_path.exists():
            key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), None)
            cert = x509.load_pem_x509_certificate(self.ca_pem_path.read_bytes())
            return key, cert
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{APP_NAME} Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, APP_NAME),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        self._write_key(self.ca_key_path, key)
        self.ca_pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return key, cert

    def _server_cert_ok(self, needed_ips: set[str]) -> bool:
        if not (self.srv_key_path.exists() and self.srv_pem_path.exists()):
            return False
        try:
            cert = x509.load_pem_x509_certificate(self.srv_pem_path.read_bytes())
            if cert.not_valid_after_utc < datetime.now(timezone.utc) + timedelta(days=30):
                return False
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            have = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
            return needed_ips.issubset(have)
        except Exception:
            return False

    def ensure(self, ips: list[str]) -> tuple[Path, Path, Path]:
        """Returns (server_cert, server_key, ca_pem), regenerating as needed."""
        ca_key, ca_cert = self._ensure_ca()
        needed = set(ips) | {"127.0.0.1"}
        if self._server_cert_ok(needed):
            return self.srv_pem_path, self.srv_key_path, self.ca_pem_path

        key = ec.generate_private_key(ec.SECP256R1())
        hostname = socket.gethostname() or "airbridge"
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{APP_NAME} on {hostname}"[:64]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, APP_NAME),
        ])
        alt: list[x509.GeneralName] = [x509.DNSName("localhost")]
        if re.fullmatch(r"[A-Za-z0-9.-]{1,63}", hostname or ""):
            alt.append(x509.DNSName(hostname))
        for ip in sorted(needed):
            try:
                alt.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=True, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        self._write_key(self.srv_key_path, key)
        self.srv_pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return self.srv_pem_path, self.srv_key_path, self.ca_pem_path


# --------------------------------------------------------------------------
# session + file state
# --------------------------------------------------------------------------

class FileRx:
    __slots__ = ("fid", "name", "size", "cs", "total", "last_len", "received",
                 "fh", "tmp", "bytes", "t0", "lock")

    def __init__(self, fid: str, name: str, size: int, cs: int, tmp: Path):
        self.fid = fid
        self.name = name
        self.size = size
        self.cs = cs
        self.total = max(1, -(-size // cs))
        self.last_len = size - (self.total - 1) * cs
        self.received: set[int] = set()
        self.tmp = tmp
        self.fh = open(tmp, "wb+")
        self.bytes = 0
        self.t0 = time.monotonic()
        self.lock = threading.Lock()


class Session:
    def __init__(self, sid: str, key: bytes, sas: list[str], code: str, addr: str):
        self.sid = sid
        self.key = key
        self.aes = AESGCM(key)
        self.sas = sas
        self.code = code
        self.addr = addr
        self.created = time.time()
        self.files: dict[str, FileRx] = {}
        self.lock = threading.Lock()

    # authenticated JSON envelopes (client <-> server control messages)
    def _aad(self, purpose: str) -> bytes:
        return f"{PROTO}|{self.sid}|{purpose}".encode()

    def open_json(self, body: bytes, purpose: str) -> dict:
        env = json.loads(body.decode("utf-8"))
        nonce = b64d(env["n"], 64)
        ct = b64d(env["c"], MAX_JSON_BODY * 2)
        if len(nonce) != GCM_NONCE:
            raise ValueError("bad nonce")
        pt = self.aes.decrypt(nonce, ct, self._aad(purpose))
        return json.loads(pt.decode("utf-8"))

    def seal_json(self, obj: dict, purpose: str) -> bytes:
        nonce = os.urandom(GCM_NONCE)
        pt = json.dumps(obj, separators=(",", ":")).encode()
        ct = self.aes.encrypt(nonce, pt, self._aad(purpose))
        return json.dumps({"n": b64e(nonce), "c": b64e(ct)}).encode()


@dataclass
class Config:
    out: Path
    state: Path
    host: str = "0.0.0.0"
    port: int = 8443
    ip: str | None = None            # address advertised in the QR code
    token_ttl: int = 15 * 60
    max_file_gb: float = 25.0
    quiet: bool = False
    no_qr: bool = False


class AppState:
    def __init__(self, cfg: Config, ui: UI):
        self.cfg = cfg
        self.ui = ui
        self.lock = threading.Lock()

        # ephemeral pairing identity for this run (forward secrecy across runs)
        self.ecdh_priv = ec.generate_private_key(ec.SECP256R1())
        self.server_pub_raw = self.ecdh_priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.fingerprint = sha256_hex(self.server_pub_raw)

        self.token = ""
        self.token_exp = 0.0
        self.new_token()

        self.sessions: dict[str, Session] = {}
        self.pair_hits: dict[str, deque] = {}

        # rolling throughput window for the status line
        self._rx = deque()           # (t, cumulative_bytes)
        self._rx_total = 0

        self.parts = cfg.out / ".airbridge-parts"
        self.parts.mkdir(parents=True, exist_ok=True)

    # -- tokens -------------------------------------------------------------
    def new_token(self):
        self.token = secrets.token_urlsafe(9)
        self.token_exp = time.time() + self.cfg.token_ttl

    def token_ok(self, tok: str) -> bool:
        if time.time() > self.token_exp:
            return False
        return hmac.compare_digest(str(tok).encode(), self.token.encode())

    def rate_ok(self, ip: str) -> bool:
        limit, window = PAIR_RATE
        now = time.time()
        with self.lock:
            dq = self.pair_hits.setdefault(ip, deque())
            while dq and now - dq[0] > window:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True

    # -- throughput ---------------------------------------------------------
    def note_rx(self, n: int):
        now = time.monotonic()
        with self.lock:
            self._rx_total += n
            self._rx.append((now, self._rx_total))
            while self._rx and now - self._rx[0][0] > 2.5:
                self._rx.popleft()

    def speed(self) -> float:
        with self.lock:
            if len(self._rx) < 2:
                return 0.0
            (t0, b0), (t1, b1) = self._rx[0], self._rx[-1]
            dt = t1 - t0
            return (b1 - b0) / dt if dt > 0 else 0.0

    def active_files(self) -> list[FileRx]:
        out = []
        with self.lock:
            sessions = list(self.sessions.values())
        for s in sessions:
            with s.lock:
                out.extend(s.files.values())
        return out


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/{VERSION}"
    protocol_version = "HTTP/1.1"

    # silence default request logging; we render our own UI
    def log_message(self, fmt, *args):  # noqa: N802
        pass

    def handle(self):
        try:
            super().handle()
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError):
            pass  # browsers probing / rejecting the self-signed cert is normal noise

    # -- plumbing -----------------------------------------------------------
    @property
    def app(self) -> AppState:
        return self.server.app  # type: ignore[attr-defined]

    def _security_headers(self, html: bool = False):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        if html:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'",
            )

    def _send(self, code: int, body: bytes, ctype: str, html: bool = False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers(html=html)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _deny(self, code: int, err: str):
        self._json(code, {"error": err})

    def _body(self, cap: int) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._deny(411, "length-required")
            return None
        if length < 0 or length > cap:
            self._deny(413, "too-large")
            return None
        data = self.rfile.read(length)
        if len(data) != length:
            raise ConnectionResetError
        return data

    def _session(self) -> Session | None:
        sid = self.headers.get("X-Session", "")
        with self.app.lock:
            s = self.app.sessions.get(sid)
        if s is None:
            self._deny(401, "no-session")
        return s

    # -- routes -------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8", html=True)
        elif path == "/app.js":
            self._send(200, APP_JS.encode(), "text/javascript; charset=utf-8")
        elif path == "/ca.pem":
            pem = self.app.cfg.state.joinpath("ca.pem")
            data = pem.read_bytes() if pem.exists() else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition", 'attachment; filename="AirBridge-CA.pem"')
            self.send_header("Content-Length", str(len(data)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(data)
        elif path == "/api/serverkey":
            self._json(200, {"pub": b64e(self.app.server_pub_raw), "app": APP_NAME, "v": VERSION})
        elif path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        else:
            self._deny(404, "not-found")

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/pair":
            self._pair()
        elif path == "/api/file/begin":
            self._file_begin()
        elif path == "/api/file/finish":
            self._file_finish()
        else:
            self._deny(404, "not-found")

    def do_PUT(self):  # noqa: N802
        if self.path.split("?", 1)[0] == "/api/file/chunk":
            self._file_chunk()
        else:
            self._deny(404, "not-found")

    # -- pairing ------------------------------------------------------------
    def _pair(self):
        app = self.app
        ip = self.client_address[0]
        if not app.rate_ok(ip):
            self._deny(429, "slow-down")
            return
        body = self._body(MAX_JSON_BODY)
        if body is None:
            return
        try:
            data = json.loads(body)
            token = data["token"]
            client_raw = b64d(data["clientPub"], 256)
            if len(client_raw) != 65 or client_raw[0] != 0x04:
                raise ValueError("bad point encoding")
            client_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), client_raw
            )
        except (KeyError, ValueError, json.JSONDecodeError):
            self._deny(400, "bad-request")
            return
        if not app.token_ok(token):
            app.ui.warn(f"⚠️  pairing rejected from {ip}: invalid or expired token")
            self._deny(403, "token-expired")
            return
        with app.lock:
            if len(app.sessions) >= MAX_SESSIONS:
                self._deny(429, "too-many-sessions")
                return

        shared = app.ecdh_priv.exchange(ec.ECDH(), client_pub)
        salt = os.urandom(16)
        info = (
            f"AirBridge-v1|{sha256_hex(client_raw)}|{sha256_hex(app.server_pub_raw)}"
        ).encode()
        okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info).derive(shared)
        sid = secrets.token_hex(8)
        sas, code = sas_from(okm[32:])
        sess = Session(sid, okm[:32], sas, code, ip)
        with app.lock:
            app.sessions[sid] = sess
        app.ui.log(
            f"\n🔗 Device paired from {ip}\n"
            f"   Verify on the phone:  {'  '.join(sas)}   ({code})\n"
            f"   If the emojis differ, someone is intercepting — close the page.\n"
        )
        self._json(200, {
            "sessionId": sid,
            "salt": b64e(salt),
            "serverPub": b64e(app.server_pub_raw),
        })

    # -- file transfer ------------------------------------------------------
    def _file_begin(self):
        app = self.app
        sess = self._session()
        if sess is None:
            return
        body = self._body(MAX_JSON_BODY)
        if body is None:
            return
        try:
            meta = sess.open_json(body, "begin")
            name = str(meta["name"])
            size = int(meta["size"])
            cs = int(meta["chunkSize"])
            total = int(meta["totalChunks"])
        except InvalidTag:
            app.ui.warn(f"⚠️  SECURITY: unauthenticated 'begin' from {sess.addr} — rejected")
            self._deny(400, "auth")
            return
        except (KeyError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self._deny(400, "bad-request")
            return

        max_bytes = int(app.cfg.max_file_gb * (1 << 30))
        if not (1 <= size <= max_bytes):
            self._deny(400, "bad-size")
            return
        if cs != CHUNK_SIZE or total != max(1, -(-size // cs)) or total > 1_000_000:
            self._deny(400, "bad-chunking")
            return
        with sess.lock:
            if len(sess.files) >= MAX_FILES_PER_SESSION:
                self._deny(429, "too-many-files")
                return
            fid = secrets.token_hex(4)
            safe = safe_filename(name)
            tmp = app.parts / f"{sess.sid}-{fid}.part"
            try:
                rx = FileRx(fid, safe, size, cs, tmp)
            except OSError as e:
                self._deny(500, f"disk:{e.errno}")
                return
            sess.files[fid] = rx
        app.ui.log(f"▶ {safe}  ({human(size)})  incoming from {sess.addr}")
        self._send(200, sess.seal_json({"fileId": fid, "name": safe}, "begin-ack"),
                   "application/json")

    def _file_chunk(self):
        app = self.app
        sess = self._session()
        if sess is None:
            return
        fid = self.headers.get("X-File", "")
        try:
            idx = int(self.headers.get("X-Index", ""))
        except ValueError:
            self._deny(400, "bad-index")
            return
        with sess.lock:
            rx = sess.files.get(fid)
        if rx is None:
            self._deny(404, "no-file")
            return
        if not (0 <= idx < rx.total):
            self._deny(416, "index-range")
            return
        expected_pt = rx.cs if idx < rx.total - 1 else rx.last_len
        expected_body = GCM_NONCE + expected_pt + GCM_TAG
        body = self._body(expected_body)
        if body is None:
            return
        if len(body) != expected_body:
            self._deny(400, "bad-chunk-size")
            return
        with rx.lock:
            if idx in rx.received:
                self._deny(409, "duplicate")
                return
        nonce, ct = body[:GCM_NONCE], body[GCM_NONCE:]
        aad = f"{PROTO}|{sess.sid}|chunk|{fid}|{idx}|{rx.total}".encode()
        try:
            pt = sess.aes.decrypt(nonce, ct, aad)
        except InvalidTag:
            app.ui.warn(
                f"⚠️  SECURITY: chunk {idx} of '{rx.name}' from {sess.addr} failed "
                f"authentication — tampered or corrupted. Rejected."
            )
            self._deny(400, "auth")
            return
        if len(pt) != expected_pt:
            self._deny(400, "bad-chunk-size")
            return
        with rx.lock:
            if idx in rx.received:
                self._deny(409, "duplicate")
                return
            rx.fh.seek(idx * rx.cs)
            rx.fh.write(pt)
            rx.received.add(idx)
            rx.bytes += len(pt)
        app.note_rx(len(pt))
        self._send(204, b"", "application/octet-stream")

    def _file_finish(self):
        app = self.app
        sess = self._session()
        if sess is None:
            return
        body = self._body(MAX_JSON_BODY)
        if body is None:
            return
        try:
            msg = sess.open_json(body, "finish")
            fid = str(msg["fileId"])
        except InvalidTag:
            app.ui.warn(f"⚠️  SECURITY: unauthenticated 'finish' from {sess.addr} — rejected")
            self._deny(400, "auth")
            return
        except (KeyError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self._deny(400, "bad-request")
            return
        with sess.lock:
            rx = sess.files.get(fid)
        if rx is None:
            self._deny(404, "no-file")
            return
        with rx.lock:
            complete = len(rx.received) == rx.total and rx.bytes == rx.size
        if not complete:
            self._send(409, sess.seal_json(
                {"error": "incomplete", "have": len(rx.received), "need": rx.total},
                "finish-ack"), "application/json")
            return
        rx.fh.flush()
        os.fsync(rx.fh.fileno())
        rx.fh.close()
        if rx.tmp.stat().st_size != rx.size:
            self._deny(500, "size-mismatch")
            return

        verified = False
        want = msg.get("sha256")
        if isinstance(want, str) and re.fullmatch(r"[0-9a-f]{64}", want):
            h = hashlib.sha256()
            with open(rx.tmp, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
            if not hmac.compare_digest(h.hexdigest(), want):
                app.ui.warn(
                    f"⚠️  SECURITY: whole-file hash mismatch for '{rx.name}' — discarded."
                )
                rx.tmp.unlink(missing_ok=True)
                with sess.lock:
                    sess.files.pop(fid, None)
                self._deny(400, "hash-mismatch")
                return
            verified = True

        out = app.cfg.out.resolve()
        with app.lock:  # serialize name de-duplication
            final = out / rx.name
            i = 1
            stem, suffix = Path(rx.name).stem, Path(rx.name).suffix
            while final.exists():
                final = out / f"{stem} ({i}){suffix}"
                i += 1
            if final.resolve().parent != out:
                self._deny(400, "bad-name")
                return
            os.replace(rx.tmp, final)
        try:
            os.chmod(final, 0o644)
        except OSError:
            pass
        with sess.lock:
            sess.files.pop(fid, None)

        dt = max(1e-6, time.monotonic() - rx.t0)
        integrity = "hash verified ✓" if verified else "AEAD chain verified ✓"
        app.ui.log(
            f"✔ {final.name}  ({human(rx.size)}, {human(rx.size / dt)}/s, {integrity})"
        )
        self._send(200, sess.seal_json(
            {"savedAs": final.name, "size": rx.size, "verified": verified},
            "finish-ack"), "application/json")


# --------------------------------------------------------------------------
# embedded iPhone web app
# --------------------------------------------------------------------------

_SAS_JS = json.dumps(SAS_EMOJIS, ensure_ascii=False)

APP_JS = r'''"use strict";
/* AirBridge client — all cryptography happens on this device via WebCrypto.
   Files are AES-256-GCM encrypted here, before anything leaves the phone. */

const AB = (() => {
  const CHUNK = 4 * 1024 * 1024;
  const HASH_MAX = 64 * 1024 * 1024;            // whole-file hash for files up to this size
  const EMOJIS = __SAS_EMOJIS__;                 // must match the server list exactly
  const te = new TextEncoder(), td = new TextDecoder();

  const hex = (u8) => Array.from(u8, b => b.toString(16).padStart(2, "0")).join("");
  function b64(u8) {
    let s = ""; const STEP = 0x8000;
    for (let i = 0; i < u8.length; i += STEP)
      s += String.fromCharCode.apply(null, u8.subarray(i, i + STEP));
    return btoa(s);
  }
  function ub64(s) {
    const bin = atob(s), u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  async function sha256hex(buf) {
    const d = await crypto.subtle.digest("SHA-256", buf);
    return hex(new Uint8Array(d));
  }

  async function getServerKey(base) {
    const r = await fetch(base + "/api/serverkey", { cache: "no-store" });
    if (!r.ok) throw new Error("server unreachable (" + r.status + ")");
    return ub64((await r.json()).pub);
  }

  /* ECDH(P-256) -> HKDF-SHA256 -> AES-256-GCM session key.
     expectedFpr16: first 16 hex chars of SHA-256(server public key), taken from
     the QR code's URL fragment — the out-of-band channel that defeats MITM. */
  async function establish(base, token, expectedFpr16) {
    const serverRaw = await getServerKey(base);
    const fprFull = await sha256hex(serverRaw);
    if (expectedFpr16 && fprFull.slice(0, 16) !== expectedFpr16.toLowerCase())
      throw new Error("FINGERPRINT_MISMATCH");

    const kp = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const clientRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));

    const r = await fetch(base + "/api/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, clientPub: b64(clientRaw) }),
    });
    if (!r.ok) {
      let err = "pair-failed-" + r.status;
      try { err = (await r.json()).error || err; } catch (_) {}
      throw new Error(err);
    }
    const j = await r.json();
    const srvRaw = ub64(j.serverPub);
    if (await sha256hex(srvRaw) !== fprFull) throw new Error("FINGERPRINT_MISMATCH");

    const srvKey = await crypto.subtle.importKey(
      "raw", srvRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: srvKey }, kp.privateKey, 256));
    const info = te.encode("AirBridge-v1|" + (await sha256hex(clientRaw)) + "|" + fprFull);
    const hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    const okm = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: ub64(j.salt), info }, hk, 512));
    const key = await crypto.subtle.importKey(
      "raw", okm.slice(0, 32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    const sas = [0, 1, 2, 3].map(i => EMOJIS[okm[32 + i] % EMOJIS.length]);
    const code = hex(okm.slice(36, 39));
    okm.fill(0); shared.fill(0);
    return { base, sid: j.sessionId, key, sas, code };
  }

  const aadStr = (s, p) => te.encode("AB1|" + s.sid + "|" + p);

  async function sealJSON(s, purpose, obj) {
    const n = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: n, additionalData: aadStr(s, purpose) },
      s.key, te.encode(JSON.stringify(obj))));
    return JSON.stringify({ n: b64(n), c: b64(ct) });
  }
  async function openJSON(s, purpose, envText) {
    const env = JSON.parse(envText);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ub64(env.n), additionalData: aadStr(s, purpose) },
      s.key, ub64(env.c));
    return JSON.parse(td.decode(pt));
  }

  async function sealChunk(s, fid, idx, total, buf) {
    const n = crypto.getRandomValues(new Uint8Array(12));
    const aad = te.encode("AB1|" + s.sid + "|chunk|" + fid + "|" + idx + "|" + total);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: n, additionalData: aad }, s.key, buf);
    return new Blob([n, new Uint8Array(ct)]);
  }

  async function api(s, path, opts) {
    opts.headers = Object.assign({ "X-Session": s.sid }, opts.headers || {});
    return fetch(s.base + path, opts);
  }

  async function putChunk(s, fid, idx, blob) {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const r = await api(s, "/api/file/chunk", {
          method: "PUT", body: blob,
          headers: { "X-File": fid, "X-Index": String(idx),
                     "Content-Type": "application/octet-stream" },
        });
        if (r.status === 204 || r.status === 409) return;   // 409 = server already has it
        if (r.status === 400 || r.status === 401 || r.status === 404) {
          let err = "chunk-" + r.status;
          try { err = (await r.json()).error || err; } catch (_) {}
          throw Object.assign(new Error(err), { fatal: true });
        }
        throw new Error("chunk-" + r.status);
      } catch (e) {
        if (e.fatal || attempt === 2) throw e;
        await new Promise(res => setTimeout(res, 400 * (attempt + 1) * (attempt + 1)));
      }
    }
  }

  /* Full pipeline for one file. `file` needs: name, size, type,
     slice(a,b) -> Blob-like with arrayBuffer(), and arrayBuffer() for hashing. */
  async function sendFile(s, file, onProgress) {
    const size = file.size;
    if (!size) throw new Error("empty-file");
    const total = Math.max(1, Math.ceil(size / CHUNK));

    let sha = null;
    if (size <= HASH_MAX) sha = await sha256hex(await file.arrayBuffer());

    const beginEnv = await sealJSON(s, "begin", {
      name: file.name, size, chunkSize: CHUNK, totalChunks: total, mime: file.type || "" });
    const br = await api(s, "/api/file/begin", {
      method: "POST", body: beginEnv,
      headers: { "Content-Type": "application/json" } });
    if (!br.ok) {
      let err = "begin-" + br.status;
      try { err = (await br.json()).error || err; } catch (_) {}
      throw new Error(err);
    }
    const { fileId } = await openJSON(s, "begin-ack", await br.text());

    let next = 0, sent = 0;
    const workers = [];
    const lanes = Math.min(3, total);
    const pump = async () => {
      for (;;) {
        const idx = next++;
        if (idx >= total) return;
        const start = idx * CHUNK, end = Math.min(size, start + CHUNK);
        const buf = await file.slice(start, end).arrayBuffer();
        const blob = await sealChunk(s, fileId, idx, total, buf);
        await putChunk(s, fileId, idx, blob);
        sent += end - start;
        if (onProgress) onProgress(sent, size);
      }
    };
    for (let i = 0; i < lanes; i++) workers.push(pump());
    await Promise.all(workers);

    const finEnv = await sealJSON(s, "finish", sha ? { fileId, sha256: sha } : { fileId });
    const fr = await api(s, "/api/file/finish", {
      method: "POST", body: finEnv,
      headers: { "Content-Type": "application/json" } });
    if (!fr.ok) {
      let err = "finish-" + fr.status;
      try {
        const ack = await openJSON(s, "finish-ack", await fr.text());
        err = ack.error || err;
      } catch (_) {}
      throw new Error(err);
    }
    return openJSON(s, "finish-ack", await fr.text());
  }

  return { CHUNK, EMOJIS, establish, sendFile, sha256hex, b64, ub64, sealJSON, openJSON };
})();
if (typeof globalThis !== "undefined") globalThis.AB = AB;

/* ----------------------------- UI layer ----------------------------- */
if (typeof document !== "undefined") (() => {
  const $ = (id) => document.getElementById(id);
  const fmt = (n) => {
    const u = ["B", "KB", "MB", "GB"]; let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  };

  function fatal(title, detail) {
    $("boot").hidden = true; $("main").hidden = true;
    $("fatal").hidden = false;
    $("fatal-title").textContent = title;
    $("fatal-detail").textContent = detail || "";
  }

  async function init() {
    if (!window.isSecureContext || !crypto.subtle) {
      fatal("Open the https:// link",
        "Encryption needs a secure page. Use the exact address shown in your terminal (it starts with https) and accept the certificate.");
      return;
    }
    const params = new URLSearchParams(location.hash.slice(1));
    const token = params.get("t"), fpr = params.get("f");
    if (!token || !fpr) {
      fatal("Scan the QR code",
        "Open this page by scanning the QR code shown in the AirBridge terminal — it carries the one-time key check.");
      return;
    }
    let session;
    try {
      session = await AB.establish(location.origin, token, fpr);
    } catch (e) {
      if (String(e.message) === "FINGERPRINT_MISMATCH") {
        fatal("⛔ Key fingerprint mismatch",
          "The computer that answered is NOT the one that printed your QR code. Someone on this network may be intercepting. Do not send anything.");
      } else if (String(e.message).indexOf("token") >= 0) {
        fatal("Code expired",
          "This QR code timed out. Press Enter in the AirBridge terminal to print a fresh one, then rescan.");
      } else {
        fatal("Couldn't reach AirBridge", String(e.message || e));
      }
      return;
    }

    // paired — reveal the seal
    $("boot").hidden = true; $("main").hidden = false;
    $("host").textContent = location.hostname;
    const sasRow = $("sas");
    session.sas.forEach((em, i) => {
      const chip = document.createElement("div");
      chip.className = "seal"; chip.style.animationDelay = (i * 90) + "ms";
      chip.textContent = em;
      sasRow.appendChild(chip);
    });
    $("sascode").textContent = session.code;
    $("pill").classList.add("live");
    $("pill-text").textContent = "End-to-end encrypted";

    let wakeLock = null;
    const keepAwake = async () => {
      try { wakeLock = await navigator.wakeLock.request("screen"); } catch (_) {}
    };

    const queue = [];
    let busy = false, transferring = 0;

    window.addEventListener("beforeunload", (e) => {
      if (transferring > 0) { e.preventDefault(); e.returnValue = ""; }
    });

    function row(file) {
      const li = document.createElement("li");
      li.className = "file";
      li.innerHTML =
        '<div class="frow"><span class="fname"></span><span class="fmeta"></span></div>' +
        '<div class="bar"><div class="fill"></div></div>' +
        '<div class="fstate">queued</div>';
      li.querySelector(".fname").textContent = file.name;
      li.querySelector(".fmeta").textContent = fmt(file.size);
      $("files").prepend(li);
      return {
        fill: li.querySelector(".fill"),
        state: li.querySelector(".fstate"),
        el: li,
      };
    }

    async function drain() {
      if (busy) return;
      busy = true;
      while (queue.length) {
        const { file, ui } = queue.shift();
        transferring++;
        const t0 = performance.now();
        ui.state.textContent = file.size <= 64 * 1024 * 1024
          ? "encrypting & hashing…" : "encrypting…";
        try {
          const res = await AB.sendFile(session, file, (sent, size) => {
            const pct = Math.min(100, (sent / size) * 100);
            ui.fill.style.width = pct.toFixed(1) + "%";
            const secs = (performance.now() - t0) / 1000;
            ui.state.textContent =
              pct.toFixed(0) + "% · " + fmt(sent / Math.max(0.2, secs)) + "/s";
          });
          ui.fill.style.width = "100%";
          ui.el.classList.add("done");
          ui.state.textContent = "✓ saved as “" + res.savedAs + "”" +
            (res.verified ? " · hash verified" : " · authenticated");
        } catch (e) {
          ui.el.classList.add("failed");
          ui.state.textContent = "✕ failed: " + String(e.message || e);
        }
        transferring--;
      }
      busy = false;
      if (wakeLock) { try { await wakeLock.release(); } catch (_) {} wakeLock = null; }
    }

    $("picker").addEventListener("change", (ev) => {
      const files = Array.from(ev.target.files || []);
      if (!files.length) return;
      keepAwake();
      $("empty").hidden = true;
      for (const f of files) {
        if (!f.size) continue;
        queue.push({ file: f, ui: row(f) });
      }
      ev.target.value = "";
      drain();
    });
  }

  init();
})();
'''.replace("__SAS_EMOJIS__", _SAS_JS)


INDEX_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>AirBridge</title>
<style>
  :root{
    --ink:#0b1020; --panel:#131a2e; --panel-2:#0f1526; --line:#232c47;
    --text:#e8ecf8; --mute:#8a94b0; --signal:#3ee6c1; --warn:#ffb454; --bad:#ff5d73;
  }
  *{box-sizing:border-box; -webkit-tap-highlight-color:transparent}
  html,body{margin:0; min-height:100%}
  body{
    background:
      radial-gradient(90vw 60vh at 80% -10%, #17204017 0%, transparent 60%),
      radial-gradient(80vw 50vh at -10% 110%, #0e2b2a55 0%, transparent 55%),
      var(--ink);
    color:var(--text);
    font:16px/1.45 -apple-system, "SF Pro Text", system-ui, "Segoe UI", Roboto, sans-serif;
    padding:max(20px, env(safe-area-inset-top)) 16px max(28px, env(safe-area-inset-bottom));
    display:flex; justify-content:center;
  }
  .wrap{width:100%; max-width:430px}
  .mono{font-family:ui-monospace, "SF Mono", SFMono-Regular, Menlo, monospace}

  header{display:flex; align-items:baseline; justify-content:space-between; padding:2px 4px 14px}
  h1{font-family:ui-monospace,"SF Mono",Menlo,monospace; font-size:17px; letter-spacing:.14em;
     font-weight:600; margin:0}
  h1 b{color:var(--signal); font-weight:600}
  .pill{display:flex; align-items:center; gap:7px; font-size:12px; color:var(--mute)}
  .pill .dot{width:8px; height:8px; border-radius:50%; background:var(--mute); opacity:.5}
  .pill.live .dot{background:var(--signal); opacity:1; box-shadow:0 0 10px var(--signal)}
  .pill.live{color:var(--signal)}

  .card{background:var(--panel); border:1px solid var(--line); border-radius:18px; overflow:hidden;
        box-shadow:0 18px 50px -30px #000}
  .card .top{padding:16px 18px 6px; font-size:13px; color:var(--mute)}
  .card .top b{color:var(--text); font-weight:600}

  /* the seal stub — boarding-pass style with a perforated tear line */
  .stub{position:relative; padding:14px 18px 18px; text-align:center}
  .tear{position:relative; height:0; border-top:1.5px dashed var(--line); margin:8px 0 16px}
  .tear::before,.tear::after{content:""; position:absolute; top:-9px; width:18px; height:18px;
    border-radius:50%; background:var(--ink); border:1px solid var(--line)}
  .tear::before{left:-27px}
  .tear::after{right:-27px}
  #sas{display:flex; justify-content:center; gap:12px; margin:6px 0 10px}
  .seal{width:62px; height:62px; border-radius:16px; background:var(--panel-2);
    border:1px solid var(--line); display:flex; align-items:center; justify-content:center;
    font-size:32px; animation:flip .5s cubic-bezier(.2,.8,.2,1) both}
  @keyframes flip{from{transform:rotateX(70deg) translateY(8px); opacity:0}
                  to{transform:none; opacity:1}}
  @media (prefers-reduced-motion: reduce){ .seal{animation:none} }
  .stub .hint{font-size:12.5px; color:var(--mute)}
  .stub .hint .mono{color:var(--text)}

  .pick{padding:0 16px 16px}
  .pickbtn{position:relative; display:block; width:100%; border:1.5px dashed #2c3b63;
    border-radius:14px; background:var(--panel-2); color:var(--text); text-align:center;
    padding:20px 12px; font-size:16px; font-weight:600}
  .pickbtn small{display:block; margin-top:4px; font-weight:400; font-size:12.5px; color:var(--mute)}
  .pickbtn input{position:absolute; inset:0; opacity:0; width:100%; height:100%}
  .pickbtn:active{border-color:var(--signal)}

  #files{list-style:none; margin:16px 0 0; padding:0; display:flex; flex-direction:column; gap:10px}
  .file{background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:12px 14px}
  .frow{display:flex; justify-content:space-between; gap:12px; font-size:14px}
  .fname{overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
  .fmeta{color:var(--mute); flex:none; font-size:12.5px}
  .bar{height:5px; border-radius:99px; background:var(--panel-2); margin:9px 0 7px; overflow:hidden}
  .fill{height:100%; width:0%; background:var(--signal); border-radius:99px;
        transition:width .25s linear}
  .fstate{font-size:12px; color:var(--mute)}
  .file.done .fstate{color:var(--signal)}
  .file.done .fill{background:var(--signal)}
  .file.failed .fill{background:var(--bad)}
  .file.failed .fstate{color:var(--bad)}
  #empty{color:var(--mute); font-size:13px; text-align:center; padding:18px 8px 4px}

  footer{margin-top:22px; text-align:center; font-size:11.5px; color:#5e6884; line-height:1.6}
  footer .mono{color:#7f89a6}

  .center{min-height:60vh; display:flex; flex-direction:column; align-items:center;
          justify-content:center; text-align:center; gap:10px; padding:0 10px}
  .spin{width:26px; height:26px; border-radius:50%; border:3px solid var(--line);
        border-top-color:var(--signal); animation:sp 1s linear infinite}
  @keyframes sp{to{transform:rotate(1turn)}}
  #fatal-title{font-size:19px; font-weight:700}
  #fatal-detail{color:var(--mute); font-size:14px; max-width:34ch}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>AIR<b>BRIDGE</b></h1>
    <div class="pill" id="pill"><span class="dot"></span><span id="pill-text">pairing…</span></div>
  </header>

  <div id="boot" class="center"><div class="spin"></div><div style="color:var(--mute);font-size:14px">Exchanging keys…</div></div>

  <div id="fatal" class="center" hidden>
    <div style="font-size:40px">🔐</div>
    <div id="fatal-title"></div>
    <div id="fatal-detail"></div>
  </div>

  <div id="main" hidden>
    <div class="card">
      <div class="top">Secure channel to <b id="host"></b></div>
      <div class="stub">
        <div class="tear"></div>
        <div id="sas"></div>
        <div class="hint">These four emojis must match your terminal · <span class="mono" id="sascode"></span></div>
      </div>
      <div class="pick">
        <label class="pickbtn">＋ Choose photos &amp; videos
          <small>encrypted on this phone before they leave it</small>
          <input id="picker" type="file" accept="image/*,video/*" multiple>
        </label>
      </div>
    </div>

    <ul id="files"></ul>
    <div id="empty">Nothing sent yet — transfers appear here.</div>

    <footer>
      AES-256-GCM · ephemeral ECDH keys · nothing is stored on this page<br>
      keep this tab open while sending
    </footer>
  </div>
</div>
<script src="/app.js"></script>
</body>
</html>
'''


# --------------------------------------------------------------------------
# banner / QR / server bootstrap
# --------------------------------------------------------------------------

def pair_url(app: AppState) -> str:
    return (f"https://{app.cfg.ip}:{app.cfg.port}/"
            f"#t={app.token}&f={app.fingerprint[:16]}")


def print_welcome(app: AppState, extra_ips: list[str]):
    cfg = app.cfg
    url = pair_url(app)
    title = f"{APP_NAME} v{VERSION} — encrypted Wi-Fi drop box"
    line = "─" * (len(title) + 4)
    print(f"\n  ┌{line}┐")
    print(f"  │  {title}  │")
    print(f"  └{line}┘\n")
    print(f"  Saving media to:  {cfg.out}\n")
    print("  On your iPhone (same Wi-Fi network):")
    print("   1. Open the Camera app and scan this code:\n")
    if not cfg.no_qr:
        try:
            import qrcode  # type: ignore
            qr = qrcode.QRCode(border=1)
            qr.add_data(url)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        except ImportError:
            print("     (install 'qrcode' for a scannable code:  pip install qrcode)")
    print(f"\n      {url}\n")
    print("   2. Tap the link, choose “Show Details → visit this website”")
    print("      to accept the local certificate.")
    print("   3. Check that the FOUR EMOJIS on the phone match the ones")
    print("      printed here when it pairs — that is your proof nobody")
    print("      is sitting in the middle.\n")
    if extra_ips:
        print(f"  Other addresses on this machine: {', '.join(extra_ips)}")
    print(f"  Key fingerprint : {app.fingerprint[:16]}  (embedded in the QR)")
    print(f"  Pairing code TTL: {cfg.token_ttl // 60} min — press Enter any time for a fresh QR")
    print(f"  Optional full TLS trust: download https://{cfg.ip}:{cfg.port}/ca.pem on the")
    print("  phone and enable it under Settings → General → About → Certificate Trust.\n")


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, addr, handler, app: AppState):
        super().__init__(addr, handler)
        self.app = app


def build_server(cfg: Config, ui: UI | None = None) -> tuple[BridgeServer, AppState]:
    ui = ui or UI(quiet=cfg.quiet)
    cfg.out = cfg.out.expanduser().resolve()
    cfg.out.mkdir(parents=True, exist_ok=True)
    cfg.state = cfg.state.expanduser().resolve()

    ips = lan_ips()
    if cfg.ip is None:
        cfg.ip = ips[0]

    store = CertStore(cfg.state)
    cert, key, _ca = store.ensure(ips)

    app = AppState(cfg, ui)
    httpd = BridgeServer((cfg.host, cfg.port), Handler, app)
    cfg.port = httpd.server_address[1]  # resolve port 0 -> real port

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd, app


def _status_ticker(app: AppState, stop: threading.Event):
    while not stop.wait(0.3):
        files = app.active_files()
        if not files:
            app.ui.clear_status()
            continue
        done = sum(f.bytes for f in files)
        total = sum(f.size for f in files)
        spd = app.speed()
        app.ui.status(
            f"  ⇅ receiving {len(files)} file(s) · {human(done)} / {human(total)}"
            f" · {human(spd)}/s "
        )


def _stdin_refresher(app: AppState, extra_ips: list[str]):
    try:
        for _ in sys.stdin:
            app.new_token()
            app.ui.clear_status()
            print_welcome(app, extra_ips)
    except (ValueError, OSError):
        pass


def main(argv=None):
    p = argparse.ArgumentParser(description=f"{APP_NAME} — encrypted iPhone→Linux transfer")
    p.add_argument("--out", default="~/AirBridge", help="destination folder (default ~/AirBridge)")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--host", default="0.0.0.0", help="bind address")
    p.add_argument("--ip", default=None, help="LAN IP to advertise in the QR (auto-detected)")
    p.add_argument("--state", default="~/.local/share/airbridge",
                   help="where keys/certificates live")
    p.add_argument("--token-ttl", type=int, default=900, help="pairing code lifetime, seconds")
    p.add_argument("--max-gb", type=float, default=25.0, help="per-file size cap in GB")
    p.add_argument("--no-qr", action="store_true", help="don't render the ASCII QR")
    args = p.parse_args(argv)

    cfg = Config(out=Path(args.out), state=Path(args.state), host=args.host,
                 port=args.port, ip=args.ip, token_ttl=args.token_ttl,
                 max_file_gb=args.max_gb, no_qr=args.no_qr)
    try:
        httpd, app = build_server(cfg)
    except PermissionError:
        sys.exit(f"Cannot bind port {cfg.port} — try --port 8443 or a port above 1024.")
    except OSError as e:
        sys.exit(f"Cannot start server: {e}")

    ips = lan_ips()
    extra = [i for i in ips if i != cfg.ip]
    print_welcome(app, extra)

    stop = threading.Event()
    threading.Thread(target=_status_ticker, args=(app, stop), daemon=True).start()
    if sys.stdin and sys.stdin.isatty():
        threading.Thread(target=_stdin_refresher, args=(app, extra), daemon=True).start()

    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        app.ui.clear_status()
        httpd.shutdown()
        for f in app.active_files():
            try:
                f.fh.close()
                f.tmp.unlink(missing_ok=True)
            except OSError:
                pass
        print("\n  AirBridge stopped. Partial transfers were discarded; finished files are safe.\n")


if __name__ == "__main__":
    main()
