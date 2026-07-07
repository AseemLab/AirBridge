#!/usr/bin/env python3
"""Concurrency stress test: 3 paired devices upload simultaneously,
including one 64 MB file, with out-of-order parallel chunk lanes."""
import hashlib
import os
import ssl
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import server as ab
from test_e2e import PyClient

tmp = Path(tempfile.mkdtemp(prefix="airbridge-stress-"))
cfg = ab.Config(out=tmp / "out", state=tmp / "state", host="127.0.0.1",
                port=0, ip="127.0.0.1", quiet=True)
httpd, app = ab.build_server(cfg)
threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.2},
                 daemon=True).start()
base = f"https://127.0.0.1:{cfg.port}"
ctx = ssl.create_default_context(cafile=str(cfg.state / "ca.pem"))

payloads = {
    "big_video.MOV": os.urandom(64 * 1024 * 1024),      # 16 chunks, no hash path
    "photo_a.HEIC": os.urandom(7 * 1024 * 1024 + 999),
    "photo_b.JPG": os.urandom(3 * 1024 * 1024 + 1),
}


def upload_parallel_lanes(client: PyClient, name: str, data: bytes):
    """Mimics the browser: 3 chunk uploads in flight, order not guaranteed."""
    st, ack, total = client.begin(name, len(data))
    assert st == 200, ack
    fid = ack["fileId"]

    def one(i):
        pt = data[i * ab.CHUNK_SIZE:(i + 1) * ab.CHUNK_SIZE]
        st = client.put_chunk(fid, i, client.seal_chunk(fid, i, total, pt))
        assert st == 204, f"{name} chunk {i} -> {st}"

    with ThreadPoolExecutor(max_workers=3) as ex:
        list(ex.map(one, range(total)))
    use_hash = len(data) <= 64 * 1024 * 1024 and name != "big_video.MOV"
    st, res = client.finish(fid, hashlib.sha256(data).hexdigest() if use_hash else None)
    assert st == 200, res
    return res


t0 = time.monotonic()
results = {}
threads = []
for name, data in payloads.items():
    c = PyClient(base, ctx).pair(app.token, app.fingerprint[:16])

    def run(c=c, name=name, data=data):
        results[name] = upload_parallel_lanes(c, name, data)

    th = threading.Thread(target=run)
    th.start()
    threads.append(th)
for th in threads:
    th.join()
dt = time.monotonic() - t0

total_mb = sum(len(d) for d in payloads.values()) / 1e6
ok = True
for name, data in payloads.items():
    saved = cfg.out / results[name]["savedAs"]
    match = saved.read_bytes() == data
    ok &= match
    print(f"  {'✔' if match else '✘'} {name}: {len(data)/1e6:.1f} MB bit-for-bit")
print(f"\n  3 devices in parallel: {total_mb:.0f} MB in {dt:.2f}s "
      f"→ {total_mb/dt:.0f} MB/s aggregate (loopback, AES-GCM both ends)")
parts_left = list((cfg.out / '.airbridge-parts').glob('*'))
print(f"  {'✔' if not parts_left else '✘'} no partial files left behind")
sys.exit(0 if ok and not parts_left else 1)
