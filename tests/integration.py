#!/usr/bin/env python3
"""Real HTTP tests against a freshly built nginx/OpenResty; Python stdlib only."""
import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import threading
import tempfile
import time
import unittest
import urllib.parse


ARGS = None
PORT = 0
UPSTREAM_PORT = 0
ROOT = None
SECRET = "demo-hls-secret"
TS = bytes(range(256)) * 128
BASE = b"#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:7,\nGEGrR-hls-000.ts\n#EXT-X-ENDLIST\n"
LONG = b"#EXTM3U\n" + b"segment.ts\n" * 20000


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def signature(user="1", stamp=None, algorithm="md5", encoding="hex", ip=None):
    stamp = int(time.time()) if stamp is None else stamp
    fields = [user, str(stamp)]
    if ip is not None:
        fields.append(ip)
    fields.append(SECRET)
    message = "%".join(fields).encode()
    if algorithm == "hmac_sha256":
        digest = hmac.new(b"test-hmac-key", message, hashlib.sha256).digest()
    else:
        digest = hashlib.new(algorithm, message).digest()
    token = {"hex": digest.hex(), "base64": base64.b64encode(digest).decode(),
             "base64url": base64.urlsafe_b64encode(digest).decode().rstrip("=")}[encoding]
    return {"token": token, "ukey": user, "pkey": ip or "192.0.2.10", "t": str(stamp)}


def url(path, params=None):
    return path + ("?" + urllib.parse.urlencode(params) if params is not None else "")


def path_signature(path, user="1", stamp=None, filename=False):
    stamp = str(int(time.time()) if stamp is None else stamp)
    identity = path.rsplit("/", 1)[-1] if filename else path
    token = hmac.new(SECRET.encode(), f"{user}\n{stamp}\n{identity}".encode(), hashlib.sha256).hexdigest()
    return {"token": token, "ukey": user, "t": stamp, "pkey": "192.0.2.10"}


def request(path, params=None, headers=None, method="GET", timeout=10):
    con = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        con.request(method, url(path, params), headers=headers or {})
        response = con.getresponse()
        data = response.read()
        return response.status, dict(response.getheaders()), data
    finally:
        con.close()


def config_check(prefix, config):
    # nginx's main() returns directly from -t without destroying the new cycle.
    # Keep ASan/UBSan enabled, but test leaks on the real process's graceful exit.
    env = os.environ.copy()
    if "ASAN_OPTIONS" in env:
        env["ASAN_OPTIONS"] += ":detect_leaks=0"
    result = subprocess.run([ARGS.nginx, "-p", str(prefix), "-t", "-c", str(config)],
                            capture_output=True, env=env)
    diagnostics = result.stderr.decode()
    if any(marker in diagnostics for marker in ("ERROR: AddressSanitizer", "runtime error:", "LeakSanitizer")):
        raise AssertionError(diagnostics)
    return result


def fixtures():
    attrs = (
        '#EXTM3U\r\n'
        '# comment URI="leave.ts"\r\n'
        '#EXT-X-KEY:METHOD=AES-128,URI="key.bin?old=1",IV=0x1234\r\n'
        '#EXT-X-SESSION-KEY:METHOD=AES-128,URI="session.key"\r\n'
        '#EXT-X-MAP:URI="init.mp4",BYTERANGE="720@0"\r\n'
        '#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="a,b",URI="audio.m3u8"\r\n'
        '#EXT-X-I-FRAME-STREAM-INF:BANDWIDTH=86000,URI="iframe.m3u8"\r\n'
        '#EXT-X-STREAM-INF:BANDWIDTH=128000\r\n'
        'child.m3u8\r\n'
        'segment.ts?keep=a%2Bb&token=old&token=older&%75key=9#part\r\n'
        f'http://127.0.0.1:{PORT}/static/segment.ts\r\n'
        f'//127.0.0.1:{PORT}/static/segment.ts\r\n'
        'https://cdn.example.test/segment.ts\r\n'
        'https://evil.example.test/segment.ts?keep=1\r\n'
        'https://cdn.example.test.evil.test/segment.ts\r\n'
        'https://cdn.example.test@evil.test/segment.ts\r\n'
        'data:application/octet-stream;base64,YQ==\r\n'
        '#EXT-X-UNKNOWN:URI="leave.ts"\r\n'
        'last.ts'
    ).encode()
    many = b"#EXTM3U\n" + b"".join(
        f"#EXTINF:7.000000,\nGEGrR-hls-{i:03}.ts\n".encode() for i in range(177)
    ) + b"#EXT-X-ENDLIST\n"
    return {
        "hls.m3u8": BASE, "many.m3u8": many, "attrs.m3u8": attrs,
        "child.m3u8": BASE, "audio.m3u8": BASE, "iframe.m3u8": BASE,
        "custom.plist": BASE, "long.m3u8": LONG,
        "segment.ts": TS, "GEGrR-hls-000.ts": TS,
        "key.bin": b"0123456789abcdef", "session.key": b"0123456789abcdef",
        "init.mp4": b"fake initialization", "invalid.m3u8": b"<html>error</html>\n",
        "empty.m3u8": b"", "oversize.m3u8": b"#EXTM3U\n" + b"x" * 65537 + b"\n",
        "badattr.m3u8": b'#EXTM3U\n#EXT-X-KEY:URI="missing\n',
        "duplicate_uri.m3u8": b'#EXTM3U\n#EXT-X-MAP:URI="a",URI="b"\n',
        "badquery.m3u8": b"#EXTM3U\na.ts?%Q0=bad\n",
        "backslash.m3u8": b"#EXTM3U\nhttps://good.test\\@evil.test/a.ts\n",
        "norules.txt": b"untouched text\n",
        "paths.m3u8": (
            '#EXTM3U\nsegment.ts?quality=hd&token=old#part\n'
            '../other/segment.ts?x=1\n./sub/../segment.ts\n'
            'sub/child.m3u8\n%73egment.ts\nspace%20name.ts\n%252F.ts\n%3F.ts\n%23.ts\n'
            f'http://127.0.0.1:{PORT}/bound/segment.ts?cache=1\n'
            f'//127.0.0.1:{PORT}/bound/segment.ts\n'
            'https://cdn.example.test/external/part.ts?quality=hd\n'
        ).encode(),
        "root.ts": TS, "space name.ts": TS, "%2F.ts": TS, "?.ts": TS, "#.ts": TS,
    }


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits = {}
    lock = threading.Lock()

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        name = parsed.path.rsplit("/", 1)[-1]
        with self.lock:
            self.hits[name] = self.hits.get(name, 0) + 1
        if name == "mime":
            body = BASE
        elif name in ("encoded.m3u8", "partial.m3u8", "notmodified.m3u8", "split.m3u8"):
            body = BASE
        else:
            body = fixtures().get(name)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if name == "encoded.m3u8":
            body = gzip.compress(body)
        self.send_response(206 if name == "partial.m3u8" else 304 if name == "notmodified.m3u8" else 200)
        self.send_header("Content-Type", "application/vnd.apple.mpegurl" if name.endswith("m3u8") or name == "mime" else "video/mp2t")
        self.send_header("ETag", '"origin-v1"')
        self.send_header("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("Connection", "close")
        self.close_connection = True
        if name == "encoded.m3u8":
            self.send_header("Content-Encoding", "gzip")
        if name == "split.m3u8":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            params = urllib.parse.parse_qs(parsed.query)
            width = int(params.get("width", [1])[0])
            try:
                for pos in range(0, len(body), width):
                    part = body[pos:pos + width]
                    self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                    self.wfile.flush()
                    time.sleep(0.001)
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command == "HEAD" or name == "notmodified.m3u8":
                return
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass


def config_text(extra=""):
    load = f"load_module {ARGS.module};" if ARGS.module else ""
    common = ""
    variants = ""
    for algorithm, encoding in (("md5", "hex"), ("sha256", "base64url"), ("hmac_sha256", "base64")):
        variants += f"""
        location /resign-{algorithm}/ {{
            alias {ROOT}/www/;
            secure_hls_algorithm {algorithm}; secure_hls_encoding {encoding};
            secure_hls_hmac_key alternate-key;
            secure_hls_token $secure_hls_arg_sig;
            secure_hls_message "v3|${{uri}}|${{secure_hls_arg_user}}|${{secure_hls_arg_at}}|alternate-key";
            secure_hls_require_args sig user at;
            secure_hls_timestamp $secure_hls_arg_at;
            secure_hls_ttl 10m;
            secure_hls_rewrite on; secure_hls_resign on;
            secure_hls_sign_param sig;
            secure_hls_sign_message "v3|${{secure_hls_target_path}}|${{secure_hls_arg_user}}|${{secure_hls_arg_at}}|alternate-key";
            secure_hls_sign_playlist_message "v3|${{secure_hls_target_path}}|${{secure_hls_arg_user}}|${{secure_hls_arg_at}}|alternate-key";
            secure_hls_param user $secure_hls_arg_user;
            secure_hls_param at $secure_hls_arg_at;
        }}
        """
    proxy = f"""
        {common}
        secure_hls_rewrite on;
        proxy_pass http://127.0.0.1:{UPSTREAM_PORT}/;
        proxy_set_header Accept-Encoding "";
        proxy_set_header Range "";
        proxy_set_header If-Range "";
        proxy_set_header If-Modified-Since "";
        proxy_set_header If-Unmodified-Since "";
        proxy_set_header If-Match "";
        proxy_set_header If-None-Match "";
    """
    return f"""
{load}
worker_processes 1;
daemon off;
master_process off;
pid {ROOT}/nginx.pid;
error_log {ROOT}/error.log error;
events {{ worker_connections 256; }}
http {{
    access_log off;
    client_body_temp_path {ROOT}/client;
    proxy_temp_path {ROOT}/proxy_temp;
    proxy_cache_path {ROOT}/cache keys_zone=hls:1m inactive=1m;
    types {{ application/vnd.apple.mpegurl m3u8 plist; video/mp2t ts; }}
    default_type application/octet-stream;
    sendfile on;
    gzip on;
    gzip_min_length 1;
    gzip_proxied any;
    gzip_types application/vnd.apple.mpegurl application/x-mpegurl;
    server {{
        listen 127.0.0.1:{PORT};
        server_name localhost;
        include {ROOT}/auth.conf;
        add_header X-HLS-Status $secure_hls_status always;
        location /static/ {{ alias {ROOT}/www/; {common} secure_hls_rewrite on;
            secure_hls_allowed_origin https://cdn.example.test:443; }}
        location /proxy/ {{ {proxy} }}
        location /stream/ {{ {proxy} proxy_buffering off; }}
        location /cache/ {{ {proxy} proxy_cache hls; proxy_cache_key $uri;
            proxy_cache_valid 200 1m; add_header X-Cache $upstream_cache_status always; }}
        location /sha/ {{ alias {ROOT}/www/; {common}
            secure_hls_algorithm sha256; secure_hls_encoding base64; secure_hls_rewrite on; }}
        location /hmac/ {{ alias {ROOT}/www/; {common}
            secure_hls_algorithm hmac_sha256; secure_hls_encoding base64url;
            secure_hls_hmac_key test-hmac-key; secure_hls_rewrite on; }}
        location /ip/ {{ alias {ROOT}/www/; {common}
            secure_hls_message "${{secure_hls_arg_ukey}}%${{secure_hls_arg_t}}%${{secure_hls_arg_pkey}}%{SECRET}";
            secure_hls_bind_ip $secure_hls_arg_pkey;
            set_real_ip_from 127.0.0.1; real_ip_header X-Real-IP; }}
        location /expires/ {{ alias {ROOT}/www/; {common} secure_hls_time_mode expires; }}
        location /fixed/ {{ alias {ROOT}/www/; {common} secure_hls_time_mode off; }}
        location /renamed/ {{ alias {ROOT}/www/;
            secure_hls_auth on; secure_hls_algorithm sha256;
            secure_hls_token $secure_hls_arg_sig;
            secure_hls_message "v2:$secure_hls_arg_user:$secure_hls_arg_at:test-key";
            secure_hls_require_args sig user at;
            secure_hls_timestamp $secure_hls_arg_at;
            secure_hls_rewrite on;
            secure_hls_param sig $secure_hls_arg_sig;
            secure_hls_param user $secure_hls_arg_user;
            secure_hls_param at $secure_hls_arg_at; }}
        location /inherit/ {{ alias {ROOT}/www/; {common} secure_hls_rewrite on;
            location /inherit/child/ {{ alias {ROOT}/www/; secure_hls_param only literal;
                secure_hls_resources lines; }} }}
        location /keys/ {{ alias {ROOT}/www/; {common} secure_hls_rewrite on; secure_hls_resources keys; }}
        location /satisfy/ {{ alias {ROOT}/www/; {common} satisfy any; allow all; }}
        location /off/ {{ alias {ROOT}/www/; secure_hls_auth off; secure_hls_rewrite off; }}
        location /bound/ {{ alias {ROOT}/www/; include {ROOT}/auth-bound.conf;
            secure_hls_rewrite on; secure_hls_resign on;
            secure_hls_allowed_origin https://cdn.example.test; }}
        location /bound-proxy/ {{ {proxy} include {ROOT}/auth-bound.conf; secure_hls_resign on; }}
        location /filename/ {{ alias {ROOT}/www/; include {ROOT}/auth-bound.conf;
            location ~ [.]ts$ {{ secure_hls_message "${{secure_hls_arg_ukey}}\\n${{secure_hls_arg_t}}\\n${{secure_hls_filename}}"; }}
            location ~ [.]m3u8$ {{ secure_hls_rewrite on; secure_hls_resign on;
                secure_hls_sign_message "${{secure_hls_arg_ukey}}\\n${{secure_hls_arg_t}}\\n${{secure_hls_target_filename}}"; }} }}
        {variants}
        {extra}
    }}
}}
"""


class Integration(unittest.TestCase):
    def success(self, path, params=None, **kwargs):
        status, headers, body = request(path, signature() if params is None else params, **kwargs)
        self.assertEqual(status, 200, (path, status, body))
        return headers, body

    def test_01_signature_vector(self):
        p = signature(stamp=1793341507)
        self.assertEqual(p["token"], "1be1dd4e192ab3312363cd6511628140")
        self.success("/fixed/hls.m3u8", p)

    def test_02_end_to_end(self):
        for source in ("static", "proxy", "stream"):
            with self.subTest(source=source):
                params = signature()
                headers, body = self.success(f"/{source}/hls.m3u8", params)
                line = next(x for x in body.decode().splitlines() if not x.startswith("#"))
                self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(line).query),
                                 {k: [v] for k, v in params.items()})
                status, _, segment = request(f"/{source}/" + line)
                self.assertEqual(status, 200)
                self.assertEqual(segment, TS)
                self.assertEqual(request(f"/{source}/GEGrR-hls-000.ts")[0], 403)
                self.assertNotIn("Content-Length", headers)
                self.assertNotIn("ETag", headers)
                self.assertNotIn("Last-Modified", headers)
                self.assertNotIn("Accept-Ranges", headers)
                self.assertEqual(headers["Cache-Control"], "private, no-store")

    def test_03_invalid_arguments(self):
        p = signature()
        cases = [None, {}, {**p, "token": "0" * 32}, {**p, "ukey": "2"},
                 {**p, "token": p["token"][:-1]}, {**p, "t": "NaN"}]
        cases += [{k: v for k, v in p.items() if k != missing} for missing in ("ukey", "t", "token")]
        for params in cases:
            self.assertEqual(request("/static/hls.m3u8", params)[0], 403, params)
        query = urllib.parse.urlencode(p)
        for suffix in ("&token=x", "&%74oken=x", "&ukey=1", "&x=%Q0", "&x=%00", "&x=%0a"):
            self.assertEqual(request("/static/hls.m3u8?" + query + suffix)[0], 403, suffix)
        # Repeated unrelated parameters are legitimate and remain unrelated.
        self.assertEqual(request("/static/hls.m3u8?" + query + "&x=1&x=2")[0], 200)
        self.assertEqual(request("/satisfy/segment.ts")[0], 403)

    def test_04_time(self):
        now = int(time.time())
        for stamp, expected in ((now, 200), (now - 7199, 200), (now - 7210, 200),
                                (now - 7235, 403), (now + 20, 200), (now + 40, 403)):
            self.assertEqual(request("/static/segment.ts", signature(stamp=stamp))[0], expected)
        self.assertEqual(request("/expires/segment.ts", signature(stamp=now + 300))[0], 200)
        self.assertEqual(request("/expires/segment.ts", signature(stamp=now - 40))[0], 403)
        self.assertEqual(request("/static/segment.ts", signature(stamp=10**30))[0], 403)

    def test_05_algorithms_encoding(self):
        for endpoint, alg, enc in (("sha", "sha256", "base64"), ("hmac", "hmac_sha256", "base64url")):
            self.success(f"/{endpoint}/hls.m3u8", signature(algorithm=alg, encoding=enc))
            self.assertEqual(request(f"/{endpoint}/hls.m3u8", signature())[0], 403)
        p = signature(); p["token"] = p["token"].upper()
        self.success("/static/hls.m3u8", p)
        p = signature(algorithm="hmac_sha256", encoding="base64url"); p["token"] += "="
        self.assertEqual(request("/hmac/hls.m3u8", p)[0], 403)

    def test_06_encoding_roundtrip(self):
        p = signature(user="user +%&=?/中文")
        _, body = self.success("/static/hls.m3u8", p)
        line = next(x for x in body.decode().splitlines() if not x.startswith("#"))
        self.assertIn("%2B", line)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(line).query)["ukey"], [p["ukey"]])
        self.assertEqual(request("/static/" + line)[0], 200)
        p.pop("pkey")
        _, body = self.success("/static/hls.m3u8", p)
        self.assertNotIn(b"pkey=", body)

    def test_07_tags_queries_origins(self):
        p = signature()
        _, body = self.success("/static/attrs.m3u8", p)
        text = body.decode()
        for name in ("key.bin?old=1&token=", "session.key?token=", "init.mp4?token=",
                     "audio.m3u8?token=", "iframe.m3u8?token=", "child.m3u8?token="):
            self.assertIn(name, text)
        self.assertIn("keep=a%2Bb&token=", text)
        self.assertNotIn("token=old", text)
        self.assertNotIn("ukey=9", text)
        self.assertIn("#part\r\n", text)
        self.assertIn(f"http://127.0.0.1:{PORT}/static/segment.ts?token=", text)
        self.assertIn(f"//127.0.0.1:{PORT}/static/segment.ts?token=", text)
        self.assertIn("https://cdn.example.test/segment.ts?token=", text)
        for literal in ('# comment URI="leave.ts"\r\n', '#EXT-X-UNKNOWN:URI="leave.ts"\r\n',
                        'https://evil.example.test/segment.ts?keep=1\r\n',
                        'https://cdn.example.test.evil.test/segment.ts\r\n',
                        'https://cdn.example.test@evil.test/segment.ts\r\n',
                        'data:application/octet-stream;base64,YQ==\r\n'):
            self.assertIn(literal, text)
        self.assertFalse(text.endswith("\n"))
        self.assertEqual(text.count("\r\n"), fixtures()["attrs.m3u8"].count(b"\r\n"))

    def test_08_many_segments(self):
        _, body = self.success("/static/many.m3u8")
        self.assertEqual(body.count(b".ts?token="), 177)
        self.assertTrue(body.endswith(b"#EXT-X-ENDLIST\n"))

    def test_09_head_range_conditionals(self):
        p = signature()
        for endpoint in ("static", "proxy"):
            h, body = self.success(f"/{endpoint}/hls.m3u8", p, method="HEAD")
            self.assertEqual(body, b"")
            self.assertNotIn("Content-Length", h)
            self.success(f"/{endpoint}/hls.m3u8", p, headers={"Range": "bytes=0-10", "If-None-Match": '"origin-v1"'})
            self.assertEqual(request(f"/{endpoint}/hls.m3u8", method="HEAD")[0], 403)
        status, headers, body = request("/static/segment.ts", p, headers={"Range": "bytes=1-4"})
        self.assertEqual(status, 206)
        self.assertEqual(body, TS[1:5])
        self.assertEqual(request("/static/segment.ts", headers={"Range": "bytes=1-4"})[0], 403)
        self.success("/static/custom.plist", p, headers={"If-Modified-Since": "Wed, 21 Oct 2099 07:28:00 GMT"})
        self.success("/proxy/mime", p)

    def test_10_gzip(self):
        for endpoint in ("static", "proxy"):
            headers, body = self.success(f"/{endpoint}/many.m3u8", headers={"Accept-Encoding": "gzip"})
            self.assertEqual(headers.get("Content-Encoding"), "gzip")
            self.assertEqual(gzip.decompress(body).count(b".ts?token="), 177)

    def test_11_bad_upstream(self):
        for name in ("encoded.m3u8", "partial.m3u8", "notmodified.m3u8"):
            self.assertEqual(request("/proxy/" + name, signature())[0], 502, name)
        self.assertEqual(request("/proxy/absent.m3u8", signature())[0], 404)

    def test_12_malformed_playlists(self):
        for name in ("invalid.m3u8", "empty.m3u8", "oversize.m3u8", "badattr.m3u8", "duplicate_uri.m3u8", "badquery.m3u8", "backslash.m3u8"):
            with self.subTest(name=name):
                try:
                    status, _, body = request("/static/" + name, signature())
                    self.assertGreaterEqual(status, 400, (name, status, body))
                except (http.client.IncompleteRead, http.client.RemoteDisconnected, ConnectionResetError):
                    pass
        self.success("/static/hls.m3u8")  # worker survives malformed input

    def test_13_ip_binding(self):
        self.success("/ip/segment.ts", signature(ip="127.0.0.1"))
        self.assertEqual(request("/ip/segment.ts", signature(ip="192.0.2.7"))[0], 403)
        self.success("/ip/segment.ts", signature(ip="192.0.2.7"), headers={"X-Real-IP": "192.0.2.7"})
        p = signature(ip="127.0.0.1"); p["pkey"] = "192.0.2.7"
        self.assertEqual(request("/ip/segment.ts", p, headers={"X-Real-IP": "192.0.2.7"})[0], 403)

    def test_14_inheritance_selection_and_renaming(self):
        _, body = self.success("/inherit/child/hls.m3u8")
        self.assertIn(b"GEGrR-hls-000.ts?only=literal", body)
        self.assertNotIn(b"token=", body)
        _, body = self.success("/keys/attrs.m3u8")
        self.assertIn(b'session.key?token=', body)
        self.assertIn(b'URI="init.mp4"', body)
        self.assertIn(b'child.m3u8\r\n', body)
        stamp = str(int(time.time()))
        p = {"sig": hashlib.sha256(f"v2:alice:{stamp}:test-key".encode()).hexdigest(), "user": "alice", "at": stamp}
        _, body = self.success("/renamed/hls.m3u8", p)
        self.assertIn(b".ts?sig=", body)
        self.assertNotIn(b"token=", body)
        status, _, body = request("/off/hls.m3u8")
        self.assertEqual((status, body), (200, BASE))

    def test_15_proxy_cache_is_not_personalized(self):
        first = signature(user="first")
        second = signature(user="second")
        h, body1 = self.success("/cache/hls.m3u8", first)
        self.assertIn(h.get("X-Cache"), ("MISS", "EXPIRED"))
        h, body2 = self.success("/cache/hls.m3u8", second)
        self.assertEqual(h.get("X-Cache"), "HIT")
        self.assertIn(b"ukey=second", body2)
        self.assertNotIn(b"ukey=first", body2)
        self.assertNotEqual(body1, body2)
        self.assertEqual(request("/cache/hls.m3u8")[0], 403)

    def test_16_fragmented_input(self):
        for width in range(1, len(BASE) + 1):
            p = signature(); p["width"] = str(width)
            _, body = self.success("/stream/split.m3u8", p)
            self.assertIn(b"GEGrR-hls-000.ts?token=", body, width)
            self.assertTrue(body.endswith(b"#EXT-X-ENDLIST\n"))

    def test_17_slow_client_and_disconnect(self):
        p = signature()
        con = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
        con.request("GET", url("/static/long.m3u8", p))
        response = con.getresponse()
        self.assertEqual(response.status, 200)
        time.sleep(0.1)
        chunks = []
        while True:
            data = response.read(8192)
            if not data:
                break
            chunks.append(data)
            time.sleep(0.0005)
        con.close()
        self.assertEqual(b"".join(chunks).count(b"segment.ts?token="), 20000)
        for _ in range(5):
            with socket.create_connection(("127.0.0.1", PORT)) as sock:
                sock.sendall(f"GET {url('/static/long.m3u8', p)} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
                sock.recv(256)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: request("/static/hls.m3u8", signature())[0], range(40)))
        self.assertEqual(results, [200] * 40)

    def test_18_configuration_errors(self):
        base = f"load_module {ARGS.module};\n" if ARGS.module else ""
        cases = [
            "secure_hls_auth on;",
            "secure_hls_algorithm imaginary;",
            "secure_hls_max_line 1;",
            "secure_hls_allowed_origin https://cdn.test/path;",
            "secure_hls_param token a; secure_hls_param token b;",
            f"include {ROOT}/auth.conf; location / {{ secure_hls_algorithm hmac_sha256; }}",
            f"include {ROOT}/auth.conf; secure_hls_bind_ip $secure_hls_arg_pkey;",
            f"include {ROOT}/auth-bound.conf; secure_hls_resign on; secure_hls_param token fixed;",
            f"include {ROOT}/auth-bound.conf; location / {{ secure_hls_resign on; secure_hls_auth off; }}",
            f"include {ROOT}/auth-bound.conf; location / {{ secure_hls_resign on; secure_hls_sign_message $secure_hls_arg_ukey; }}",
            f"include {ROOT}/auth-bound.conf; location / {{ secure_hls_resign on; secure_hls_sign_playlist_message $secure_hls_target_filename; }}",
            f'include {ROOT}/auth-bound.conf; location / {{ secure_hls_resign on; secure_hls_sign_message "${{secure_hls_target_path}}$1"; }}',
        ]
        for index, directives in enumerate(cases):
            conf = ROOT / f"bad-{index}.conf"
            conf.write_text(base + f"error_log stderr; events {{}} http {{ server {{ listen 127.0.0.1:{PORT}; {directives} }} }}")
            result = config_check(ROOT, conf)
            self.assertNotEqual(result.returncode, 0, directives)

    def test_19_documented_examples(self):
        examples = Path(__file__).resolve().parent.parent / "examples"
        prefix = ROOT / "examples"
        for name in ("conf", "modules", "logs", "cache"):
            (prefix / name).mkdir(parents=True, exist_ok=True)
        shutil.copy2(examples / "auth.conf", prefix / "conf/secure-hls-auth.conf")
        shutil.copy2(examples / "proxy-playlist.conf", prefix / "conf/secure-hls-proxy-playlist.conf")
        if ARGS.module:
            shutil.copy2(ARGS.module, prefix / "modules/ngx_http_secure_hls_module.so")
        for name in ("nginx-static.conf", "nginx-proxy.conf"):
            text = (examples / name).read_text()
            if not ARGS.module:
                text = "\n".join(line for line in text.splitlines() if not line.startswith("load_module"))
            conf = prefix / "conf/nginx.conf"
            conf.write_text(text)
            result = config_check(prefix, conf)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_20_full_path_binding(self):
        for prefix in ("/bound/", "/bound-proxy/"):
            with self.subTest(prefix=prefix):
                path = prefix + "hls.m3u8"
                p = path_signature(path)
                _, body = self.success(path, p)
                line = next(x for x in body.decode().splitlines() if not x.startswith("#"))
                target = urllib.parse.urljoin(path, line)
                parsed = urllib.parse.urlsplit(target)
                fields = dict(urllib.parse.parse_qsl(parsed.query))
                self.assertNotEqual(fields["token"], p["token"])
                self.assertEqual(fields["token"], path_signature(parsed.path, stamp=p["t"])["token"])
                self.assertEqual(request(target)[0], 200)
                self.assertEqual(request(prefix + "a/hls.m3u8", p)[0], 403)
                self.assertEqual(request(prefix + "many.m3u8", p)[0], 403)
                self.assertEqual(request(prefix + "a/GEGrR-hls-000.ts", fields)[0], 403)
                self.assertEqual(request(prefix + "segment.ts", fields)[0], 403)
                self.assertEqual(request(parsed.path, {**fields, "ukey": "other"})[0], 403)
                self.assertEqual(request(parsed.path, {**fields, "t": str(int(p["t"]) + 1)})[0], 403)
                self.assertEqual(request(path, signature())[0], 403)
                self.assertEqual(request(path, path_signature(path, stamp=int(time.time()) - 7240))[0], 403)
                # Same path, different CDN host: no domain binding by design.
                self.assertEqual(request(parsed.path, fields, headers={"Host": "cdn.example.test"})[0], 200)
        with socket.create_connection(("127.0.0.1", PORT), timeout=5) as sock:
            sock.sendall(("GET " + url("/bound/hls.m3u8", path_signature("/bound/hls.m3u8"))
                          + " HTTP/1.0\r\n\r\n").encode())
            received = bytearray()
            while True:
                block = sock.recv(8192)
                if not block:
                    break
                received.extend(block)
            self.assertTrue(received.startswith(b"HTTP/1.1 200") or received.startswith(b"HTTP/1.0 200"))
            self.assertIn(b"GEGrR-hls-000.ts?", received)

    def test_21_path_resolution_and_child_playlists(self):
        path = "/bound/a/paths.m3u8"
        p = path_signature(path)
        _, body = self.success(path, p)
        lines = [x for x in body.decode().splitlines() if not x.startswith("#")]
        tokens = []
        for line in lines:
            full = urllib.parse.urljoin(f"http://127.0.0.1:{PORT}" + path, line)
            parts = urllib.parse.urlsplit(full)
            normalized = urllib.parse.unquote(parts.path)
            fields = dict(urllib.parse.parse_qsl(parts.query))
            self.assertEqual(fields["token"], path_signature(normalized, stamp=p["t"])["token"], line)
            if "cdn.example.test" not in parts.netloc:
                status, _, content = request(parts.path + "?" + parts.query)
                self.assertEqual(status, 200, line)
                if normalized.endswith("child.m3u8"):
                    child_line = next(x for x in content.decode().splitlines() if not x.startswith("#"))
                    child_target = urllib.parse.urljoin(parts.path, child_line)
                    self.assertEqual(request(child_target)[0], 200)
            tokens.append(fields["token"])
        # Different URI spellings/query values referring to the same path agree.
        self.assertEqual(tokens[0], tokens[2])
        self.assertEqual(tokens[0], tokens[4])
        self.assertIn("quality=hd", lines[0])
        self.assertTrue(lines[0].endswith("#part"))
        self.assertEqual(request("/bound/a/../hls.m3u8", path_signature("/bound/hls.m3u8"))[0], 200)
        self.assertEqual(request("/bound/a/%2e%2e/other/hls.m3u8", path_signature("/bound/a/hls.m3u8"))[0], 403)

    def test_22_resign_large_playlists_and_filename_mode(self):
        path = "/bound/long.m3u8"
        p = path_signature(path)
        _, body = self.success(path, p)
        expected = path_signature("/bound/segment.ts", stamp=p["t"])["token"].encode()
        self.assertEqual(body.count(expected), 20000)
        path = "/filename/hls.m3u8"
        p = path_signature(path)
        _, body = self.success(path, p)
        line = next(x for x in body.decode().splitlines() if not x.startswith("#"))
        fields = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(line).query))
        self.assertEqual(fields["token"], path_signature("GEGrR-hls-000.ts", stamp=p["t"], filename=True)["token"])
        self.assertEqual(request("/filename/" + line)[0], 200)
        self.assertEqual(request("/filename/a/GEGrR-hls-000.ts", fields)[0], 200)
        self.assertEqual(request("/filename/segment.ts", fields)[0], 403)
        self.assertEqual(request("/filename/a/hls.m3u8", p)[0], 403)

    def test_23_php_issuer(self):
        php = shutil.which("php")
        self.assertIsNotNone(php, "php-cli is required to verify the bundled issuer")
        script = str(Path(__file__).resolve().parent.parent / "examples/sign.php")
        stamp = str(int(time.time()))
        for relative in ("/bound/hls.m3u8", "/bound/a/../%68ls.m3u8",
                         "/bound//hls.m3u8?keep=a%2Bb&token=old&%74oken=older#part",
                         "/bound/space%20name.ts", "/bound/%252F.ts", "/bound/%3F.ts", "/bound/%23.ts"):
            signed = subprocess.check_output([php, script, "https://cdn.example.test" + relative,
                                              "user +中文", "", stamp], text=True).strip()
            parts = urllib.parse.urlsplit(signed)
            fields = dict(urllib.parse.parse_qsl(parts.query))
            expected = path_signature(urllib.parse.unquote(parts.path), user="user +中文", stamp=stamp)
            self.assertEqual(fields["token"], expected["token"])
            self.assertEqual(request(parts.path + "?" + parts.query)[0], 200, signed)
            self.assertEqual(len(urllib.parse.parse_qs(parts.query)["token"]), 1)
        for path in ("/../escape.m3u8", "/bad%Q0.m3u8", "/bad%0a.m3u8"):
            result = subprocess.run([php, script, "https://example.test" + path, "1"], capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_24_resign_configurable_algorithm_fields_and_template(self):
        stamp = str(int(time.time()))
        for algorithm, encoding in (("md5", "hex"), ("sha256", "base64url"), ("hmac_sha256", "base64")):
            with self.subTest(algorithm=algorithm, encoding=encoding):
                def credentials(path, at=stamp):
                    message = f"v3|{path}|changed user|{at}|alternate-key".encode()
                    digest = (hmac.new(b"alternate-key", message, hashlib.sha256).digest()
                              if algorithm == "hmac_sha256" else hashlib.new(algorithm, message).digest())
                    encoded = {"hex": digest.hex(), "base64": base64.b64encode(digest).decode(),
                               "base64url": base64.urlsafe_b64encode(digest).decode().rstrip("=")}[encoding]
                    return {"sig": encoded, "user": "changed user", "at": at}
                path = f"/resign-{algorithm}/hls.m3u8"
                _, body = self.success(path, credentials(path))
                line = next(x for x in body.decode().splitlines() if not x.startswith("#"))
                target = urllib.parse.urljoin(path, line)
                parsed = urllib.parse.urlsplit(target)
                fields = dict(urllib.parse.parse_qsl(parsed.query))
                self.assertEqual(fields, credentials(parsed.path))
                self.assertEqual(request(target)[0], 200)
                self.assertEqual(request(parsed.path.replace("000.ts", "001.ts"), fields)[0], 403)
                self.assertEqual(request(path, credentials(path, str(int(stamp) - 640)))[0], 403)


def main():
    global ARGS, PORT, UPSTREAM_PORT, ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx", required=True)
    parser.add_argument("--module", default="")
    parser.add_argument("--work", required=True)
    ARGS = parser.parse_args()
    report_dir = Path(ARGS.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    # Native Linux filesystem: Windows bind mounts do not provide all cache
    # tempfile/unlink/fstat semantics used by nginx.
    ROOT = Path(tempfile.mkdtemp(prefix="secure-hls-test-"))
    ROOT.mkdir(parents=True, exist_ok=True)
    ROOT.chmod(0o755)
    (ROOT / "www").mkdir(exist_ok=True)
    (ROOT / "logs").mkdir(exist_ok=True)
    PORT, UPSTREAM_PORT = free_port(), free_port()
    for name, data in fixtures().items():
        (ROOT / "www" / name).write_bytes(data)
    for directory in ("a", "other", "sub", "a/sub"):
        folder = ROOT / "www" / directory
        folder.mkdir(parents=True, exist_ok=True)
        for name, data in fixtures().items():
            (folder / name).write_bytes(data)
    examples = Path(__file__).resolve().parent.parent / "examples"
    shutil.copy2(examples / "auth.conf", ROOT / "auth-bound.conf")
    (ROOT / "auth.conf").write_text(f"""
secure_hls_auth on;
secure_hls_algorithm md5;
secure_hls_token $secure_hls_arg_token;
secure_hls_message "${{secure_hls_arg_ukey}}%${{secure_hls_arg_t}}%{SECRET}";
secure_hls_require_args token ukey t;
secure_hls_timestamp $secure_hls_arg_t;
secure_hls_time_mode issued;
secure_hls_ttl 2h;
secure_hls_clock_skew 30s;
secure_hls_param token $secure_hls_arg_token;
secure_hls_param ukey $secure_hls_arg_ukey;
secure_hls_param pkey $secure_hls_arg_pkey;
secure_hls_param t $secure_hls_arg_t;
""")
    config = ROOT / "nginx.conf"
    config.write_text(config_text())
    (ROOT / "error.log").write_text("")
    checked = config_check(ROOT, config)
    if checked.returncode != 0:
        raise RuntimeError(checked.stderr.decode())
    server = http.server.ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with (ROOT / "process.log").open("w") as log:
        process = subprocess.Popen([ARGS.nginx, "-p", str(ROOT), "-c", str(config)], stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((ROOT / "process.log").read_text() + (ROOT / "error.log").read_text())
                try:
                    with socket.create_connection(("127.0.0.1", PORT), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Integration))
        finally:
            process.send_signal(signal.SIGQUIT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
            server.shutdown()
    logs = (ROOT / "process.log").read_text() + (ROOT / "error.log").read_text()
    sanitizer_ok = not any(word in logs for word in ("ERROR: AddressSanitizer", "runtime error:", "LeakSanitizer"))
    report = {"binary": ARGS.nginx, "module": ARGS.module, "tests": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "process_exit": process.returncode, "sanitizers_clean": sanitizer_ok}
    (ROOT / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    for name in ("result.json", "nginx.conf", "auth.conf", "error.log", "process.log"):
        shutil.copy2(ROOT / name, report_dir / name)
    if not result.wasSuccessful() or process.returncode != 0 or not sanitizer_ok:
        print(logs[-12000:])
        raise SystemExit(1)
    shutil.rmtree(ROOT)


if __name__ == "__main__":
    main()
