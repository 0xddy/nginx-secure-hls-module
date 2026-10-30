#!/usr/bin/env python3
"""Summarize successful matrix runs and fingerprint the delivered inputs."""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--work", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("builds", nargs="+")
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
builds = []
for label in args.builds:
    target = Path(args.work) / label
    result = json.loads((target / "test/result.json").read_text())
    if result["failures"] or result["errors"] or result["process_exit"] or not result["sanitizers_clean"]:
        raise SystemExit(f"Cannot certify unsuccessful build: {label}")
    binary = Path((target / "binary.path").read_text().strip())
    item = {"build": label, **result, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    module = (target / "module.path").read_text().strip()
    if module:
        item["module_sha256"] = hashlib.sha256(Path(module).read_bytes()).hexdigest()
    builds.append(item)

inputs = ["src/ngx_http_secure_hls_module.c", "config", "tests/integration.py",
          "examples/auth.conf", "examples/auth-legacy.conf", "examples/sign.php",
          "examples/nginx-static.conf", "examples/nginx-proxy.conf", "examples/proxy-playlist.conf"]
hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in inputs}
message = b"1\n1793341507\n/upload/hls/video/hls.m3u8"
report = {
    "verified_at_utc": datetime.now(timezone.utc).isoformat(),
    "default_binding": "normalized full path + userid + issued time; HMAC-SHA256; per-resource signing",
    "source_sha256": hashes[inputs[0]],
    "test_sha256": hashes["tests/integration.py"],
    "input_sha256": hashes,
    "builds": builds,
    "sanitizer": {
        "build": "nginx-1.30.6-static-yes",
        "checks": "ASan + UBSan; LeakSanitizer enabled for the HTTP process and graceful exit",
        "upstream_ubsan_suppression": "tests/ubsan.supp: ngx_pstrdup nonnull-attribute",
        "config_test_exception": "Only nginx -t disables leak detection: upstream main returns without destroying the configuration cycle; ASan/UBSan remain enabled"
    },
    "php_signature_vector": hmac.new(b"demo-hls-secret", message, hashlib.sha256).hexdigest(),
    "legacy_md5_vector": hashlib.md5(b"1%1793341507%demo-hls-secret").hexdigest()
}
output = Path(args.output)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, indent=2) + "\n")
print(f"Verified {len(builds)} builds; report: {output}")
