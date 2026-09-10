#!/usr/bin/env python3
"""
Builds a signed blocklist bundle for Auralis Guard.

Fetches the upstream lists, compiles their union into the same binary index format the app uses
at runtime, computes a delta against the previous bundle, and signs the manifest with Ed25519.

Run by .github/workflows/blocklist-update.yml on a daily schedule. The private signing key never
leaves GitHub Actions secrets; the app pins only the public key.

Two invariants matter more than anything else here, both from docs/ARCHITECTURE.md section 7:

  * A bundle that fails verification must leave the previous list in place. Never empty.
  * Versions are monotonic, so an old bundle can never be replayed over a newer one.

The sanity floor below enforces the first invariant at build time: if an upstream list breaks and
returns almost nothing, we refuse to publish rather than shipping a bundle that silently stops
blocking.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MAGIC_INDEX = 0x4147424C  # "AGBL"
MAGIC_DELTA = 0x4147444C  # "AGDL"
FORMAT_VERSION = 1
HEADER_BYTES = 16

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = 0xFFFFFFFFFFFFFFFF

# Refuse to publish if the union collapses to less than this fraction of the previous bundle.
# An upstream outage returning an empty file must not become a bundle that stops blocking.
SANITY_FLOOR = 0.80

SOURCES = [
    (
        "hagezi-nsfw",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
        "text",
    ),
    (
        "stevenblack-porn",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
        "text",
    ),
    (
        "toulouse-adult",
        "https://dsi.ut-capitole.fr/blacklists/download/adult.tar.gz",
        "tar:adult/domains",
    ),
]

IGNORED = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "0.0.0.0",
}

# Public DNS resolver addresses the app routes into its VPN tunnel and answers directly, so an
# app/browser that hard-codes one of these (instead of using the device's normal DNS path) still
# gets filtered answers rather than bypassing everything. Moved here from a hardcoded APK constant
# 2026-09-10 (Guard's Phase 11 adversarial suite, finding B2) specifically so it can grow over time
# via this same daily pipeline instead of needing an app release. The app unions this with its own
# small built-in seed list (ResolverPolicy.SEED in the app repo) — this list only ever adds to that
# floor, never replaces it, so a bad or missing bundle can't shrink coverage below the seed.
#
# Kept in sync manually with the app's seed list for now, not auto-derived from it — the two repos
# are deliberately independent (this one is public, the app's is private) and the overlap is a
# reasonable duplication of a short, rarely-changing list rather than a build-time coupling between
# them.
RESOLVERS = [
    # Google
    "8.8.8.8", "8.8.4.4",
    # Cloudflare, including the family-filter variants
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    # Quad9
    "9.9.9.9", "9.9.9.10", "9.9.9.11", "149.112.112.112", "149.112.112.9",
    # OpenDNS / Cisco
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
    # AdGuard
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16",
    # CleanBrowsing
    "185.228.168.9", "185.228.169.9", "185.228.168.10", "185.228.169.11",
    # NextDNS
    "45.90.28.0", "45.90.30.0",
    # Comodo
    "8.26.56.26", "8.20.247.20",
    # Verisign
    "64.6.64.6", "64.6.65.6",
    # DNS.WATCH
    "84.200.69.80", "84.200.70.40",
    # Mullvad
    "194.242.2.2", "194.242.2.4",
    # ControlD
    "76.76.2.0", "76.76.10.0",
    # Level3 — deliberately including the secondaries the app's own seed list does not (.3/.4/.5/.6),
    # since the app already covers .1/.2; this is the first real "grown since the seed" entry.
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    # Yandex
    "77.88.8.8", "77.88.8.1",
    # DNS.SB
    "185.222.222.222", "45.11.45.11",
    # Alternate DNS
    "76.76.19.19", "76.223.122.150",
    # Digitale Gesellschaft (Switzerland) — the specific non-mainstream provider used to
    # demonstrate the bypass live during the adversarial suite; added precisely because it's the
    # kind of provider that isn't in any browser's built-in dropdown but is one search away.
    "185.95.218.42", "185.95.218.43",
]


def fnv1a64(host: str) -> int:
    """Must stay byte-for-byte identical to DomainBlocklist.hash() in the app."""
    h = FNV_OFFSET
    for byte in host.encode("ascii"):
        h ^= byte
        h = (h * FNV_PRIME) & MASK64
    return h


def to_signed(value: int) -> int:
    """
    The app stores these as Java longs and sorts them signed. Python treats them as unsigned, so
    ordering would diverge above 2^63 and every binary search past that point would fail. Convert
    before sorting, and write with a signed pack.
    """
    return value - (1 << 64) if value >= (1 << 63) else value


def parse_host(line: str) -> str | None:
    line = line.strip()
    if not line or line[0] in "#!":
        return None

    host = line.split()[-1].strip().lower()
    if "." not in host or host in IGNORED:
        return None
    # Non-ASCII would hash differently in Python and Kotlin. Domain lists are punycode, so
    # dropping these costs nothing and removes a whole class of silent mismatch.
    if not host.isascii():
        return None
    return host


def fetch(url: str, kind: str) -> list[str]:
    print(f"  fetching {url}", flush=True)
    request = urllib.request.Request(url, headers={"User-Agent": "auralis-guard-bundler"})
    with urllib.request.urlopen(request, timeout=300) as response:
        payload = response.read()

    if kind == "text":
        return payload.decode("utf-8", "replace").splitlines()

    if kind.startswith("tar:"):
        member = kind[4:]
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"{member} missing from archive")
            return extracted.read().decode("utf-8", "replace").splitlines()

    raise ValueError(f"unknown source kind: {kind}")


def build_union() -> tuple[set[int], list[dict]]:
    hashes: set[int] = set()
    stats: list[dict] = []

    for name, url, kind in SOURCES:
        before = len(hashes)
        count = 0
        for line in fetch(url, kind):
            host = parse_host(line)
            if host:
                hashes.add(fnv1a64(host))
                count += 1
        stats.append({"name": name, "domains": count, "new": len(hashes) - before})
        print(f"  {name}: {count:,} entries, {len(hashes) - before:,} new", flush=True)

    return hashes, stats


def write_index(path: Path, sorted_signed: list[int], version: int) -> None:
    with path.open("wb") as handle:
        handle.write(
            struct.pack(">iiii", MAGIC_INDEX, FORMAT_VERSION, version, len(sorted_signed))
        )
        chunk = bytearray()
        for value in sorted_signed:
            chunk += struct.pack(">q", value)
            if len(chunk) >= 1 << 16:
                handle.write(chunk)
                chunk = bytearray()
        if chunk:
            handle.write(chunk)


def read_index(path: Path) -> list[int]:
    raw = path.read_bytes()
    magic, fmt, _version, count = struct.unpack(">iiii", raw[:HEADER_BYTES])
    if magic != MAGIC_INDEX or fmt != FORMAT_VERSION:
        raise ValueError("previous index has an unexpected format")
    return list(struct.unpack(f">{count}q", raw[HEADER_BYTES : HEADER_BYTES + count * 8]))


def write_delta(path: Path, added: list[int], removed: list[int], base: int, target: int) -> None:
    body = struct.pack(">iiiiii", MAGIC_DELTA, FORMAT_VERSION, base, target, len(added), len(removed))
    body += b"".join(struct.pack(">q", v) for v in added)
    body += b"".join(struct.pack(">q", v) for v in removed)
    path.write_bytes(gzip.compress(body, 9))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sign(manifest: Path, signature: Path, pem: str) -> None:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem.encode(), password=None)
    signature.write_bytes(key.sign(manifest.read_bytes()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--previous-index", type=Path)
    parser.add_argument("--previous-version", type=int, default=0)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    version = int(datetime.now(timezone.utc).strftime("%Y%m%d"))
    if version <= args.previous_version:
        version = args.previous_version + 1  # keep versions strictly monotonic

    print("building union", flush=True)
    hashes, stats = build_union()
    current = sorted(to_signed(h) for h in hashes)
    print(f"union: {len(current):,} distinct domains", flush=True)

    previous: list[int] = []
    if args.previous_index and args.previous_index.is_file():
        previous = read_index(args.previous_index)
        print(f"previous bundle: {len(previous):,} domains", flush=True)

        if len(current) < len(previous) * SANITY_FLOOR:
            print(
                f"REFUSING: union shrank to {len(current):,} from {len(previous):,} "
                f"(floor {SANITY_FLOOR:.0%}). An upstream source is probably broken.",
                file=sys.stderr,
            )
            return 1

    index_name = f"index-{version}.bin"
    write_index(args.out / index_name, current, version)

    resolvers_name = "resolvers.json"
    resolvers_path = args.out / resolvers_name
    resolvers_path.write_text(json.dumps(RESOLVERS, indent=2))
    print(f"resolvers: {len(RESOLVERS)} addresses", flush=True)

    manifest = {
        "version": version,
        "created": datetime.now(timezone.utc).isoformat(),
        "domains": len(current),
        "format": FORMAT_VERSION,
        "index": {
            "name": index_name,
            "size": (args.out / index_name).stat().st_size,
            "sha256": sha256(args.out / index_name),
        },
        "resolvers": {
            "name": resolvers_name,
            "count": len(RESOLVERS),
            "size": resolvers_path.stat().st_size,
            "sha256": sha256(resolvers_path),
        },
        "sources": stats,
    }

    if previous:
        previous_set = set(previous)
        current_set = set(current)
        added = sorted(current_set - previous_set)
        removed = sorted(previous_set - current_set)
        delta_name = f"delta-{args.previous_version}-{version}.bin.gz"
        write_delta(args.out / delta_name, added, removed, args.previous_version, version)
        manifest["delta"] = {
            "name": delta_name,
            "from": args.previous_version,
            "added": len(added),
            "removed": len(removed),
            "size": (args.out / delta_name).stat().st_size,
            "sha256": sha256(args.out / delta_name),
        }
        print(f"delta: +{len(added):,} -{len(removed):,}", flush=True)

    manifest_path = args.out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    pem = os.environ.get("BUNDLE_SIGNING_KEY")
    if not pem:
        print("BUNDLE_SIGNING_KEY not set — refusing to publish an unsigned bundle", file=sys.stderr)
        return 1
    sign(manifest_path, args.out / "manifest.json.sig", pem)

    print(f"bundle {version} ready: {len(current):,} domains", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
