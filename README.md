# auralis-bundles

Signed DNS blocklist bundles, rebuilt daily from public sources.

## What this is

A publishing target. Each release contains a compiled blocklist index and a manifest signed with
Ed25519, which a client verifies against a pinned public key before applying.

Sources, all fetched fresh on every build:

| Source | Licence |
|---|---|
| [HaGeZi NSFW](https://github.com/hagezi/dns-blocklists) | GPL-3.0 |
| [StevenBlack hosts (porn)](https://github.com/StevenBlack/hosts) | MIT |
| [University of Toulouse blacklists (adult)](https://dsi.ut-capitole.fr/blacklists/) | free for use |

## What this is not

This repository contains **no personal information**. No browsing data, no device data, no usage
statistics, no configuration. The payload is public blocklist data, deduplicated and reformatted.

## Release contents

| File | Purpose |
|---|---|
| `manifest.json` | version, domain count, artifact hashes |
| `manifest.json.sig` | Ed25519 signature over `manifest.json` |
| `index-<version>.bin` | full sorted index of 64-bit domain hashes |
| `delta-<from>-<to>.bin.gz` | additions and removals since the previous bundle |

Clients apply the delta and fall back to the full index only on first sync or if the chain breaks.

## Safety properties

- A failed build publishes nothing, so clients keep the list they already have. They never end up
  with an empty one.
- A union that collapses below 80% of the previous bundle is refused at build time, so an upstream
  outage cannot produce a bundle that silently stops blocking.
- Versions are strictly monotonic, so an old bundle cannot be replayed over a newer one.

Only hashes are published, not domains, so the underlying list is not recoverable from a bundle.
