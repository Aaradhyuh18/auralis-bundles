"""
Tests for the source-cache fallback in build_bundle.py. No network: `download` is replaced.

    python -I -m unittest tools/test_build_bundle.py -v        (from the repo root)
"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_bundle as bb  # noqa: E402

GOOD = ("\n".join(f"site{i}.example.com" for i in range(1000)) + "\n").encode()
TINY = b"only.example.com\n"
URL = "https://example.invalid/list.txt"


def fail(_url):
    raise OSError("HTTP Error 404: Not Found")


class SourceCacheTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def run_source(self, download):
        with mock.patch.object(bb, "download", download):
            return bb.load_source("src", URL, "text", self.cache)

    def seed(self, payload=GOOD, age_days=0):
        bb.save_cache(self.cache, "src", URL, payload, bb.count_hosts(bb.parse_payload(payload, "text")))
        if age_days:
            meta_path = self.cache / "src.meta.json"
            meta = json.loads(meta_path.read_text())
            meta["fetched_at"] = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
            meta_path.write_text(json.dumps(meta))

    def test_good_download_is_used_and_cached(self):
        lines, info = self.run_source(lambda _u: GOOD)
        self.assertFalse(info["fallback"])
        self.assertEqual(len(lines), 1000)
        self.assertIsNotNone(bb.load_cache(self.cache, "src"))

    def test_failed_download_uses_fresh_cache(self):
        self.seed()
        lines, info = self.run_source(fail)
        self.assertTrue(info["fallback"])
        self.assertEqual(len(lines), 1000)
        self.assertEqual(info["stale_days"], 0)

    def test_failed_download_without_cache_fails(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.run_source(fail)
        self.assertIn("no usable cached copy", str(ctx.exception))

    def test_cache_older_than_limit_fails_loudly(self):
        self.seed(age_days=bb.CACHE_MAX_AGE_DAYS + 1)
        with self.assertRaises(RuntimeError) as ctx:
            self.run_source(fail)
        self.assertIn("days old", str(ctx.exception))

    def test_cache_at_the_limit_is_still_used(self):
        self.seed(age_days=bb.CACHE_MAX_AGE_DAYS)
        _lines, info = self.run_source(fail)
        self.assertTrue(info["fallback"])
        self.assertEqual(info["stale_days"], bb.CACHE_MAX_AGE_DAYS)

    def test_tiny_download_is_treated_as_broken_and_does_not_overwrite_cache(self):
        self.seed()
        lines, info = self.run_source(lambda _u: TINY)
        self.assertTrue(info["fallback"])
        self.assertEqual(len(lines), 1000)
        cached = bb.load_cache(self.cache, "src")
        self.assertEqual(cached[1]["entries"], 1000)  # unchanged: the tiny file did not poison it

    def test_empty_download_without_cache_fails(self):
        with self.assertRaises(RuntimeError):
            self.run_source(lambda _u: b"# nothing\n")

    def test_corrupt_cache_is_ignored(self):
        self.seed()
        (self.cache / "src.payload").write_bytes(b"tampered")
        self.assertIsNone(bb.load_cache(self.cache, "src"))
        with self.assertRaises(RuntimeError):
            self.run_source(fail)

    def test_malformed_metadata_is_ignored(self):
        self.seed()
        (self.cache / "src.meta.json").write_text("{not json")
        self.assertIsNone(bb.load_cache(self.cache, "src"))

    def test_no_cache_dir_behaves_as_before(self):
        with mock.patch.object(bb, "download", lambda _u: GOOD):
            lines, info = bb.load_source("src", URL, "text", None)
        self.assertEqual(len(lines), 1000)
        self.assertFalse(info["fallback"])
        with mock.patch.object(bb, "download", fail), self.assertRaises(RuntimeError):
            bb.load_source("src", URL, "text", None)

    def test_a_good_download_replaces_an_older_cache(self):
        self.seed(payload=TINY * 1)  # 1 entry cached, so a bigger fresh download is not "broken"
        lines, info = self.run_source(lambda _u: GOOD)
        self.assertFalse(info["fallback"])
        self.assertEqual(bb.load_cache(self.cache, "src")[1]["entries"], 1000)


class UnionTests(unittest.TestCase):
    def test_one_source_down_still_builds_and_marks_fallback_in_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            payloads = {name: GOOD.replace(b"site", name.encode()[:3] + b"-") for name, _u, _k in bb.SOURCES}

            def fake_download(url):
                name = next(n for n, u, _k in bb.SOURCES if u == url)
                return payloads[name]

            def as_text(payload, kind):
                return payload.decode().splitlines()

            sources = [(n, u, "text") for n, u, _k in bb.SOURCES]
            with mock.patch.object(bb, "SOURCES", sources), mock.patch.object(bb, "download", fake_download):
                _hashes, first = bb.build_union(cache)
                self.assertTrue(all("fallback" not in s for s in first))

            down_name = sources[-1][0]

            def flaky(url):
                if url == sources[-1][1]:
                    raise OSError("HTTP Error 404: Not Found")
                return fake_download(url)

            with mock.patch.object(bb, "SOURCES", sources), mock.patch.object(bb, "download", flaky):
                hashes, second = bb.build_union(cache)

            fell_back = [s for s in second if s.get("fallback")]
            self.assertEqual([s["name"] for s in fell_back], [down_name])
            self.assertEqual(len(hashes), 3000)  # all three sources still contributed


if __name__ == "__main__":
    unittest.main()
