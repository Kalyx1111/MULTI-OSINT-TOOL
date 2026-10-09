"""Offline-bundle integrity, archive extraction and install pre-flight tests (no network, no installs)."""
import hashlib
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mot_testlib as T  # noqa: E402

import mot_config as C  # noqa: E402
import mot_tools as M  # noqa: E402


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class ManifestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wh_", dir=T._TMP))
        self._w, self._m = C.WHEELS, M.MANIFEST
        C.WHEELS, M.MANIFEST = self.tmp, self.tmp / "mot_wheels.sha256"
        self.core = self.tmp / "core"
        self.core.mkdir()
        (self.core / "a-1.0-py3-none-any.whl").write_bytes(b"alpha")
        (self.core / "b-1.0-py3-none-any.whl").write_bytes(b"beta")
        self.manifest()

    def tearDown(self):
        C.WHEELS, M.MANIFEST = self._w, self._m

    def manifest(self, extra=()):
        lines = [f"{sha(f.read_bytes())}  core/{f.name}" for f in sorted(self.core.iterdir()) if f.is_file() and f.name != ".gitkeep"]
        M.MANIFEST.write_text("\n".join(lines + list(extra)) + "\n", encoding="utf-8")


class TestManifest(ManifestCase):
    def test_intact_bundle_passes(self):
        self.assertEqual(M.verify_manifest(self.core), [])

    def test_changed_file_is_refused(self):
        (self.core / "a-1.0-py3-none-any.whl").write_bytes(b"alphX")
        self.assertTrue(any("a-1.0" in p and "mismatched" in p for p in M.verify_manifest(self.core)))

    def test_unlisted_file_is_refused(self):
        (self.core / "evil-1.0-py3-none-any.whl").write_bytes(b"x")
        self.assertTrue(any("evil-1.0" in p for p in M.verify_manifest(self.core)))

    def test_missing_file_is_reported_clearly(self):
        (self.core / "b-1.0-py3-none-any.whl").unlink()
        self.assertTrue(any("b-1.0" in p and "missing" in p for p in M.verify_manifest(self.core)))

    def test_gitkeep_is_ignored(self):
        (self.core / ".gitkeep").write_bytes(b"")
        self.assertEqual(M.verify_manifest(self.core), [])

    def test_malformed_and_escaping_lines_are_reported_not_skipped(self):
        good = sha(b"alpha")
        for bad in (f"{'0' * 64}  ../../etc/passwd", f"{good}  /etc/passwd", f"{good}  C:\\Windows\\x", f"{good}  core\\a.whl", f"{good}  core//a.whl",
                    f"{good}  core/./a.whl", "zz  core/a-1.0-py3-none-any.whl", f"{good} core/a.whl", f"{good}  "):
            self.manifest([bad])
            problems = M.verify_manifest(self.core)
            self.assertTrue(any("malformed" in p for p in problems), bad)

    def test_missing_empty_or_unreadable_manifest(self):
        M.MANIFEST.write_text("\n", encoding="utf-8")
        self.assertTrue(any("empty" in p for p in M.verify_manifest(self.core)))
        M.MANIFEST.write_bytes(b"\xff\xfe\x00bad")
        self.assertTrue(M.verify_manifest(self.core))  # unreadable or malformed: never "all good"
        M.MANIFEST.unlink()
        self.assertTrue(any("No wheels/mot_wheels.sha256" in p for p in M.verify_manifest(self.core)))

    def test_folder_outside_wheels_or_missing(self):
        self.manifest()
        self.assertTrue(any("outside" in p for p in M.verify_manifest(Path(tempfile.mkdtemp(dir=T._TMP)))))
        self.assertTrue(any("missing" in p for p in M.verify_manifest(self.tmp / "nope")))


class TestInstallPreflight(ManifestCase):
    """Offline mode must never fall back to a download, and must fail before it deletes a working installation."""

    def setUp(self):
        super().setUp()
        self.cfg = C.Config(self.tmp / "cfg.json").load()
        self._libs = C.LIBS
        C.LIBS = self.tmp / "libs"
        self.guard = os.path.join(str(self.tmp), "never")

    def tearDown(self):
        C.LIBS = self._libs
        super().tearDown()

    def _bundle(self, cid: str, files: dict):
        d = self.tmp / cid
        d.mkdir(exist_ok=True)
        for n, b in files.items():
            (d / n).write_bytes(b)
        lines = [f"{sha(f.read_bytes())}  {f.relative_to(self.tmp).as_posix()}" for f in sorted(self.tmp.rglob("*")) if f.is_file() and f.name != "mot_wheels.sha256" and f.name != "cfg.json"]
        M.MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return d

    def test_unknown_tool(self):
        self.assertFalse(M.install_tool("nope", self.cfg)["ok"])

    def test_offline_url_recipe_without_built_wheel_is_refused_before_any_venv(self):
        self._bundle("theharvester", {"unrelated-1.0-py3-none-any.whl": b"x"})
        r = M.install_tool("theharvester", self.cfg, offline=True)
        self.assertFalse(r["ok"])
        self.assertIn("no built wheel", r["msg"])
        self.assertFalse((C.LIBS / "tools" / "theharvester").exists(), "nothing may be created or deleted on a pre-flight failure")

    def test_offline_archive_recipe_without_archive_is_refused(self):
        self._bundle("spiderfoot", {"somepackage-1.0-py3-none-any.whl": b"x"})
        r = M.install_tool("spiderfoot", self.cfg, offline=True)
        self.assertFalse(r["ok"])
        self.assertIn("no source archive", r["msg"])
        self.assertFalse((C.LIBS / "tools" / "spiderfoot").exists())

    def test_offline_with_tampered_bundle_is_refused_and_keeps_existing_install(self):
        d = self._bundle("sherlock", {"sherlock_project-0.16.2-py3-none-any.whl": b"real"})
        existing = C.LIBS / "tools" / "sherlock"
        existing.mkdir(parents=True)
        (existing / "marker.txt").write_text("working install")
        (d / "sherlock_project-0.16.2-py3-none-any.whl").write_bytes(b"tampered")
        r = M.install_tool("sherlock", self.cfg, offline=True)
        self.assertFalse(r["ok"])
        self.assertIn("integrity", r["msg"])
        self.assertTrue((existing / "marker.txt").exists(), "a failed pre-flight must not destroy a working installation")

    def test_recipes_are_pinned(self):
        for cid, rec in M.RECIPES.items():
            tgt = rec.get("pkg") or rec.get("archive")
            self.assertTrue(("==" in tgt) or ("/tags/" in tgt), f"{cid} must be pinned to a version or tag")


class TestSafeExtract(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="zx_", dir=T._TMP))

    def _zip(self, entries):
        p = self.tmp / "t.zip"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in entries:
                z.writestr(zipfile.ZipInfo(name), data)
        return p

    def test_normal_archive(self):
        top = M._safe_extract(self._zip([("proj-1.0/requirements.txt", "requests\n"), ("proj-1.0/sf.py", "print(1)")]), self.tmp / "out")
        self.assertTrue((top / "requirements.txt").is_file())

    def test_zip_slip_is_refused(self):
        for evil in ("../escape.txt", "proj/../../escape.txt", "/abs.txt", "\\abs.txt"):
            with self.assertRaises(RuntimeError, msg=evil):
                M._safe_extract(self._zip([("proj/ok.txt", "x"), (evil, "x")]), self.tmp / "out2")
        self.assertFalse((self.tmp / "escape.txt").exists())

    def test_too_many_entries_is_refused(self):
        with self.assertRaises(RuntimeError):
            M._safe_extract(self._zip([(f"p/f{i}", "") for i in range(20001)]), self.tmp / "out3")

    def test_zip_bomb_is_refused(self):
        big = bytes(1024 * 1024)
        with self.assertRaises(RuntimeError):
            M._safe_extract(self._zip([(f"p/f{i}", big) for i in range(401)]), self.tmp / "out4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
