import hashlib
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = REPO_ROOT / "dist"
ARTIFACT_NAME = "LeakShield.pyz"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


class ReproducibleBuildTests(unittest.TestCase):
    def setUp(self):
        if DIST_DIR.exists():
            shutil.rmtree(DIST_DIR)

    def tearDown(self):
        if DIST_DIR.exists():
            shutil.rmtree(DIST_DIR)

    def test_two_consecutive_builds_are_byte_identical(self):
        build_script = REPO_ROOT / "build.py"
        self.assertTrue(build_script.is_file(), msg="build.py not found")

        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        subprocess.run(
            [sys.executable, str(build_script)],
            cwd=str(REPO_ROOT),
            check=True,
            env=env,
        )
        first = DIST_DIR / ARTIFACT_NAME
        self.assertTrue(first.is_file(), msg="First artifact not created")
        first_hash = sha256_of(first)
        first_bytes = first.read_bytes()

        subprocess.run(
            [sys.executable, str(build_script)],
            cwd=str(REPO_ROOT),
            check=True,
            env=env,
        )
        second = DIST_DIR / ARTIFACT_NAME
        self.assertTrue(second.is_file(), msg="Second artifact not created")
        second_hash = sha256_of(second)
        second_bytes = second.read_bytes()

        self.assertEqual(first_bytes, second_bytes, msg="Artifacts differ byte-for-byte")
        self.assertEqual(first_hash, second_hash, msg="SHA-256 hashes differ")
        self.assertEqual(len(first_hash), 64, msg="SHA-256 hash length incorrect")


if __name__ == "__main__":
    unittest.main()
