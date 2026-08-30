import os
import tempfile
import unittest
from pathlib import Path

from leakshield.discovery import (
	DEFAULT_IGNORE_PATTERNS,
	FileInfo,
	_normalize_ignore_path,
	discover,
	filter_files,
	is_ignored,
)


def _file_info(relative_path):
	path = Path(relative_path)
	return FileInfo(
		path=path,
		relative_path=relative_path,
		name=path.name,
		extension=path.suffix.lower(),
		size=1,
		classification="python" if path.suffix == ".py" else "text",
	)


class IgnoreEngineTests(unittest.TestCase):
	def test_normal_file_is_included(self):
		file_info = _file_info("src/app.py")

		self.assertFalse(is_ignored(file_info))

	def test_default_patterns_ignore_files(self):
		ignored_paths = (
			".git/config",
			"cache/__pycache__/module.py",
			"module.pyc",
			".venv/bin/python",
			"node_modules/package/index.js",
			".vscode/settings.json",
		)

		for relative_path in ignored_paths:
			with self.subTest(relative_path=relative_path):
				self.assertTrue(is_ignored(_file_info(relative_path)))

		self.assertIn(".git/**", DEFAULT_IGNORE_PATTERNS)

	def test_custom_patterns_ignore_nested_paths(self):
		file_info = _file_info("docs/internal/notes.secret")

		self.assertTrue(is_ignored(file_info, ("docs/**/*.secret",)))
		self.assertFalse(is_ignored(_file_info("docs/public/notes.txt"), ("docs/**/*.secret",)))

	def test_path_normalization(self):
		self.assertEqual(
			_normalize_ignore_path(r".\docs\internal\notes.txt"),
			"docs/internal/notes.txt",
		)
		self.assertFalse(is_ignored(_file_info(r".\src\app.py")))

	def test_matching_is_case_sensitive(self):
		self.assertTrue(is_ignored(_file_info(".git/config")))
		self.assertFalse(is_ignored(_file_info(".GIT/config")))

	def test_multiple_matching_patterns_still_ignore(self):
		file_info = _file_info("cache/data.tmp")

		self.assertTrue(is_ignored(file_info, ("cache/*.tmp", "**/*.tmp")))

	def test_filter_preserves_order_and_objects(self):
		files = [
			_file_info("zeta.py"),
			_file_info("node_modules/package.js"),
			_file_info("alpha.py"),
		]

		filtered = filter_files(files)

		self.assertEqual([file.relative_path for file in filtered], ["zeta.py", "alpha.py"])
		self.assertIs(filtered[0], files[0])
		self.assertIs(filtered[1], files[2])

	def test_negation_is_not_supported(self):
		self.assertFalse(is_ignored(_file_info("keep.py"), ("!keep.py",)))
		self.assertTrue(is_ignored(_file_info("keep.py"), ("*.py", "!keep.py")))

	def test_dist_directory_is_ignored(self):
		ignored_paths = (
			"dist/LeakShield.pyz",
			"dist/bundle/app.js",
			"build/output.css",
			"build/lib/module.js",
		)

		for relative_path in ignored_paths:
			with self.subTest(relative_path=relative_path):
				self.assertTrue(is_ignored(_file_info(relative_path)))

		self.assertIn("dist/", DEFAULT_IGNORE_PATTERNS)
		self.assertIn("build/", DEFAULT_IGNORE_PATTERNS)

	def test_discover_skips_ignored_directories(self):
		with tempfile.TemporaryDirectory() as tmp:
			root = Path(tmp)
			(root / "src").mkdir()
			(root / "src" / "app.py").write_text('password = "secret123"\n', encoding="utf-8")
			(root / "dist").mkdir()
			(root / "dist" / "bundle.js").write_text('password = "secret456"\n', encoding="utf-8")
			(root / "build").mkdir()
			(root / "build" / "output.css").write_text("body { color: red; }\n", encoding="utf-8")
			(root / ".git").mkdir()
			(root / ".git" / "config").write_text("[core]\n", encoding="utf-8")
			(root / "node_modules").mkdir()
			(root / "node_modules" / "index.js").write_text('password = "secret789"\n', encoding="utf-8")

			files = discover(root)
			relative_paths = [file_info.relative_path for file_info in files]

			self.assertIn("src/app.py", relative_paths)
			self.assertNotIn("dist/bundle.js", relative_paths)
			self.assertNotIn("build/output.css", relative_paths)
			self.assertNotIn(".git/config", relative_paths)
			self.assertNotIn("node_modules/index.js", relative_paths)


if __name__ == "__main__":
	unittest.main()
