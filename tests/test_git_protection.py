import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from leakshield import cli
from leakshield.git_protection import (
    LEAKSHIELD_HOOK_MARKER,
    get_git_root,
    get_staged_content,
    get_staged_files,
    generate_hook_script,
    install_hook,
    is_git_repository,
    is_leakshield_hook,
    scan_staged,
    uninstall_hook,
)


def _remove_readonly(func, path, exc_info):
    """Clear the readonly bit and reattempt removal on Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class GitProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.repo_path = Path(self.temp_dir)
        subprocess.run(["git", "init"], cwd=self.temp_dir, capture_output=True, check=True)
        # Configure local git user to allow commits if needed in tests
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.temp_dir, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.temp_dir, capture_output=True, check=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, onerror=_remove_readonly)

    def test_is_git_repository_true_for_git_repo(self):
        self.assertTrue(is_git_repository(self.repo_path))

    def test_is_git_repository_false_for_non_git_dir(self):
        non_git = tempfile.mkdtemp()
        try:
            self.assertFalse(is_git_repository(non_git))
        finally:
            shutil.rmtree(non_git, onerror=_remove_readonly)

    def test_get_git_root_returns_resolved_root(self):
        root = get_git_root(self.repo_path)
        self.assertEqual(root, self.repo_path.resolve())

    def test_install_hook_into_fresh_repo(self):
        success, message = install_hook(self.repo_path)
        self.assertTrue(success)
        self.assertIn("installed successfully", message)

        hook_file = self.repo_path / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook_file.exists())
        self.assertTrue(is_leakshield_hook(hook_file))
        content = hook_file.read_text(encoding="utf-8")
        self.assertIn(LEAKSHIELD_HOOK_MARKER, content)
        self.assertIn("leakshield pre-commit", content)

    def test_install_hook_reinstall_over_existing_leakshield_hook(self):
        install_hook(self.repo_path)
        success, message = install_hook(self.repo_path)
        self.assertTrue(success)
        self.assertIn("installed successfully", message)

    def test_install_hook_refuses_to_overwrite_unrelated_hook(self):
        hooks_dir = self.repo_path / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        unrelated_hook = hooks_dir / "pre-commit"
        unrelated_hook.write_text("#!/bin/sh\necho 'custom hook'\n", encoding="utf-8")

        success, message = install_hook(self.repo_path)
        self.assertFalse(success)
        self.assertIn("not managed by LeakShield", message)

        # Original hook must remain untouched
        content = unrelated_hook.read_text(encoding="utf-8")
        self.assertEqual(content, "#!/bin/sh\necho 'custom hook'\n")

    def test_install_hook_on_non_git_dir_fails(self):
        non_git = tempfile.mkdtemp()
        try:
            success, message = install_hook(non_git)
            self.assertFalse(success)
            self.assertIn("not a Git repository", message)
        finally:
            shutil.rmtree(non_git, onerror=_remove_readonly)

    def test_uninstall_hook_removes_leakshield_hook(self):
        install_hook(self.repo_path)
        hook_file = self.repo_path / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook_file.exists())

        success, message = uninstall_hook(self.repo_path)
        self.assertTrue(success)
        self.assertIn("uninstalled successfully", message)
        self.assertFalse(hook_file.exists())

    def test_uninstall_hook_refuses_to_remove_unrelated_hook(self):
        hooks_dir = self.repo_path / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        unrelated_hook = hooks_dir / "pre-commit"
        unrelated_hook.write_text("#!/bin/sh\necho 'custom hook'\n", encoding="utf-8")

        success, message = uninstall_hook(self.repo_path)
        self.assertFalse(success)
        self.assertIn("not installed or managed by LeakShield", message)
        self.assertTrue(unrelated_hook.exists())

    def test_uninstall_hook_when_no_hook_exists(self):
        success, message = uninstall_hook(self.repo_path)
        self.assertFalse(success)
        self.assertIn("No pre-commit hook found", message)

    def test_staged_content_vs_working_tree_staged_safe_working_tree_vulnerable(self):
        """Critical test: Working tree has sensitive code, but staged content is safe -> scan must pass."""
        test_file = self.repo_path / "config.py"
        test_file.write_text('greeting = "Hello, world!"\n', encoding="utf-8")
        subprocess.run(["git", "add", "config.py"], cwd=self.temp_dir, check=True)

        var_name = "".join(["pas", "sword"])
        test_file.write_text(f'{var_name} = "REAL_EXPOSED_SECRET_12345"\n', encoding="utf-8")

        findings = scan_staged(self.repo_path)
        self.assertEqual(len(findings), 0)

    def test_staged_content_vs_working_tree_staged_vulnerable_working_tree_safe(self):
        """Critical test: Working tree is clean, but staged content contains a secret -> scan must block."""
        test_file = self.repo_path / "config.py"
        var_name = "".join(["pas", "sword"])
        test_file.write_text(f'{var_name} = "REAL_EXPOSED_SECRET_12345"\n', encoding="utf-8")
        subprocess.run(["git", "add", "config.py"], cwd=self.temp_dir, check=True)

        test_file.write_text('greeting = "Hello, world!"\n', encoding="utf-8")

        findings = scan_staged(self.repo_path)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "credential-assignment")

    def test_unstaged_unrelated_vulnerable_files_ignored(self):
        """Unstaged files in working tree should not trigger pre-commit findings."""
        safe_file = self.repo_path / "safe.py"
        safe_file.write_text('x = 42\n', encoding="utf-8")
        subprocess.run(["git", "add", "safe.py"], cwd=self.temp_dir, check=True)

        bad_file = self.repo_path / "bad.py"
        var_name = "".join(["pas", "sword"])
        bad_file.write_text(f'{var_name} = "REAL_SECRET_12345"\n', encoding="utf-8")

        findings = scan_staged(self.repo_path)
        self.assertEqual(len(findings), 0)

    def test_deleted_files_handled_gracefully(self):
        """Deleted files staged in git should be skipped cleanly."""
        file_to_delete = self.repo_path / "old.py"
        file_to_delete.write_text('x = 1\n', encoding="utf-8")
        subprocess.run(["git", "add", "old.py"], cwd=self.temp_dir, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=self.temp_dir, capture_output=True, check=True)

        # Delete file and stage deletion
        file_to_delete.unlink()
        subprocess.run(["git", "add", "-u"], cwd=self.temp_dir, check=True)

        findings = scan_staged(self.repo_path)
        self.assertEqual(len(findings), 0)

    def test_binary_files_handled_gracefully(self):
        """Binary files staged in git should be skipped without crashing."""
        binary_file = self.repo_path / "image.png"
        binary_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00")
        subprocess.run(["git", "add", "image.png"], cwd=self.temp_dir, check=True)

        findings = scan_staged(self.repo_path)
        self.assertEqual(len(findings), 0)

    def test_ast_security_finding_in_staged_content_detected(self):
        """Dangerous AST patterns staged in git should be detected."""
        dangerous_file = self.repo_path / "eval_test.py"
        dangerous_file.write_text('print(eval("1 + 1"))\n', encoding="utf-8")
        subprocess.run(["git", "add", "eval_test.py"], cwd=self.temp_dir, check=True)

        findings = scan_staged(self.repo_path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "eval")

    def test_generated_hook_prefers_python_over_python3(self):
        """Generated hook script should prefer 'python' before 'python3' on Windows."""
        hook_content = generate_hook_script(str(self.repo_path))
        python_index = hook_content.find('PYTHON_EXEC="python"')
        python3_index = hook_content.find('PYTHON_EXEC="python3"')
        self.assertNotEqual(python_index, -1)
        self.assertNotEqual(python3_index, -1)
        self.assertLess(python_index, python3_index)


class CliGitProtectionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.repo_path = Path(self.temp_dir)
        subprocess.run(["git", "init"], cwd=self.temp_dir, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.temp_dir, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.temp_dir, capture_output=True, check=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, onerror=_remove_readonly)

    def test_cli_install_hook_command_success(self):
        original_argv = sys.argv[:]
        try:
            sys.argv = ["leakshield", "install-hook", str(self.repo_path)]
            exit_code = cli.main()
            self.assertEqual(exit_code, 0)
            hook_file = self.repo_path / ".git" / "hooks" / "pre-commit"
            self.assertTrue(hook_file.exists())
        finally:
            sys.argv = original_argv

    def test_cli_uninstall_hook_command_success(self):
        install_hook(self.repo_path)
        original_argv = sys.argv[:]
        try:
            sys.argv = ["leakshield", "uninstall-hook", str(self.repo_path)]
            exit_code = cli.main()
            self.assertEqual(exit_code, 0)
            hook_file = self.repo_path / ".git" / "hooks" / "pre-commit"
            self.assertFalse(hook_file.exists())
        finally:
            sys.argv = original_argv

    def test_cli_pre_commit_clean_staged_returns_zero(self):
        test_file = self.repo_path / "safe.py"
        test_file.write_text('value = "safe_placeholder"\n', encoding="utf-8")
        subprocess.run(["git", "add", "safe.py"], cwd=self.temp_dir, check=True)

        original_argv = sys.argv[:]
        try:
            sys.argv = ["leakshield", "pre-commit", str(self.repo_path)]
            exit_code = cli.main()
            self.assertEqual(exit_code, 0)
        finally:
            sys.argv = original_argv

    def test_cli_pre_commit_vulnerable_staged_returns_one(self):
        test_file = self.repo_path / "vuln.py"
        var_name = "".join(["pas", "sword"])
        test_file.write_text(f'{var_name} = "SUPER_SECRET_VALUE_12345"\n', encoding="utf-8")
        subprocess.run(["git", "add", "vuln.py"], cwd=self.temp_dir, check=True)

        original_argv = sys.argv[:]
        try:
            sys.argv = ["leakshield", "pre-commit", str(self.repo_path)]
            exit_code = cli.main()
            self.assertEqual(exit_code, 1)
        finally:
            sys.argv = original_argv

    def test_cli_pre_commit_on_non_git_target_returns_two(self):
        non_git = tempfile.mkdtemp()
        try:
            original_argv = sys.argv[:]
            try:
                sys.argv = ["leakshield", "pre-commit", non_git]
                exit_code = cli.main()
                self.assertEqual(exit_code, 2)
            finally:
                sys.argv = original_argv
        finally:
            shutil.rmtree(non_git, onerror=_remove_readonly)

    def test_cli_pre_commit_redaction_does_not_leak_raw_secret(self):
        test_file = self.repo_path / "secret.py"
        var_parts = ["pas", "sword"]
        var_name = "".join(var_parts)
        value_parts = ["MY_", "VERY_", "SENSITIVE_", "SECRET_", "XYZ_", "999"]
        value = "".join(value_parts)
        test_file.write_text(f'{var_name} = "{value}"\n', encoding="utf-8")
        subprocess.run(["git", "add", "secret.py"], cwd=self.temp_dir, check=True)

        import io
        captured_output = io.StringIO()
        original_argv = sys.argv[:]
        try:
            sys.argv = ["leakshield", "pre-commit", str(self.repo_path)]
            with patch("sys.stdout", captured_output):
                exit_code = cli.main()
            self.assertEqual(exit_code, 1)
            output = captured_output.getvalue()
            self.assertIn("Location:", output)
            self.assertIn("Hardcoded credential assignment", output)
            self.assertIn("Commit blocked.", output)
            self.assertNotIn("MY_VERY_SENSITIVE_SECRET_XYZ_999", output)
        finally:
            sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
