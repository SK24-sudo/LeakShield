import unittest
from pathlib import Path

from leakshield.discovery import FileInfo
from leakshield.ast_security import (
    _detect_credential_assignments,
    _detect_eval_calls,
    _detect_exec_calls,
    _detect_os_system,
    _detect_shell_true,
    _detect_subprocess_popen,
)


def _file_info():
    path = Path("synthetic.py")
    return FileInfo(
        path=path,
        relative_path="synthetic.py",
        name=path.name,
        extension=path.suffix,
        size=1,
        classification="python",
    )


class EvalDetectorTests(unittest.TestCase):
    def test_direct_eval_call_is_detected(self):
        source = 'eval("x")\n'
        result = _detect_eval_calls(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].finding_type, "eval")
        self.assertEqual(result[0].detector_id, "ast-security")
        self.assertEqual(result[0].candidate_value, "eval")
        self.assertEqual(result[0].evidence, {"pattern": "eval"})

    def test_multiple_direct_eval_calls_are_detected_in_source_order(self):
        source = 'eval("a")\neval("b")\n'
        result = _detect_eval_calls(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.finding_type for item in result], ["eval", "eval"])
        self.assertEqual([item.location for item in result], [(1, 1), (2, 1)])

    def test_same_line_multiple_direct_eval_calls_are_detected_in_source_order(self):
        source = 'eval("a"); eval("b")\n'
        result = _detect_eval_calls(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.location for item in result], [(1, 1), (1, 12)])

    def test_similarly_named_function_is_not_detected(self):
        source = 'my_eval("x")\n'
        self.assertEqual(_detect_eval_calls(source, _file_info()), [])

    def test_attribute_call_is_not_detected(self):
        source = 'obj.eval("x")\n'
        self.assertEqual(_detect_eval_calls(source, _file_info()), [])

    def test_string_containing_eval_is_not_detected(self):
        source = "value = \"eval('x')\"\n"
        self.assertEqual(_detect_eval_calls(source, _file_info()), [])

    def test_comment_containing_eval_is_not_detected(self):
        source = '# eval("x")\n'
        self.assertEqual(_detect_eval_calls(source, _file_info()), [])

    def test_alias_usage_is_not_detected(self):
        source = 'e = eval\ne("x")\n'
        self.assertEqual(_detect_eval_calls(source, _file_info()), [])

    def test_location_matches_ast_call_position(self):
        source = 'x = 1\ny = 2\neval("x")\n'
        result = _detect_eval_calls(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, (3, 1))

    def test_empty_source_has_no_findings(self):
        self.assertEqual(_detect_eval_calls("", _file_info()), [])

    def test_malformed_python_returns_no_findings(self):
        source = 'eval(\n'
        self.assertEqual(_detect_eval_calls(source, _file_info()), [])


class ExecDetectorTests(unittest.TestCase):
    def test_direct_exec_call_is_detected(self):
        source = 'exec("x")\n'
        result = _detect_exec_calls(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].finding_type, "exec")
        self.assertEqual(result[0].detector_id, "ast-security")
        self.assertEqual(result[0].candidate_value, "exec")
        self.assertEqual(result[0].evidence, {"pattern": "exec"})

    def test_multiple_direct_exec_calls_are_detected_in_source_order(self):
        source = 'exec("a")\nexec("b")\n'
        result = _detect_exec_calls(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.finding_type for item in result], ["exec", "exec"])
        self.assertEqual([item.location for item in result], [(1, 1), (2, 1)])

    def test_same_line_multiple_direct_exec_calls_are_detected_in_source_order(self):
        source = 'exec("a"); exec("b")\n'
        result = _detect_exec_calls(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.location for item in result], [(1, 1), (1, 12)])

    def test_similarly_named_function_is_not_detected(self):
        source = 'my_exec("x")\n'
        self.assertEqual(_detect_exec_calls(source, _file_info()), [])

    def test_attribute_call_is_not_detected(self):
        source = 'obj.exec("x")\n'
        self.assertEqual(_detect_exec_calls(source, _file_info()), [])

    def test_string_containing_exec_is_not_detected(self):
        source = "value = \"exec('x')\"\n"
        self.assertEqual(_detect_exec_calls(source, _file_info()), [])

    def test_comment_containing_exec_is_not_detected(self):
        source = '# exec("x")\n'
        self.assertEqual(_detect_exec_calls(source, _file_info()), [])

    def test_alias_usage_is_not_detected(self):
        source = 'e = exec\ne("x")\n'
        self.assertEqual(_detect_exec_calls(source, _file_info()), [])

    def test_location_matches_ast_call_position(self):
        source = 'x = 1\ny = 2\nexec("x")\n'
        result = _detect_exec_calls(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, (3, 1))

    def test_empty_source_has_no_findings(self):
        self.assertEqual(_detect_exec_calls("", _file_info()), [])

    def test_malformed_python_returns_no_findings(self):
        source = 'exec(\n'
        self.assertEqual(_detect_exec_calls(source, _file_info()), [])


class SubprocessPopenDetectorTests(unittest.TestCase):
    def test_direct_subprocess_popen_call_is_detected(self):
        source = 'import subprocess\nsubprocess.Popen("x")\n'
        result = _detect_subprocess_popen(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].finding_type, "subprocess")
        self.assertEqual(result[0].detector_id, "ast-security")
        self.assertEqual(result[0].candidate_value, "subprocess.Popen")
        self.assertEqual(result[0].evidence, {"pattern": "subprocess.Popen"})

    def test_multiple_direct_subprocess_popen_calls_are_detected_in_source_order(self):
        source = 'import subprocess\nsubprocess.Popen("a")\nsubprocess.Popen("b")\n'
        result = _detect_subprocess_popen(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.finding_type for item in result], ["subprocess", "subprocess"])
        self.assertEqual([item.location for item in result], [(2, 1), (3, 1)])

    def test_same_line_multiple_direct_calls_are_detected_in_source_order(self):
        source = 'import subprocess\nsubprocess.Popen("a"); subprocess.Popen("b")\n'
        result = _detect_subprocess_popen(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.location for item in result], [(2, 1), (2, 24)])

    def test_subprocess_alias_call_is_not_detected(self):
        source = 'import subprocess\nsp = subprocess\nsp.Popen("x")\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_imported_popen_is_not_detected(self):
        source = 'from subprocess import Popen\nPopen("x")\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_object_attribute_call_is_not_detected(self):
        source = 'import subprocess\nobj = type("X", (), {})()\nobj.Popen("x")\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_run_call_is_not_detected(self):
        source = 'import subprocess\nsubprocess.run("x")\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_call_function_is_not_detected(self):
        source = 'import subprocess\nsubprocess.call("x")\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_check_call_is_not_detected(self):
        source = 'import subprocess\nsubprocess.check_call("x")\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_check_output_is_not_detected(self):
        source = 'import subprocess\nsubprocess.check_output("x")\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_string_containing_subprocess_popen_is_not_detected(self):
        source = 'value = "subprocess.Popen(\'x\')"\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_comment_containing_subprocess_popen_is_not_detected(self):
        source = '# subprocess.Popen("x")\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])

    def test_location_matches_ast_call_position(self):
        source = 'x = 1\ny = 2\nimport subprocess\nsubprocess.Popen("x")\n'
        result = _detect_subprocess_popen(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, (4, 1))

    def test_empty_source_has_no_findings(self):
        self.assertEqual(_detect_subprocess_popen("", _file_info()), [])

    def test_malformed_python_returns_no_findings(self):
        source = 'subprocess.Popen(\n'
        self.assertEqual(_detect_subprocess_popen(source, _file_info()), [])


class ShellTrueDetectorTests(unittest.TestCase):
    def test_direct_shell_true_call_is_detected(self):
        source = 'import subprocess\nsubprocess.Popen("x", shell=True)\n'
        result = _detect_shell_true(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].finding_type, "shell-true")
        self.assertEqual(result[0].detector_id, "ast-security")
        self.assertEqual(result[0].candidate_value, "shell=True")
        self.assertEqual(result[0].evidence, {"pattern": "shell=True"})

    def test_multiple_shell_true_calls_are_detected_in_source_order(self):
        source = 'import subprocess\nsubprocess.Popen("a", shell=True)\nsubprocess.Popen("b", shell=True)\n'
        result = _detect_shell_true(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.finding_type for item in result], ["shell-true", "shell-true"])
        self.assertEqual([item.location for item in result], [(2, 1), (3, 1)])

    def test_same_line_multiple_shell_true_calls_are_detected_in_source_order(self):
        source = 'import subprocess\nsubprocess.Popen("a", shell=True); subprocess.Popen("b", shell=True)\n'
        result = _detect_shell_true(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.location for item in result], [(2, 1), (2, 36)])

    def test_keyword_order_is_not_restricted(self):
        source = 'import subprocess\nsubprocess.Popen("x", cwd="/tmp", shell=True)\n'
        result = _detect_shell_true(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, (2, 1))

    def test_shell_false_is_not_detected(self):
        source = 'import subprocess\nsubprocess.Popen("x", shell=False)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_shell_one_is_not_detected(self):
        source = 'import subprocess\nsubprocess.Popen("x", shell=1)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_shell_string_true_is_not_detected(self):
        source = 'import subprocess\nsubprocess.Popen("x", shell="True")\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_shell_variable_is_not_detected(self):
        source = 'import subprocess\nflag = True\nsubprocess.Popen("x", shell=flag)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_shell_function_call_is_not_detected(self):
        source = 'import subprocess\nsubprocess.Popen("x", shell=get_value())\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_subprocess_alias_call_is_not_detected(self):
        source = 'import subprocess\nsp = subprocess\nsp.Popen("x", shell=True)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_imported_popen_is_not_detected(self):
        source = 'from subprocess import Popen\nPopen("x", shell=True)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_object_attribute_call_is_not_detected(self):
        source = 'import subprocess\nobj = type("X", (), {})()\nobj.Popen("x", shell=True)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_run_call_is_not_detected(self):
        source = 'import subprocess\nsubprocess.run("x", shell=True)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_call_function_is_not_detected(self):
        source = 'import subprocess\nsubprocess.call("x", shell=True)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_check_call_is_not_detected(self):
        source = 'import subprocess\nsubprocess.check_call("x", shell=True)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_check_output_is_not_detected(self):
        source = 'import subprocess\nsubprocess.check_output("x", shell=True)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_string_containing_shell_true_is_not_detected(self):
        source = 'value = "subprocess.Popen(\'x\', shell=True)"\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_comment_containing_shell_true_is_not_detected(self):
        source = '# subprocess.Popen("x", shell=True)\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])

    def test_overlap_policy_prefers_shell_true_over_subprocess(self):
        source = 'import subprocess\nsubprocess.Popen("x", shell=True)\n'
        subprocess_findings = _detect_subprocess_popen(source, _file_info())
        shell_findings = _detect_shell_true(source, _file_info())

        self.assertEqual(subprocess_findings, [])
        self.assertEqual(len(shell_findings), 1)
        self.assertEqual(shell_findings[0].finding_type, "shell-true")

    def test_location_matches_ast_call_position(self):
        source = 'x = 1\ny = 2\nimport subprocess\nsubprocess.Popen("x", shell=True)\n'
        result = _detect_shell_true(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, (4, 1))

    def test_empty_source_has_no_findings(self):
        self.assertEqual(_detect_shell_true("", _file_info()), [])

    def test_malformed_python_returns_no_findings(self):
        source = 'subprocess.Popen("x", shell=True\n'
        self.assertEqual(_detect_shell_true(source, _file_info()), [])


class OsSystemDetectorTests(unittest.TestCase):
    def test_direct_os_system_call_is_detected(self):
        source = 'import os\nos.system("x")\n'
        result = _detect_os_system(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].finding_type, "os-system")
        self.assertEqual(result[0].detector_id, "ast-security")
        self.assertEqual(result[0].candidate_value, "os.system")
        self.assertEqual(result[0].evidence, {"pattern": "os.system"})

    def test_multiple_direct_os_system_calls_are_detected_in_source_order(self):
        source = 'import os\nos.system("a")\nos.system("b")\n'
        result = _detect_os_system(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.finding_type for item in result], ["os-system", "os-system"])
        self.assertEqual([item.location for item in result], [(2, 1), (3, 1)])

    def test_same_line_multiple_os_system_calls_are_detected_in_source_order(self):
        source = 'import os\nos.system("a"); os.system("b")\n'
        result = _detect_os_system(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.location for item in result], [(2, 1), (2, 17)])

    def test_multi_line_location_is_correct(self):
        source = 'x = 1\ny = 2\nimport os\nos.system("x")\n'
        result = _detect_os_system(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, (4, 1))

    def test_similarly_named_function_is_not_detected(self):
        source = 'import os\nmy_system("x")\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])

    def test_direct_system_function_is_not_detected(self):
        source = 'system("x")\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])

    def test_imported_system_is_not_detected(self):
        source = 'from os import system\nsystem("x")\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])

    def test_arbitrary_object_system_is_not_detected(self):
        source = 'import os\nobj = type("X", (), {})()\nobj.system("x")\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])

    def test_os_popen_is_not_detected(self):
        source = 'import os\nos.popen("x")\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])

    def test_os_spawn_is_not_detected(self):
        source = 'import os\nos.spawn("x")\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])

    def test_string_containing_os_system_is_not_detected(self):
        source = 'value = "os.system(\'x\')"\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])

    def test_comment_containing_os_system_is_not_detected(self):
        source = '# os.system("x")\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])

    def test_empty_source_has_no_findings(self):
        self.assertEqual(_detect_os_system("", _file_info()), [])

    def test_malformed_python_returns_no_findings(self):
        source = 'os.system(\n'
        self.assertEqual(_detect_os_system(source, _file_info()), [])


class CredentialAssignmentDetectorTests(unittest.TestCase):
    def test_password_assignment_is_detected(self):
        source = 'password = "abc123"\n'
        result = _detect_credential_assignments(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].finding_type, "credential-assignment")
        self.assertEqual(result[0].detector_id, "ast-security")
        self.assertEqual(result[0].candidate_value, "password")
        self.assertEqual(result[0].evidence, {"pattern": "credential-assignment", "credential_name": "password"})

    def test_each_allowed_name_is_detected(self):
        allowed = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "private_key",
        ]

        for name in allowed:
            source = f'{name} = "value"\n'
            result = _detect_credential_assignments(source, _file_info())
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].candidate_value, name)
            self.assertEqual(result[0].evidence["credential_name"], name)

    def test_case_insensitive_name_is_detected(self):
        source = 'PASSWORD = "abc"\nApi_Key = "def"\n'
        result = _detect_credential_assignments(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.candidate_value for item in result], ["PASSWORD", "Api_Key"])

    def test_annotated_assignment_is_detected(self):
        source = 'password: str = "abc"\n'
        result = _detect_credential_assignments(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].candidate_value, "password")

    def test_multiple_targets_in_one_assignment_are_detected(self):
        source = 'password = api_key = "secret"\n'
        result = _detect_credential_assignments(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.candidate_value for item in result], ["password", "api_key"])
        self.assertEqual([item.location for item in result], [(1, 1), (1, 1)])

    def test_multiple_assignments_are_detected_in_source_order(self):
        source = 'password = "a"\napi_key = "b"\n'
        result = _detect_credential_assignments(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.location for item in result], [(1, 1), (2, 1)])

    def test_same_line_multiple_assignments_are_detected_with_correct_locations(self):
        source = 'password = "a"; token = "b"\n'
        result = _detect_credential_assignments(source, _file_info())

        self.assertEqual(len(result), 2)
        self.assertEqual([item.location for item in result], [(1, 1), (1, 17)])

    def test_empty_string_is_not_detected(self):
        source = 'password = ""\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_non_credential_variable_is_not_detected(self):
        source = 'user = "abc"\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_substring_variable_names_are_not_detected(self):
        source = 'my_password = "abc"\npassword_hint = "def"\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_variable_reference_value_is_not_detected(self):
        source = 'password = other_value\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_function_call_value_is_not_detected(self):
        source = 'password = get_password()\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_numeric_value_is_not_detected(self):
        source = 'password = 12345\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_boolean_value_is_not_detected(self):
        source = 'password = True\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_none_value_is_not_detected(self):
        source = 'password = None\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_attribute_assignment_is_not_detected(self):
        source = 'obj.password = "abc"\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_subscript_assignment_is_not_detected(self):
        source = 'config["password"] = "abc"\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_string_containing_assignment_is_not_detected(self):
        source = 'value = "password = \"abc\""\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_comment_containing_assignment_is_not_detected(self):
        source = '# password = "abc"\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])

    def test_secret_value_is_not_exposed_in_candidate_or_evidence(self):
        source = 'password = "SUPER_SECRET_VALUE"\n'
        result = _detect_credential_assignments(source, _file_info())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].candidate_value, "password")
        self.assertEqual(result[0].evidence["credential_name"], "password")
        self.assertNotIn("SUPER_SECRET_VALUE", result[0].candidate_value)
        self.assertNotIn("SUPER_SECRET_VALUE", str(result[0].evidence))

    def test_empty_source_has_no_findings(self):
        self.assertEqual(_detect_credential_assignments("", _file_info()), [])

    def test_malformed_python_returns_no_findings(self):
        source = 'password = "abc\n'
        self.assertEqual(_detect_credential_assignments(source, _file_info()), [])


if __name__ == "__main__":
    unittest.main()
