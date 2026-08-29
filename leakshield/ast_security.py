import ast

from leakshield.findings import RawFinding


_AST_CACHE = {}


def _parse_python_ast(source_text):
    """Parse Python source once per unique source text and reuse the resulting AST."""
    if not isinstance(source_text, str):
        return None

    if source_text in _AST_CACHE:
        return _AST_CACHE[source_text]

    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        _AST_CACHE[source_text] = None
        return None

    _AST_CACHE[source_text] = tree
    return tree


def _detect_eval_calls(source_text, file_info):
    """Return direct built-in eval() calls from Python source text."""
    tree = _parse_python_ast(source_text)
    if tree is None:
        return []

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "eval":
            continue

        line = node.lineno
        column = node.col_offset + 1
        findings.append(
            RawFinding(
                finding_type="eval",
                relative_path=file_info.relative_path,
                location=(line, column),
                candidate_value="eval",
                detector_id="ast-security",
                evidence={"pattern": "eval"},
            )
        )

    findings.sort(key=lambda item: (item.location[0], item.location[1]))
    return findings


def _detect_exec_calls(source_text, file_info):
    """Return direct built-in exec() calls from Python source text."""
    tree = _parse_python_ast(source_text)
    if tree is None:
        return []

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "exec":
            continue

        findings.append(
            RawFinding(
                finding_type="exec",
                relative_path=file_info.relative_path,
                location=(node.lineno, node.col_offset + 1),
                candidate_value="exec",
                detector_id="ast-security",
                evidence={"pattern": "exec"},
            )
        )

    findings.sort(key=lambda item: (item.location[0], item.location[1]))
    return findings


def _detect_subprocess_popen(source_text, file_info):
    """Return direct subprocess.Popen(...) calls from Python source text."""
    tree = _parse_python_ast(source_text)
    if tree is None:
        return []

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "subprocess":
            continue
        if node.func.attr != "Popen":
            continue

        is_shell_true = False
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is True:
                    is_shell_true = True
                    break

        if is_shell_true:
            continue

        findings.append(
            RawFinding(
                finding_type="subprocess",
                relative_path=file_info.relative_path,
                location=(node.lineno, node.col_offset + 1),
                candidate_value="subprocess.Popen",
                detector_id="ast-security",
                evidence={"pattern": "subprocess.Popen"},
            )
        )

    findings.sort(key=lambda item: (item.location[0], item.location[1]))
    return findings


def _detect_shell_true(source_text, file_info):
    """Return direct subprocess.Popen(..., shell=True) calls from Python source text."""
    tree = _parse_python_ast(source_text)
    if tree is None:
        return []

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "subprocess":
            continue
        if node.func.attr != "Popen":
            continue

        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                findings.append(
                    RawFinding(
                        finding_type="shell-true",
                        relative_path=file_info.relative_path,
                        location=(node.lineno, node.col_offset + 1),
                        candidate_value="shell=True",
                        detector_id="ast-security",
                        evidence={"pattern": "shell=True"},
                    )
                )
                break

    findings.sort(key=lambda item: (item.location[0], item.location[1]))
    return findings


def _detect_os_system(source_text, file_info):
    """Return direct os.system(...) calls from Python source text."""
    tree = _parse_python_ast(source_text)
    if tree is None:
        return []

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id != "os":
            continue
        if node.func.attr != "system":
            continue

        findings.append(
            RawFinding(
                finding_type="os-system",
                relative_path=file_info.relative_path,
                location=(node.lineno, node.col_offset + 1),
                candidate_value="os.system",
                detector_id="ast-security",
                evidence={"pattern": "os.system"},
            )
        )

    findings.sort(key=lambda item: (item.location[0], item.location[1]))
    return findings


_CREDENTIAL_NAMES = {
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
}


def _detect_credential_assignments(source_text, file_info):
    """Return hardcoded credential assignments with approved variable names."""
    tree = _parse_python_ast(source_text)
    if tree is None:
        return []

    findings = []

    def _record_assignment(node, variable_name):
        normalized = variable_name.lower()
        if normalized not in _CREDENTIAL_NAMES:
            return

        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            return

        if isinstance(node, ast.Assign):
            value = node.value
        else:
            value = node.value

        if value is None:
            return
        if not isinstance(value, ast.Constant):
            return
        if not isinstance(value.value, str):
            return
        if value.value == "":
            return

        findings.append(
            RawFinding(
                finding_type="credential-assignment",
                relative_path=file_info.relative_path,
                location=(node.lineno, node.col_offset + 1),
                candidate_value=variable_name,
                detector_id="ast-security",
                evidence={
                    "pattern": "credential-assignment",
                    "credential_name": variable_name,
                },
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    _record_assignment(node, target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                _record_assignment(node, node.target.id)

    findings.sort(key=lambda item: (item.location[0], item.location[1]))
    return findings
