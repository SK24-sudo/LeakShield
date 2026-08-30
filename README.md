# LeakShield

LeakShield is a local, deterministic repository security auditor written in Python.

It scans repository contents for likely leaked secrets, credential-like values, and selected high-risk Python security patterns.

LeakShield treats repository content as **untrusted data** and analyzes it without executing repository code.

## Features

* Detects supported secret and credential patterns, with entropy used as contextual evidence for applicable findings.
* Detects selected dangerous Python constructs using AST analysis.
* Provides deterministic repository traversal and finding ordering.
* Applies finding normalization, confidence, severity, risk, and exact deduplication.
* Supports CLI, JSON, and HTML reporting.
* Uses Python standard-library functionality only.
* Requires no third-party runtime dependencies.
* Performs scanning locally without network communication.
* Never executes scanned repository code.

## Requirements

* Python 3.14
* A local repository or directory to scan

No external Python packages are required.

## Usage

Run LeakShield against a target directory:

```powershell
python -m leakshield <target>
```

For example:

```powershell
python -m leakshield examples\vulnerable_repo
```

The default output format is the CLI summary.

### Output Formats

LeakShield supports three output formats:

```powershell
python -m leakshield <target> --format cli
python -m leakshield <target> --format json
python -m leakshield <target> --format html
```

The available formats are:

| Format | Description                  |
| ------ | ---------------------------- |
| `cli`  | Concise command-line summary |
| `json` | Structured JSON findings     |
| `html` | HTML report                  |

Example CLI output:

```text
LeakShield scan
Target: examples\vulnerable_repo

10 potential security findings found.

Location: dangerous_code.py:8:5
What: Direct eval() call
Why: A direct eval() call was detected by AST analysis.
Action: Avoid eval() with untrusted input; consider safer alternatives.
```

The bundled `examples\vulnerable_repo` target contains intentionally fake
demonstration data and produces output similar to the example above. The
displayed findings depend on the contents of the scanned target.

### Clean Demo

To see a scan with no findings, run LeakShield against the bundled clean fixture:

```powershell
python -m leakshield examples\clean_repo
```

Expected output:

```text
LeakShield scan
Target: examples\clean_repo

No supported security patterns detected.

LeakShield did not find any supported patterns in the files it analyzed.
A clean scan is not a guarantee that the repository contains no secrets.
```

The `examples\clean_repo` fixture contains safe code with no hardcoded
credentials and no dangerous patterns.

## What LeakShield Detects

### Secret and Credential Findings

The current secret-detection implementation includes supported categories such as:

* Credential-like assignments
* Provider-specific tokens
* JWT-like structured tokens
* PEM private keys
* Entropy-based contextual evidence for applicable findings

The detector uses structural and contextual evidence rather than treating every long or random-looking string as a secret.

Supported provider-token patterns currently include GitHub personal access tokens, GitHub fine-grained personal access tokens, GitLab personal access tokens, and Slack tokens.

JWT detection is structural: LeakShield identifies candidates whose segments can be decoded and whose header and payload can be parsed as JSON objects. It does **not** verify JWT authenticity or trust.

### Python Security Findings

LeakShield also detects selected Python constructs associated with security risk, including:

* `eval(...)`
* `exec(...)`
* `subprocess.Popen(...)`
* `subprocess.Popen(..., shell=True)`
* `os.system(...)`
* Credential-like variable assignments

Detection uses Python AST structure where applicable rather than relying only on substring matching.

The detector set is intentionally limited to the implemented rules. LeakShield does not attempt to detect every dangerous Python construct.

## Interpreting Finding Metadata

LeakShield reports confidence, severity, and risk as distinct fields:

* **Confidence** describes how likely the finding is correctly identified. High confidence means the scanner has strong supporting evidence that the material matches the detected condition.
* **Severity** describes how dangerous the condition would be if it is genuinely sensitive or valid. High severity does not establish that a detected credential is active.
* **Risk** is the scanner's final prioritization derived from confidence and severity. High risk must not be interpreted as proof that a credential is live, active, or exploitable.

LeakShield performs static analysis only, so detected material alone cannot establish credential liveness. Test fixtures, examples, and other sample material can therefore still legitimately be detected.

## Scan Pipeline

A scan follows a deterministic processing flow:

```text
Target
  |
  v
Repository discovery
  |
  v
Ignore filtering
  |
  v
File reading
  |
  v
Secret detection + AST security detection
  |
  v
Finding normalization
  |
  v
Confidence / severity / risk
  |
  v
Exact deduplication
  |
  v
Redaction
  |
  v
Reporting
```

Detector execution order and finding ordering are intentionally deterministic.

## Security Model

LeakShield treats repository contents as untrusted input.

The scanner:

* Reads repository files as data.
* Parses Python source statically when AST analysis is required.
* Does not execute repository code.
* Does not make network requests.
* Does not invoke subprocesses while scanning.
* Does not require third-party runtime dependencies.
* Produces CLI, JSON, and HTML output locally.

LeakShield is intended for local static analysis and risk identification. Scanned repository contents are treated as data to analyze, not code to execute.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the project's documented security objectives, protected assets, trust boundaries, threat actors, attack surfaces, mitigations, assumptions, and limitations.

## Secret Handling

LeakShield includes an internal `Finding.redacted_copy()` mechanism for producing a redacted representation of a finding.

The redacted representation:

* Replaces the candidate value with `[REDACTED]`.
* Removes the raw finding reference.
* Redacts evidence values that exactly match the candidate value.
* Preserves non-secret finding metadata.
* Preserves confidence, severity, and risk.
* Does not mutate the original internal finding.
* Is deterministic and idempotent.

For normal CLI JSON and HTML output, `cli.main()` creates redacted `Finding` copies after scanning and deduplication and before reporter dispatch. Raw candidate material remains internal to the `Finding` model and is not passed to the normal CLI JSON or HTML reporting path.

## Determinism

Deterministic behavior is a core project requirement.

Equivalent scans are designed to produce stable:

* File traversal order
* Detector execution order
* Finding ordering
* Finding metadata
* Deduplication results
* Output representations

Exact duplicate findings are removed while preserving the first occurrence and original ordering.

The test suite includes regression coverage for deterministic scanning.

## Zero Dependencies

LeakShield is intentionally designed without third-party runtime dependencies.

The implementation uses Python standard-library modules only. The repository does not require a package installation step or a third-party dependency file to run the scanner.

## Project Structure

```text
LeakShield/
├── leakshield/
│   ├── ast_security.py
│   ├── cli.py
│   ├── config.py
│   ├── discovery.py
│   ├── findings.py
│   ├── reporting.py
│   ├── scanner.py
│   ├── secrets.py
│   ├── __init__.py
│   └── __main__.py
├── tests/
├── examples/
│   └── vulnerable_repo/
├── PROJECT_STATE.md
├── STDLIB.md
├── THREAT_MODEL.md
├── deps-proof.txt
├── .zero-dep.toml
└── README.md
```

## Testing

Run the complete test suite with:

```powershell
python -m unittest discover -s tests -v
```

The regression suite covers:

* Secret detection
* JWT structural detection
* Private-key detection
* AST security detection
* Repository discovery and ignore filtering
* Finding normalization
* Confidence, severity, and risk
* Deduplication
* Redaction
* CLI behavior
* JSON reporting
* HTML reporting
* Deterministic scanning

The full regression suite passes with **236 tests**.

## Limitations

LeakShield is a static repository security auditor, not a complete security assessment platform.

It does **not** currently:

* Detect malware comprehensively.
* Analyze Git history.
* Perform remote vulnerability scanning.
* Verify JWT authenticity or trust.
* Provide AI/ML-based secret detection.
* Analyze runtime behavior.
* Analyze deployed infrastructure.
* Assess external services.

Static detection can produce both false positives and false negatives. The detector set is intentionally limited to the project's implemented secret and AST security rules.

Normal CLI JSON and HTML reporting receives redacted `Finding` copies. This CLI boundary does not imply that direct calls to a reporting formatter redact their input.

## Non-Goals

LeakShield does not aim to:

* Detect malware.
* Analyze Git history.
* Perform remote vulnerability scanning.
* Verify JWT validity or token authenticity.
* Perform AI/ML-based secret detection.
* Execute repository code.
* Provide a complete vulnerability assessment of a system or application.

## Project Status

Phases 1 through 6D are complete and frozen.

Phase 7A is complete.

Phase 7B is complete.

Phase 7C demo verification is complete. The CLI, JSON, and HTML paths have
been verified successfully, and the full regression suite passes with
**236/236 tests**.

See [`PROJECT_STATE.md`](PROJECT_STATE.md) for the authoritative repository state and phase history.

## License

No license is currently specified in the repository.
