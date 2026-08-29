# Threat Model

## 1. Purpose

LeakShield is a local, deterministic repository security auditor written in Python 3.14. It scans repository contents for leaked secrets, suspicious credential-like values, high-risk Python security patterns, and contextual security risks. It produces CLI, JSON, and HTML reports, but it does not execute repository code.

## 2. Security Objectives

- Detect likely leaked secrets and credential-like values in repository content.
- Detect selected dangerous Python patterns in source text.
- Preserve deterministic detection behavior and stable findings across equivalent runs.
- Minimize exposure of sensitive values in internal results and output.
- Use only repository-local analysis with no network access or external runtime dependencies.

## 3. Protected Assets

- Repository file contents under analysis.
- Secret-like values found in source files and text files.
- Detection metadata such as relative path, line, column, evidence, confidence, severity, and risk.
- The user’s local working tree and output artifacts.
- The integrity of the scan pipeline: discovery, filtering, analysis, normalization, deduplication, and reporting.

## 4. Trust Boundaries

- The repository contents are treated as untrusted input.
- The tool boundary is local to the host filesystem.
- Input is read from disk as plain text and parsed into AST or regex-based findings.
- Output is produced locally and is not sent to external services.
- The scanner does not trust repository content to be safe or non-malicious; it treats it as data to analyze, not code to execute.

### Trust Boundary Diagram

Developer
    │
    ▼
LeakShield CLI
    │
    ▼
Scanner Process
    │
    ├── Reads ──► Local Repository (UNTRUSTED)
    │
    └── Writes ─► JSON / HTML / CLI Reports (LOCAL OUTPUT)

- Repository contents are untrusted input.
- LeakShield never executes scanned repository code.
- No network communication occurs during scanning.

## 5. Threat Actors

- Malicious or careless repository contributors.
- Developers who accidentally commit secrets, tokens, or credential-like values.
- Attackers attempting to hide secrets in code, config, or text files.
- Operators or downstream consumers who rely on deterministic findings and safe output handling.

## 6. Attack Surfaces

- Repository files and directory trees.
- Source files containing secrets, credentials, or unsafe Python constructs.
- Text files and configuration-like content that may include secret values.
- Input paths and ignore patterns used during repository discovery.
- CLI-generated JSON or HTML reports containing findings metadata.

## 7. Security Assumptions

- LeakShield performs local, deterministic scanning.
- Repository contents are treated as untrusted input.
- LeakShield does not execute scanned code.
- LeakShield has no network access and no third-party runtime dependencies.
- The implementation uses only the approved standard-library modules and frozen architecture.
- The scanner is intended for static analysis and risk identification, not for full system compromise assessment.

## 8. Threat Analysis

- Secret leakage: credential-like values and hardcoded secrets may exist in text or source files.
- Unsafe Python patterns: dangerous calls such as eval, exec, subprocess usage, or shell=True may indicate risky behavior.
- False positives: pattern matches can identify suspicious values that are placeholders, examples, or non-secret metadata.
- False negatives: not all secret types or risky patterns are covered by the current static rules.
- Output exposure: report content must not expose raw secret values in unsafe output paths.
- Adversarial content: repository data may be intentionally crafted to trigger misleading matches or ambiguous signals.

## 9. Existing Mitigations

- Deterministic repository traversal and file filtering.
- Fixed detector execution order.
- Normalization and deduplication of findings.
- Structured evidence fields and location metadata.
- Redaction of secret values in internal redacted representations.
- No execution of scanned repository code.
- No network calls or external dependency usage.
- Strict module boundaries and zero external dependency policy.

## 10. Known Limitations

- This tool is not a malware detector.
- It does not perform Git history analysis.
- It does not perform remote vulnerability scanning.
- It does not verify JWT validity or trust token authenticity.
- It does not provide AI/ML-based secret detection.
- It relies on static pattern and AST-based heuristics; some risks may be missed or incorrectly classified.
- It does not inspect runtime behavior, deployed infrastructure, or external services.

## 11. Future Security Considerations

- Formalize the output contract and redaction flow for external reporting.
- Expand threat coverage only within the frozen architecture boundaries.
- Review false-positive and false-negative tradeoffs for secret and unsafe-pattern detection.
- Document any future output-safety guarantees for CLI, JSON, and HTML reports.
- Reassess security assumptions if the tool is extended beyond local repository scanning.

## Non-Goals

LeakShield does not aim to:

- detect malware
- analyze Git history
- perform remote vulnerability scanning
- verify JWT validity
- perform AI/ML secret detection
