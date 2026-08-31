# LeakShield — Zero-Dependency Engineering Evidence

LeakShield is intentionally implemented as a **zero-third-party-Python-dependency security auditor**.

The production scanner does not require third-party Python packages. Its core functionality is built using Python's standard library and repository-local modules.

This document explains **how** that was achieved, what functionality would commonly be provided by external packages, and the engineering trade-offs of the approach.

For a deeper capability-by-capability comparison, see `PACKAGE_KILLER.md`.

---

## Package Killer at a Glance

| Item | Detail |
|------|--------|
| Candidate | `detect-secrets` |
| Why | Same broad repository secret-scanning problem space |
| LeakShield contribution | Focused secret-detection capabilities implemented using Python standard library + repository-local logic |
| Evidence | Pattern detection, entropy signals, credential/keyword-oriented detection, structured decoding, repository scanning |
| Qualification | Meaningful subset / capability-level reimplementation |
| Not claimed | Feature parity, drop-in replacement, replacement of the complete detect-secrets ecosystem |

---

## 1. Zero-Dependency Philosophy

LeakShield has **zero third-party Python runtime dependencies**.

The repository-local modules under `leakshield/` import only:

1. Python standard-library modules
2. Other `leakshield.*` modules

Repository-local modules are part of LeakShield itself and are not external dependencies.

### What zero dependency means here

"Zero dependency" refers specifically to **third-party Python runtime dependencies**.

It does **not** mean:

* no Python requirement
* no operating-system/tooling requirements
* no external executable requirements
* feature parity with every security framework

Zero dependency is an engineering constraint and deployment choice, not a guarantee of security by itself.

### Conceptual model

```text
ZERO-RUNTIME-DEPENDENCY MODEL

Python runtime
      ↓
Python standard library
      ↓
LeakShield local modules
      ↓
Security scanning
```

Contrast this with a conventional package-based approach:

```text
CONVENTIONAL PACKAGE-BASED MODEL

Python runtime
      ↓
Third-party package installation
      ↓
External Python runtime dependencies
      ↓
Application
```

LeakShield deliberately avoids the second model. A fresh Python environment does not need a dependency installation step before the scanner can run from the project directory.

### Why this matters

| Concern | stdlib approach |
|---------|-----------------|
| Reproducibility | No dependency resolution or lockfile drift |
| Supply-chain exposure | Fewer third-party components to trust and maintain |
| Auditing | Implementation is directly inspectable through Python source |
| Deployment | Simple project-directory usage without package management |
| Privacy | No network access required for normal operation |

The trade-off is that LeakShield owns more of its implementation instead of delegating functionality to external libraries.

---

## 2. Runtime Dependency Audit

The production import surface was inspected across the `leakshield/` package.

### Conclusion

```text
Third-party Python runtime dependencies: NONE
```

This conclusion comes from inspection of the actual production import surface, not merely from the absence of `requirements.txt`.

### Runtime dependencies

| Dependency | Role |
|------------|------|
| Python | Required runtime |
| Python standard library | Core implementation |
| Git executable | Required only for Git-specific functionality |

Git is an external executable requirement for Git-specific protection features. Git is not a Python dependency. Git integration is implemented through Python's standard-library `subprocess` module invoking the local Git CLI.

### Repository-local imports

All `leakshield.*` imports are repository-local modules that are part of LeakShield itself. They are not third-party dependencies.

### Absent dependency manifests

The repository does not contain:

* `requirements.txt`
* `requirements-dev.txt`
* `pyproject.toml`
* `setup.py`
* `setup.cfg`
* `Pipfile`
* `Pipfile.lock`
* `poetry.lock`
* `uv.lock`

---

## 3. LeakShield Architecture

```text
                 Repository / Target
                         │
                         ▼
              Configuration / Discovery
                         │
                         ▼
                   File Filtering
                         │
                         ▼
                      Scanner
                    /         \
                   /           \
                  ▼             ▼
        Secret detectors   AST detectors
                  \             /
                   \           /
                    ▼         ▼
                     RawFinding
                         │
                         ▼
                 Finding normalization
                         │
                         ▼
              Per-file exact deduplication
                         │
                         ▼
            Repository-wide exact deduplication
                         │
                         ▼
               Cross-location consolidation
                         │
                         ▼
                     Reporting
                 /        |        \
                ▼         ▼         ▼
               CLI       JSON      HTML


       Git protection operates around the scanner
       for Git/pre-commit workflows.
```

### Stage descriptions

**Configuration / Discovery**
Resolves the scan target, validates the configuration, and discovers filesystem files.

**File Filtering**
Applies default and custom ignore patterns to exclude repository-noise directories and user-specified paths.

**Scanner**
Iterates discovered files and invokes detector pipelines.

**Secret detectors**
Pattern-based detection using `re`, structured decoding with `base64`/`json`, and entropy analysis with `math`.

**AST detectors**
Structural Python source analysis using the `ast` module.

**RawFinding**
The raw detector-level finding model emitted by individual detectors.

**Finding normalization**
Converts `RawFinding` objects into normalized `Finding` objects with confidence, severity, and risk metadata.

**Per-file exact deduplication**
Removes exact duplicate findings within a single file based on the project's exact-identity contract.

**Repository-wide exact deduplication**
Removes exact duplicate findings across the entire scan result.

**Cross-location consolidation**
Groups equivalent findings that occur at multiple locations into a single logical finding with multiple locations.

**Reporting**
Formats findings into CLI output, JSON payloads, or self-contained HTML reports.

**Git protection**
An integration boundary around scanning workflows that invokes the local Git CLI for pre-commit checks and staged-content inspection.

---

## 4. Production Standard Library Modules

The following table lists verified standard-library imports used by production code:

| Capability                   | Stdlib module | Actual use                                     | Why sufficient                                   | Trade-off                                     |
| ---------------------------- | ------------- | ---------------------------------------------- | ------------------------------------------------ | --------------------------------------------- |
| CLI parsing                  | `argparse`    | command-line options, validation, help         | fits project CLI requirements                    | less framework abstraction                    |
| CLI/system interaction       | `sys`         | process/CLI behavior actually used by `cli.py` | direct stdlib access is sufficient               | lower-level API                               |
| AST security analysis        | `ast`         | structural Python source analysis              | direct syntax-tree access supports defined rules | LeakShield owns rule logic                    |
| Filesystem paths             | `pathlib`     | repository paths and traversal                 | sufficient for local repository scanning         | less specialized abstraction                  |
| Ignore matching              | `fnmatch`     | ignore-pattern matching                        | sufficient for defined patterns                  | not identical to every `.gitignore` edge case |
| Git integration              | `subprocess`  | controlled invocation of local Git CLI         | focused Git operations do not require GitPython  | requires Git executable                       |
| Secret pattern detection     | `re`          | regex-based detection                          | sufficient for defined patterns                  | heuristic/scope limitations                   |
| Structured decoding          | `base64`      | Base64/Base64URL-related decoding              | stdlib supports implemented formats              | limited to implemented formats                |
| Structured parsing/reporting | `json`        | structured secret parsing and JSON reports     | native JSON support is sufficient                | no specialized framework                      |
| Entropy analysis             | `math`        | Shannon entropy calculation                    | basic mathematical operations suffice            | entropy remains heuristic                     |
| HTML reporting               | `html.escape` | HTML escaping                                  | sufficient for controlled report output          | no template-engine abstraction                |

These imports were verified across the `leakshield/` production package.

No third-party Python imports were identified in production code.

---

## 5. How Each Stdlib Capability Is Used

### CLI

`argparse` provides command-line parsing, option validation, help generation, and structured CLI ergonomics.

LeakShield's CLI requirements fit within `argparse`'s standard-library functionality. The trade-off is that frameworks like Click or Typer can provide richer CLI abstractions, but `argparse` avoids a runtime dependency.

### Static security analysis

`ast` provides direct access to Python's syntax tree. LeakShield uses it to inspect source code structurally rather than executing scanned repository code.

Implemented AST-level rules detect security-sensitive constructs including:

* `eval()`
* `exec()`
* dangerous subprocess usage
* `os.system()` usage
* suspicious credential-related assignments

Specialized analysis frameworks can provide more abstractions and broader functionality. LeakShield keeps the analysis path small and directly inspectable.

### Secret detection

LeakShield combines:

```text
re
base64
json
math
+
repository-local detection logic
```

`re` provides pattern-based detection for credential assignments, provider tokens, and private-key patterns.

`base64` and `json` support structured decoding for JWT-like token validation.

`math` provides Shannon entropy calculation as a confidence signal.

Repository-local logic ties these primitives together into the project's defined detector set.

Large dedicated secret-scanning frameworks may provide broader detector catalogues and ongoing provider-specific rules. LeakShield instead owns a smaller, auditable detector set.

### Repository discovery

`pathlib` handles filesystem traversal and path construction.

`fnmatch` provides ignore-pattern matching.

Together these support repository discovery and practical `.gitignore`-style filtering without a path-matching dependency.

A dedicated path-specification library can support a broader pattern language, while LeakShield keeps the implementation smaller and dependency-free.

### Reporting

`json` provides native JSON parsing and serialization for machine-consumable output.

`html.escape` provides HTML escaping for safe report generation.

Project-local string formatting and report assembly complete the reporting path without a template engine.

A template engine can make large or highly dynamic templates easier to maintain, while LeakShield avoids an additional runtime package.

### Git protection

`subprocess` invokes the local Git CLI in a controlled manner.

Git-specific features (pre-commit hooks, staged-content inspection, repository root detection) operate by calling `git` as an external executable.

This avoids requiring a Python Git library such as GitPython. The trade-off is that Git must be installed and available on the system PATH.

Git is an external executable requirement, not a third-party Python dependency.

### Testing

`unittest` and `unittest.mock` provide assertions, test discovery, setup mechanisms, and mocking.

The complete regression suite runs with Python's built-in test runner:

```powershell
python -m unittest discover -s tests -v
```

pytest offers a richer ecosystem and many convenience features, but unittest keeps the project's test execution dependency-free.

---

## 6. Conceptual Package Alternatives

The following comparisons describe plausible implementation alternatives. They are not claims that LeakShield historically depended on these packages.

| Capability      | Common package approach        | LeakShield stdlib approach                             | Honest characterization               |
| --------------- | ------------------------------ | ------------------------------------------------------ | ------------------------------------- |
| CLI             | Click / Typer                  | `argparse`                                              | stdlib alternative                    |
| Git operations  | GitPython                      | `subprocess` + Git CLI                                  | focused stdlib alternative            |
| Path matching   | pathspec                       | `pathlib` + `fnmatch`                                   | narrower stdlib implementation        |
| Secret scanning | detect-secrets / similar tools | `re` + `base64` + `json` + `math` + local logic        | meaningful subset, not feature parity |
| HTML templating | Jinja2                         | `html.escape` + project formatting                      | controlled reporting alternative      |
| Testing         | pytest                         | `unittest`                                               | stdlib test framework                 |

### Secret-scanning ecosystem: `detect-secrets`

Established tools such as `detect-secrets` address a broader repository secret-scanning problem with their own detector sets, filtering mechanisms, plugins, and workflows.

LeakShield overlaps with that problem space but intentionally implements a smaller, locally auditable subset of secret-detection capabilities using Python's standard library.

```text
CAPABILITY / IMPLEMENTATION COMPARISON
NOT FEATURE-FOR-FEATURE REPLACEMENT

                 SECRET-SCANNING SPACE

                  detect-secrets
                         │
              broader package ecosystem
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       detectors      filtering       workflows
                         │
                         ▼
                   pre-commit use


                     LEAKSHIELD

                    Python stdlib
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
         re          base64/json       math
          │              │              │
          └──────────────┼──────────────┘
                         ▼
              repository-local logic
                         │
                         ▼
               focused secret detection
```

Overlap with `detect-secrets` includes:

* repository secret detection
* pattern-based detection
* entropy-related heuristics
* security/pre-commit workflow relevance

Differences include:

* smaller detector catalogue
* no feature-for-feature compatibility claim
* does not reproduce the complete `detect-secrets` ecosystem
* no online secret validation
* focused zero-runtime-dependency architecture

`detect-secrets` is the strongest conceptual comparison because it occupies the same problem space. LeakShield implements a focused subset of its capabilities using the Python standard library.

LeakShield does **not** claim to be a full reimplementation or feature-equivalent replacement of `detect-secrets`.

### Capability comparison

| Capability                   | `detect-secrets`           | LeakShield                                | Assessment              |
| ---------------------------- | -------------------------- | ----------------------------------------- | ----------------------- |
| Pattern/regex detection      | Yes                        | Yes                                       | Direct overlap          |
| Entropy analysis             | Yes                        | Yes                                       | Direct overlap          |
| Keyword/credential detection | Yes                        | Credential-assignment detection           | Partial overlap         |
| Provider-specific plugins    | Extensive plugin ecosystem | Focused detector set                      | detect-secrets-specific |
| Baselines/filtering          | Yes                        | Different repository/filtering mechanisms | Not equivalent          |
| AST security analysis        | No                         | Yes                                       | LeakShield-specific     |
| Git/pre-commit workflow      | Yes                        | Yes                                       | Workflow overlap        |
| JSON/HTML reporting          | JSON-oriented workflows    | CLI / JSON / HTML                         | Partial overlap         |

### Evidence flow

```text
PACKAGE KILLER EVIDENCE

Established package
       │
       ▼
detect-secrets
       │
       │ overlapping capability
       ▼
Repository secret scanning
       │
       ├── pattern detection
       ├── entropy signals
       └── credential/keyword-oriented detection
       │
       ▼
LeakShield implementation
       │
       ├── re
       ├── base64
       ├── json
       ├── math
       └── repository-local detection logic
       │
       ▼
Focused stdlib implementation
       │
       ▼
NOT feature-for-feature replacement
```

**Capability-level comparison, not feature-for-feature replacement.**

### Package Killer assessment — Qualified

LeakShield independently implements a focused subset of repository secret-scanning capabilities commonly provided by established tools such as `detect-secrets`, using only Python's standard library and repository-local code.

This is a meaningful capability-level reimplementation for LeakShield's defined scope, but LeakShield does **not** claim feature-for-feature compatibility with `detect-secrets` or replacement of its complete ecosystem.

Adoption/download figures were not used as a basis for this claim.

---

## 7. Engineering Trade-offs

| Area             | Benefit of stdlib approach       | Cost / trade-off                                        |
| ---------------- | -------------------------------- | ------------------------------------------------------- |
| CLI              | no CLI framework dependency      | less abstraction/convenience                            |
| Git              | explicit process boundary        | requires Git executable and careful subprocess handling |
| File matching    | small/simple implementation      | narrower semantics than specialized path libraries      |
| Secret detection | direct control and auditability  | LeakShield owns detector maintenance and edge cases     |
| Reporting        | no template dependency           | more formatting logic remains in project code           |
| Testing          | no pytest dependency             | fewer test-runner conveniences                          |
| Maintenance      | smaller external runtime surface | more functionality is owned by LeakShield               |

Zero dependency is not automatically better for every project. These trade-offs are accepted deliberately.

---

## 8. Security Limitations

The following are boundaries of the implemented scope, not evidence that the architecture failed:

* Pattern detection is heuristic.
* Entropy is a signal, not proof of secrecy.
* False positives are possible.
* False negatives are possible.
* No online secret validation occurs.
* Detector coverage is intentionally scoped.
* `.gitignore`-style matching is a practical subset of Git's ignore specification, not a complete reproduction of every edge case.
* Clean scan results do not prove repository security.
* Git-specific features require a local Git executable.

---

## 9. Testing Evidence

The regression suite is executed using Python's built-in `unittest` runner:

```powershell
python -m unittest discover -s tests -v
```

Current verified result:

```text
Ran 312 tests
ALL PASSING
```

Test areas include:

* AST security detection
* CLI behavior and exit codes
* Configuration validation
* Discovery and ignore filtering
* Finding normalization, confidence, severity, and risk
* Git protection and pre-commit workflows
* HTML reporting
* JSON reporting
* Reproducible build
* Scanner collection and determinism
* Secret detection (private keys, credentials, provider tokens, JWTs)
* Shannon entropy
* Deduplication and cross-location consolidation

No third-party test framework is required.

---

## 10. Zero-Dependency Verification

| Evidence                    | Result                                 |
| --------------------------- | -------------------------------------- |
| Production import audit     | stdlib + repository-local imports only |
| Third-party runtime imports | none identified                        |
| Python dependency manifests | none present                           |
| Git integration             | `subprocess` + local Git CLI           |
| Test framework              | stdlib `unittest` / `unittest.mock`    |
| Regression suite            | 312 tests, all passing                 |
| Repository inspection       | completed                              |

```text
Third-party Python runtime dependencies: NONE
```

The claim is based on multiple forms of evidence:

1. Production imports
2. Dependency manifests
3. Test framework imports
4. Standard-library usage
5. Git integration implementation
6. Successful execution of the complete regression suite

The goal is to make the zero-dependency design **inspectable and reproducible**, rather than asking users or judges to take the claim on trust.

---

## 11. What LeakShield Does Not Claim

* LeakShield did not remove previously installed dependencies.
* The listed packages are reasonable alternatives, not historical dependencies.
* Zero Python dependency does not mean zero operating-system requirements.
* Git-specific features require a local Git executable.
* Python itself remains required.
* The standard library is part of the Python runtime.
* LeakShield does not claim feature parity with the listed third-party frameworks.
* Zero dependency does not automatically mean better performance or broader functionality.
* LeakShield does not claim to be a complete replacement for `detect-secrets` or any other security-scanning platform.
* LeakShield does not claim comprehensive secret-scanning coverage.
