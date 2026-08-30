# LeakShield — Zero-Dependency Engineering Evidence

LeakShield is intentionally implemented as a **zero-Python-dependency security auditor**.

The production scanner does not require third-party Python packages. Its core functionality is built using Python's standard library and repository-local modules.

This document explains **how** that was achieved, what functionality would commonly be provided by external packages, and the engineering trade-offs of the approach.

For a deeper capability-by-capability comparison, see `PACKAGE_KILLER.md`.

---

## 1. Dependency Policy

LeakShield has **no third-party Python runtime dependencies**.

The repository does not require:

* `requirements.txt`
* `requirements-dev.txt`
* `pyproject.toml`
* `setup.py`
* `setup.cfg`
* `Pipfile`
* `Pipfile.lock`
* `poetry.lock`
* `uv.lock`

No `pip install` step is required for normal scanner usage from the project directory.

Production modules import only:

1. Python standard-library modules
2. Repository-local `leakshield.*` modules

Repository-local modules are part of LeakShield itself and are not external dependencies.

---

## 2. Standard Library Evidence

The production implementation currently uses these Python standard-library modules:

| Module       | Used for                                                  |
| ------------ | --------------------------------------------------------- |
| `argparse`   | Command-line argument parsing                             |
| `ast`        | Static Python syntax analysis                             |
| `base64`     | Base64/Base64URL decoding for structured secret detection |
| `fnmatch`    | Repository ignore-pattern matching                        |
| `html`       | HTML escaping for security reports                        |
| `json`       | JSON parsing and JSON report generation                   |
| `math`       | Shannon entropy calculation                               |
| `pathlib`    | Filesystem paths and repository traversal                 |
| `re`         | Pattern-based secret detection                            |
| `subprocess` | Controlled interaction with the local Git CLI             |

These imports were verified across the `leakshield/` production package.

No third-party Python imports were identified.

---

## 3. What Zero Dependency Means Here

“Zero dependency” does **not** mean that LeakShield requires absolutely nothing from the operating environment.

It means that LeakShield does not require **third-party Python packages** to perform its scanner functionality.

The distinction is important:

* Python itself is required.
* The Python standard library is used extensively.
* Git is required for Git-specific protection features because those features interact with a Git repository.
* The Git CLI is invoked through Python's standard-library `subprocess` module.
* No Python Git library such as GitPython is required.

The scanner does not execute scanned repository code.

---

## 4. Engineering Substitutions

A zero-dependency design means that functionality commonly provided by external packages must instead be implemented using standard-library capabilities.

The following are the relevant substitutions in LeakShield:

| Capability               | Typical external option                  | LeakShield stdlib implementation | Why we chose it                                                                                    |
| ------------------------ | ---------------------------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------- |
| CLI parsing              | Click / Typer                            | `argparse`                       | Provides structured commands, options, help text, and validation without an external CLI framework |
| Python AST analysis      | AST helper libraries                     | `ast`                            | Direct access to Python syntax trees is sufficient for LeakShield's static analysis rules          |
| Filesystem/path handling | Pathspec or similar filesystem libraries | `pathlib`, `fnmatch`             | Provides repository traversal, path handling, and ignore-pattern matching                          |
| JSON processing          | External JSON libraries                  | `json`                           | Native parsing and report serialization are sufficient                                             |
| HTML escaping            | Template/reporting libraries             | `html.escape`                    | Provides the escaping needed for safe HTML report generation                                       |
| Secret detection         | External scanning libraries              | `re`, `base64`, `math`           | Pattern matching, decoding, and entropy calculations can be implemented directly                   |
| Testing                  | pytest                                   | `unittest`                       | Supports the project's regression suite without adding a test dependency                           |
| Git integration          | GitPython                                | `subprocess` + Git CLI           | Provides the required Git operations without adding a Python Git package                           |

These are **alternative implementation comparisons**, not claims that LeakShield previously depended on those packages.

---

## 5. What LeakShield Implements Itself

Instead of relying on a third-party security framework, LeakShield combines standard-library primitives into its own scanning pipeline.

### Static Python analysis

LeakShield uses Python's `ast` module to inspect source code structurally rather than executing it.

This enables detection of security-sensitive constructs such as:

* `eval()`
* `exec()`
* dangerous subprocess usage
* suspicious credential-related assignments
* other AST-level patterns implemented by LeakShield's rules

### Secret detection

LeakShield combines:

* `re` for pattern detection
* `base64` for structured decoding
* `math` for entropy calculations

This allows secret-oriented analysis without importing an external secret-scanning package.

### Repository discovery

LeakShield uses:

* `pathlib` for filesystem traversal and paths
* `fnmatch` for ignore-pattern matching

This provides the repository discovery layer without a path-matching dependency.

### Reporting

LeakShield generates:

* CLI output
* JSON reports
* HTML security reports

using standard-library functionality including `json` and `html.escape`.

### Git protection

LeakShield integrates with Git by invoking the local Git executable through:

```text
subprocess → git CLI
```

This avoids requiring a Python Git wrapper such as GitPython.

### Testing

The test suite uses Python's built-in:

```text
unittest
unittest.mock
```

rather than requiring pytest.

---

## 6. Why Zero Dependency Matters

Zero dependency is an engineering choice, not just a marketing label.

### Reproducibility

A fresh Python environment does not need a dependency installation step before the scanner can run.

### Reduced dependency supply-chain exposure

Every third-party package introduces another piece of software that must be obtained, maintained, trusted, and potentially updated.

Reducing the dependency surface reduces that particular class of supply-chain exposure.

### Easier auditing

The scanner's implementation can be inspected directly through its Python source and standard-library usage.

There is no large third-party scanning framework hidden behind the core analysis.

### Simpler deployment

For normal project-directory usage:

```text
Python
   ↓
LeakShield
   ↓
Standard library
```

rather than:

```text
Python
   ↓
Package installer
   ↓
Third-party dependencies
   ↓
LeakShield
```

---

## 7. Trade-offs

Zero dependency is not automatically better for every project.

LeakShield accepts several trade-offs.

### More implementation effort

Functionality that mature packages provide must sometimes be implemented directly.

### More maintenance responsibility

LeakShield owns more of its implementation instead of delegating functionality to external libraries.

### Less framework convenience

A package such as Click or pytest can provide conveniences that `argparse` and `unittest` do not provide in exactly the same way.

### Git remains an external executable

Git-specific protection requires a locally available Git executable.

This is an operating-system/tooling dependency, but **not a third-party Python package dependency**.

### Scope remains deliberate

LeakShield does not attempt to reproduce every feature of large security-scanning frameworks. Its zero-dependency architecture is designed around the functionality required by this project.

---

## 8. Verification Evidence

The production import surface was inspected across the `leakshield/` package.

No third-party Python imports were identified.

The repository contains no Python dependency manifest such as:

```text
requirements.txt
pyproject.toml
setup.py
Pipfile
poetry.lock
uv.lock
```

The test suite can be executed using Python's built-in unittest runner:

```powershell
python -m unittest discover -s tests -v
```

The current regression suite completed successfully with:

```text
Ran 292 tests

OK
```

The development environment used for this verification contained only:

```text
pip
```

as an installed package outside the Python standard library.

---

## 9. Verification Principle

The zero-dependency claim is based on the **actual implementation**, not simply on the absence of a `requirements.txt` file.

Evidence considered includes:

1. Production imports
2. Dependency manifests
3. Test framework imports
4. Standard-library usage
5. Git integration implementation
6. Successful execution of the complete regression suite

The goal is to make the zero-dependency design **inspectable and reproducible**, rather than asking users or judges to take the claim on trust.
