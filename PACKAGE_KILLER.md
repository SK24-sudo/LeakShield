# Package Killer

Zero dependency is an engineering constraint rather than merely the absence of a dependency manifest.

LeakShield deliberately uses Python standard-library capabilities and repository-local code instead of requiring third-party Python packages for its core scanner functionality.

Each section below shows a concrete capability, a reasonable external alternative, the stdlib implementation LeakShield actually uses, and the resulting engineering trade-off.

---

## 1. CLI Argument Parsing

```
Capability:
CLI argument parsing and validation

Typical external option:
Click / Typer

Capability provided:
Structured command-line options, help generation,
validation, and CLI ergonomics.

LeakShield implementation:
argparse

Why:
LeakShield's CLI requirements fit within argparse's
standard-library functionality.

Trade-off:
Click/Typer can provide richer CLI abstractions and
presentation conveniences, but argparse avoids a runtime
dependency while providing the required parsing behavior.
```

---

## 2. Git Integration

```
Capability:
Git repository interaction

Typical external option:
GitPython

Capability provided:
Python-level wrappers around Git repository operations.

LeakShield implementation:
subprocess + local Git CLI

Why:
LeakShield needs a focused set of Git operations and can
invoke the locally installed Git executable through Python's
standard-library subprocess module.

Trade-off:
A Python Git library can provide a richer object-oriented API,
but LeakShield avoids another Python package and keeps the
Git boundary explicit.
```

Git itself remains an external executable requirement for Git-specific protection features. Git is not a Python dependency.

---

## 3. Filesystem and Ignore Matching

```
Capability:
Repository traversal, path handling, and ignore matching

Typical external option:
pathspec or similar path-matching libraries

LeakShield implementation:
pathlib + fnmatch

Why:
The repository discovery requirements can be implemented using
standard-library path traversal and filename-pattern matching.

Trade-off:
A dedicated path-specification library can support a broader or
more specialized pattern language, while LeakShield keeps the
implementation smaller and dependency-free.
```

---

## 4. Secret Detection

```
Capability:
Pattern-based secret detection, structured decoding,
and entropy analysis

Typical external option:
Dedicated secret-scanning libraries/frameworks

LeakShield implementation:
re + base64 + json + math + repository-local detection logic

Why:
LeakShield's defined detection rules can be implemented from
standard-library primitives without depending on an external
scanning framework.

Trade-off:
Large dedicated secret-scanning frameworks may provide a much
broader detector catalogue and ongoing provider-specific rules.
LeakShield instead owns a smaller, auditable detector set.
```

---

## 5. HTML Reporting

```
Capability:
Safe HTML report generation

Typical external option:
Jinja2 or another template engine

LeakShield implementation:
html.escape + standard Python string/reporting logic

Why:
LeakShield's report structure is sufficiently controlled that
a full template engine is not required.

Trade-off:
A template engine can make large or highly dynamic templates
easier to maintain, while LeakShield avoids an additional
runtime package and keeps the reporting path explicit.
```

---

## 6. JSON Reporting

```
Capability:
JSON serialization

Typical external option:
External JSON libraries

LeakShield implementation:
json

Why:
Python's standard library already provides JSON parsing and
serialization suitable for LeakShield's reporting requirements.

Trade-off:
External JSON libraries may offer different performance or
specialized features, but those are not required for the
project's defined output contract.
```

---

## 7. Static Python Analysis

```
Capability:
Python source-code structural analysis

Typical external option:
AST helper/analysis libraries

LeakShield implementation:
ast + repository-local detector logic

Why:
Python's built-in AST module exposes the syntax tree directly,
which is sufficient for LeakShield's defined static security
rules.

Trade-off:
Specialized analysis frameworks can provide more abstractions,
helper utilities, and broader analysis functionality. LeakShield
keeps the analysis path small and directly inspectable.
```

---

## 8. Testing

```
Capability:
Automated regression testing

Typical external option:
pytest

LeakShield implementation:
unittest + unittest.mock

Why:
Python's standard library provides the assertions, test
discovery, setup mechanisms, and mocking needed by LeakShield's
existing regression suite.

Trade-off:
pytest offers a richer ecosystem and many convenience features,
but unittest keeps the project's test execution dependency-free.
```

---

## 9. Reproducible Packaging

```
Capability:
Runnable application packaging and reproducible artifact creation

Typical external options:
setuptools / PyInstaller / other packaging/build frameworks

LeakShield implementation:
Python standard library including zipfile, tempfile, pathlib,
hashlib, shutil, and deterministic archive construction.

Why:
LeakShield can create a runnable .pyz artifact without adding
a third-party packaging dependency.

Trade-off:
Full packaging frameworks can provide installers, native
executables, dependency bundling, and platform-specific
distribution features. LeakShield intentionally targets a
lightweight Python .pyz artifact.
```

The runtime artifact is not a native executable. The artifact still requires Python.

---

## Comparison Matrix

| Capability             | Reasonable external option   | LeakShield stdlib                  | Main trade-off                                 |
| ---------------------- | ---------------------------- | ---------------------------------- | ---------------------------------------------- |
| CLI parsing            | Click / Typer                | argparse                           | Less framework convenience                     |
| Git integration        | GitPython                    | subprocess + Git CLI               | Less Python-level abstraction                  |
| Path matching          | pathspec                     | pathlib + fnmatch                  | Narrower pattern semantics                     |
| Secret detection       | Security scanning frameworks | re + base64 + math + project logic | Smaller detector scope                         |
| HTML reporting         | Jinja2                       | html.escape + project formatting   | Less template abstraction                      |
| JSON                   | External JSON libraries      | json                               | Specialized alternatives unnecessary for scope |
| Static Python analysis | AST helper frameworks        | ast + project logic                | Fewer analysis abstractions                    |
| Testing                | pytest                       | unittest                           | Less test-runner convenience                   |
| Packaging              | setuptools / PyInstaller     | zipfile + stdlib build logic       | No native executable/installer features        |

---

## What We Did Not Claim

* LeakShield did not remove previously installed dependencies.
* The listed packages are reasonable alternatives, not historical dependencies.
* Zero Python dependency does not mean zero operating-system requirements.
* Git-specific features require a local Git executable.
* Python itself remains required.
* The standard library is part of the Python runtime.
* LeakShield does not claim feature parity with the listed third-party frameworks.
* Zero dependency does not automatically mean better performance or broader functionality.

---

## Verification

Production imports were inspected across the `leakshield/` package.

Verified production standard-library imports:

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

No third-party Python imports were identified in production code.

The repository contains no Python dependency manifest such as `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, `poetry.lock`, or `uv.lock`.

The test suite can be executed using Python's built-in unittest runner:

```powershell
python -m unittest discover -s tests -v
```

Current regression suite result:

```
Ran 292 tests

OK
```

The development environment used for this verification contained only `pip` as an installed package outside the Python standard library.
