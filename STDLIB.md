# LeakShield Standard Library Policy

LeakShield is intentionally implemented using Python's standard library only.

## Dependency Policy

LeakShield has no third-party runtime dependencies.

The repository does not require:

- `requirements.txt`
- `requirements-dev.txt`
- `pyproject.toml`
- `setup.py`
- `setup.cfg`
- `Pipfile`
- `Pipfile.lock`
- `poetry.lock`
- `uv.lock`

No package installation step is required to run the scanner.

## Standard Library Modules

The current production implementation imports only these Python standard-library modules:

| Module | Used for |
|---|---|
| `argparse` | Command-line argument parsing |
| `ast` | Static Python syntax analysis |
| `base64` | Base64/Base64URL decoding for structured secret detection |
| `fnmatch` | Repository ignore-pattern matching |
| `html` | HTML escaping for reporting |
| `json` | JSON parsing and JSON reporting |
| `math` | Shannon entropy calculation |
| `pathlib` | Filesystem paths and repository traversal |
| `re` | Pattern-based secret detection |

Production modules also import internal `leakshield.*` modules. These are repository-local modules, not external dependencies.

## Runtime Boundary

LeakShield does not use third-party packages, network access, or subprocesses as part of its scanner implementation.

Repository contents are treated as untrusted data. LeakShield does not execute scanned repository code.

## Verification

The production import surface was manually inspected across the `leakshield/` package.

No third-party imports were identified.

The repository also contains no third-party dependency manifest.

The full regression suite was verified with:

```text
python -m unittest discover -s tests -v
```

The current verification run completed with:

```text
Ran 236 tests

OK
```