# Reproducible Build

## Purpose

LeakShield can produce a deterministic runnable `.pyz` artifact using only Python's standard library. No third-party build tools are required.

## Requirements

* Python 3 (validated on Python 3.13.13)
* LeakShield source tree
* No network access required
* No external dependencies required

## Build

```powershell
python build.py
```

## Artifact

```
dist/LeakShield.pyz
```

## Run

```powershell
python dist\LeakShield.pyz --help
```

## Reproducibility verification

```
Source
  ↓
python build.py
  ↓
dist/LeakShield.pyz
  ↓
SHA-256
```

Then:

```
Same source
  ↓
python build.py again
  ↓
dist/LeakShield.pyz
  ↓
SHA-256
```

The resulting artifacts must be byte-identical.

## Hash evidence

After building twice from the same source tree, the following SHA-256 hashes were obtained:

Build 1: `935A5190581C18864B20C79D815CD0D605EA0DD947DEB4394C8C00555D86494B`

Build 2: `935A5190581C18864B20C79D815CD0D605EA0DD947DEB4394C8C00555D86494B`

The hashes match. Direct byte comparison also passed.

## Toolchain

* Python 3.13.13
* Windows 32-bit (win32)
* Standard library only (`zipfile`, `tempfile`, `hashlib`, `pathlib`, `os`, `shutil`, `sys`)

## Zero-dependency explanation

The build uses Python's standard library exclusively:

* `zipfile` for deterministic archive creation
* `tempfile` for isolated staging
* `hashlib` for SHA-256 verification
* `pathlib` and `os` for file collection

The runtime artifact (`dist/LeakShield.pyz`) requires only a Python interpreter. No third-party runtime package is bundled or required. The build does not download or install dependencies.

## Limitations

Reproducibility has been demonstrated on the same machine with the same Python version. Cross-machine or cross-platform reproducibility is not claimed unless independently verified. The claim is limited to: two consecutive builds from the same source tree on the same toolchain produce byte-identical artifacts.
