# LeakShield

**LeakShield is a local, zero-dependency Python repository security auditor.**

It helps developers prevent accidentally shipping **secrets and security-sensitive code patterns** by scanning repository files before those issues move further through development or into a remote repository.

LeakShield:

* Runs locally on your computer.
* Does not execute the code it scans.
* Does not make network requests while scanning.
* Uses Python's standard library only.
* Reports **potential security findings** for developer review.

> **Important:** A finding is a detection signal that deserves investigation. It does not automatically mean that your application is exploitable or that a detected credential is active.

---

## Why LeakShield Exists

Security-sensitive code and credentials can be added to a repository accidentally.

A common workflow looks like this:

```text
Developer writes code
        ↓
A secret or risky security pattern is accidentally added
        ↓
The repository is committed
        ↓
The issue may reach a remote repository
        ↓
LeakShield helps catch supported patterns earlier
```

LeakShield is designed as a **preventive developer-security tool**.

Its purpose is not to exploit vulnerabilities or perform penetration testing. It performs local static analysis and gives developers information they can review before shipping code.

---

# Getting Started

If you are completely new to LeakShield, follow these steps in order:

```text
1. Obtain the LeakShield project
2. Open a terminal
3. Navigate to the LeakShield project directory
4. Verify Python is available
5. Run the demo
6. Scan your own repository
7. Review any findings
8. Choose CLI, JSON, or HTML output when needed
```

---

## Requirements

You need:

* **Python 3**
* A local directory or repository that you want to scan

LeakShield currently has **no third-party Python runtime dependencies**.

There is no `requirements.txt`, `pyproject.toml`, or `setup.py` installation step required to run the scanner from the project directory.

### Check your Python version

Open PowerShell or another terminal and run:

```powershell
python --version
```

For example:

```text
Python 3.13.13
```

LeakShield uses Python standard-library functionality and is run directly from the project source tree.

---

# Install / Setup

LeakShield does not require a package installation command for normal use.

### 1. Obtain the LeakShield repository

Clone or otherwise obtain the LeakShield project on your computer.

### 2. Open a terminal

On Windows, you can use **PowerShell**.

### 3. Navigate to the LeakShield directory

For example:

```powershell
cd <PATH_TO_LEAKSHIELD>
```

`<PATH_TO_LEAKSHIELD>` is a placeholder for the folder containing the LeakShield project.

For example:

```powershell
cd C:\Projects\LeakShield
```

### 4. Verify that you are in the correct directory

The directory should contain files and folders similar to:

```text
LeakShield/
├── leakshield/
├── tests/
├── examples/
└── README.md
```

Once you are there, you can run:

```powershell
python -m leakshield ...
```

---

# Where Should I Run the Commands?

This is an important distinction.

There are **two different locations**:

### 1. The LeakShield project

This is where the LeakShield code lives.

Example:

```text
C:\Projects\LeakShield\
```

Run the `python -m leakshield ...` commands from this project directory when using the source-tree workflow described in this README.

### 2. The repository you want to scan

This is the **target**.

Example:

```text
C:\Projects\my-app\
```

The target can be a completely different directory from the LeakShield project.

Think of it like this:

```text
LeakShield project
C:\Projects\LeakShield\
        │
        │ runs the scanner
        ↓
Your repository
C:\Projects\my-app\
        │
        │ is scanned
        ↓
Potential security findings
```

You do **not** need to copy your project into the `examples` directory.

You do **not** normally put your own repository inside the LeakShield project.

---

# Scan Your Own Repository

The general command is:

```powershell
python -m leakshield <REPOSITORY_PATH>
```

Replace `<REPOSITORY_PATH>` with the path to the repository you want to scan.

For example:

```powershell
python -m leakshield C:\Projects\my-app
```

Or:

```powershell
python -m leakshield C:\Users\<USERNAME>\Projects\my-app
```

### What is `<REPOSITORY_PATH>`?

It is a **placeholder**.

Do not type the angle brackets literally.

This:

```powershell
python -m leakshield <REPOSITORY_PATH>
```

means:

```text
Replace <REPOSITORY_PATH> with the location of your repository.
```

For example:

```powershell
python -m leakshield C:\Projects\my-app
```

Your path will be different depending on where your repository is stored.

---

## Scanning the Current Directory

You can also use:

```powershell
python -m leakshield .
```

The `.` means:

> **the current directory**

Therefore, this command scans whichever directory your terminal is currently in.

For example, if PowerShell shows:

```text
PS C:\Projects\my-app>
```

and you run:

```powershell
python -m leakshield .
```

then `.` refers to:

```text
C:\Projects\my-app
```

Be careful: if you are currently inside the LeakShield project and run:

```powershell
python -m leakshield .
```

you are asking LeakShield to scan the **LeakShield directory itself**, not your separate application.

---

# First-Time Demo: Vulnerable Repository

LeakShield includes example repositories so you can see how the scanner behaves before scanning your own project.

The examples are for:

* demonstrations
* testing
* learning

They are **not your application** and are not where you are expected to put your project.

## Run the vulnerable demo

From the LeakShield project directory:

```powershell
python -m leakshield examples\vulnerable_repo
```

This repository intentionally contains security-sensitive demonstration patterns.

Therefore, findings are **expected**.

You may see output similar to:

```text
LEAKSHIELD

Target: ...\examples\vulnerable_repo

[1/3] Discovering repository files...
[2/3] Analyzing supported security patterns...
[3/3] Preparing findings...

10 potential security findings found.
```

The exact findings depend on the contents of the example repository.

### Remember

```text
examples\vulnerable_repo
        ↓
Demo / learning
        ↓
Not your real project
```

The findings from this demo do not mean that your own repository contains those findings.

---

# Clean Repository Demo

LeakShield also includes a clean example:

```powershell
python -m leakshield examples\clean_repo
```

This example is designed to contain no supported security patterns.

You should see a clean result similar to:

```text
No supported security patterns detected.
```

### What does zero findings mean?

It means:

> LeakShield did not detect any of the currently supported patterns in the files it analyzed.

It does **not** mean:

> The repository is guaranteed to be completely secure.

No static scanner can establish complete security from a clean scan alone.

The clean demo is simply a way to see what a repository with no supported LeakShield findings looks like.

---

# Scan Your Own Project: Practical Example

Suppose your application is located at:

```text
C:\Users\<USERNAME>\Projects\my-app
```

First, open PowerShell and navigate to the LeakShield project:

```powershell
cd <PATH_TO_LEAKSHIELD>
```

For example:

```powershell
cd C:\Projects\LeakShield
```

Then scan your application:

```powershell
python -m leakshield C:\Users\<USERNAME>\Projects\my-app
```

LeakShield will:

```text
1. Identify the target
2. Discover files
3. Analyze supported security patterns
4. Prepare and normalize findings
5. Report the results
```

The scan is performed locally.

LeakShield treats the repository as **data to analyze**, not code to execute.

---

# Understanding the Output

The default output format is the CLI.

A typical scan communicates information such as:

```text
LEAKSHIELD

Target: <target path>

[1/3] Discovering repository files...
[2/3] Analyzing supported security patterns...
[3/3] Preparing findings...

<result>

Location: ...
What: ...
Why: ...
Action: ...
```

## Location

**Location** tells you where the potential issue was detected.

For example:

```text
config.py:18:5
```

This means the finding was detected in `config.py`, at line 18, column 5.

Use the location to inspect the relevant part of your repository.

---

## What

**What** describes the security-sensitive pattern that LeakShield detected.

For example:

```text
Hardcoded credential assignment
```

or:

```text
Direct eval() call
```

---

## Why

**Why** explains why LeakShield considers the pattern worth reviewing.

For example:

```text
A credential-like variable is assigned a hardcoded string value.
```

The explanation is intended to help you understand the security concern rather than simply pointing to a line of code.

---

## Action

**Action** provides a recommended next step.

For example:

```text
Move the credential outside source code and rotate it if it may already have been exposed.
```

The appropriate action depends on what you discover during your review.

---

# What Is a "Potential Finding"?

A LeakShield finding is a **detection signal that deserves developer or security review**.

It is not automatically proof that:

```text
"Your application is definitely vulnerable."
```

For example, LeakShield can detect a direct:

```python
eval(...)
```

call.

That is security-sensitive, but whether it creates an exploitable vulnerability depends on how the code is used and what data reaches it.

Similarly, if LeakShield detects a credential-like assignment, you should determine whether the value is:

* a real credential
* a test value
* a placeholder
* already revoked
* otherwise harmless

If it may be a real exposed credential, consider rotating or revoking it as appropriate.

---

# What Does LeakShield Detect?

LeakShield currently detects selected secret, credential, and Python security patterns.

The detector set is intentionally limited. LeakShield does **not** attempt to detect every possible security problem.

## Secret and Credential Patterns

Supported categories include:

* Hardcoded credential-like assignments
* GitHub personal access token patterns
* GitHub fine-grained personal access token patterns
* GitLab personal access token patterns
* Slack token patterns
* JWT-like structured tokens
* PEM private keys
* Entropy-based contextual evidence for applicable findings

LeakShield uses structural and contextual evidence for these detections. It does not treat every long or random-looking string as a secret.

### JWT detection

LeakShield can identify JWT-like candidates when the token has structurally valid, decodable header and payload segments that parse as JSON objects.

This does **not** mean LeakShield verifies:

* JWT authenticity
* token trust
* whether the token is active
* whether the token can be used successfully

---

# Python Security Patterns

LeakShield also uses Python's AST (Abstract Syntax Tree) to detect selected security-sensitive constructs.

Currently implemented examples include:

```python
eval(...)
exec(...)
subprocess.Popen(...)
subprocess.Popen(..., shell=True)
os.system(...)
```

It also detects selected hardcoded credential assignments in Python code.

AST analysis means LeakShield can examine the **structure of Python code**, rather than relying only on simple text matching.

For example, it can recognize a call as a Python function call and inspect its structure.

You do not need to understand ASTs to use LeakShield.

---

# Understanding Confidence, Severity, and Risk

Some findings contain additional metadata.

These values answer different questions.

### Confidence

**How likely is the detection to be correct?**

Higher confidence means LeakShield has stronger evidence that the detected material matches the relevant pattern.

### Severity

**How dangerous could the condition be if it is genuinely sensitive or valid?**

High severity does not prove that a detected credential is active.

### Risk

**How should the finding be prioritized?**

Risk combines the scanner's assessment of confidence and severity.

A high-risk finding should receive attention, but it is still not proof that:

* a credential is live
* a credential is usable
* an application is exploitable

LeakShield performs static analysis. Determining whether a credential is active or exploitable requires additional investigation.

---

# Output Formats

LeakShield supports three output formats:

```text
CLI  → developer interaction
JSON → machine/integration use
HTML → human review/reporting
```

## CLI

CLI is the default:

```powershell
python -m leakshield <REPOSITORY_PATH>
```

Use it when you are directly running a scan and want a readable summary of what LeakShield found and what to review.

---

## JSON

Use:

```powershell
python -m leakshield <REPOSITORY_PATH> --format json
```

JSON produces structured findings that can be consumed by:

* scripts
* automation
* CI/CD workflows
* other software

This is useful when another tool needs to process the scan results instead of a person reading terminal output.

---

## HTML

Use:

```powershell
python -m leakshield <REPOSITORY_PATH> --format html
```

HTML produces a browser-readable report.

It can be useful for:

* human review
* inspecting findings outside the terminal
* presenting a readable scan report

---

# Zero Dependency

"Zero dependency" does **not** mean that LeakShield requires absolutely nothing.

It means that the core scanner does not require third-party Python packages.

LeakShield uses Python's **standard library**.

For normal source-tree use, you do not need to run:

```powershell
pip install ...
```

before running LeakShield.

You need Python itself.

---

# How LeakShield Handles Repository Code

LeakShield is designed to treat repository contents as **untrusted input**.

During a scan it:

* Reads repository files as data.
* Parses Python source statically when AST analysis is needed.
* Does not execute scanned repository code.
* Does not make network requests.
* Does not invoke subprocesses while scanning.
* Produces its reports locally.

This is an important part of LeakShield's security model.

---

# Common Beginner Mistakes

## "I ran the command from the wrong directory."

Make sure you are running the source-tree command from the LeakShield project directory.

For example:

```powershell
cd <PATH_TO_LEAKSHIELD>
```

Then:

```powershell
python -m leakshield <REPOSITORY_PATH>
```

The target repository can be somewhere else.

---

## "I typed `<REPOSITORY_PATH>` literally."

Do not type the angle brackets.

This:

```powershell
python -m leakshield <REPOSITORY_PATH>
```

is an example showing where your path goes.

Replace it with the actual path:

```powershell
python -m leakshield C:\Projects\my-app
```

---

## "I thought `examples\vulnerable_repo` was my project."

It is not.

The example repositories are included for demonstration and testing.

```text
examples\vulnerable_repo
        ↓
Intentional demo

examples\clean_repo
        ↓
Intentional clean demo

your-project
        ↓
Your real repository
```

Scan your own repository by providing its path.

---

## "What does `.` mean?"

`.` means **the current directory**.

For example:

```powershell
PS C:\Projects\my-app> python -m leakshield .
```

scans:

```text
C:\Projects\my-app
```

Make sure the current directory is the repository you actually want to scan.

---

## "LeakShield found zero findings. Does that mean my repository is secure?"

No.

It means LeakShield did not detect any of its **currently supported patterns** in the files it analyzed.

Static analysis can have both false positives and false negatives, and LeakShield is not a complete security assessment platform.

---

# Limitations

LeakShield is a static repository security auditor, not a complete security assessment platform.

It does not currently:

* Detect malware comprehensively.
* Analyze Git history.
* Perform remote vulnerability scanning.
* Verify JWT authenticity or trust.
* Provide AI/ML-based secret detection.
* Analyze runtime behavior.
* Analyze deployed infrastructure.
* Assess external services.

The detector set is intentionally limited to the implemented secret and Python security rules.

---

# Command Quick Reference

### Scan your repository

```powershell
python -m leakshield <REPOSITORY_PATH>
```

### Scan the current directory

```powershell
python -m leakshield .
```

### Run the vulnerable demo

```powershell
python -m leakshield examples\vulnerable_repo
```

### Run the clean demo

```powershell
python -m leakshield examples\clean_repo
```

### Generate JSON output

```powershell
python -m leakshield <REPOSITORY_PATH> --format json
```

### Generate HTML output

```powershell
python -m leakshield <REPOSITORY_PATH> --format html
```

### Run the test suite

```powershell
python -m unittest discover -s tests -v
```

---

# Project Structure

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
│   ├── clean_repo/
│   └── vulnerable_repo/
├── PROJECT_STATE.md
├── STDLIB.md
├── THREAT_MODEL.md
├── deps-proof.txt
├── .zero-dep.toml
└── README.md
```

The important distinction for new users is:

```text
leakshield/
    ↓
The scanner itself

examples/
    ↓
Demonstration and test repositories

your repository
    ↓
The project you actually want to scan
```

---

# Testing

To run the complete regression suite:

```powershell
python -m unittest discover -s tests -v
```

The test suite covers areas including:

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

---

# Final Mental Model

If you remember only one workflow, remember this:

```text
Open PowerShell
      ↓
Go to the LeakShield project
      ↓
cd <PATH_TO_LEAKSHIELD>
      ↓
Choose the repository you want to scan
      ↓
python -m leakshield <REPOSITORY_PATH>
      ↓
Review the potential findings
      ↓
Investigate each finding
      ↓
Take the recommended action
```

For a first demonstration:

```powershell
python -m leakshield examples\vulnerable_repo
```

Then try the clean example:

```powershell
python -m leakshield examples\clean_repo
```

Finally, scan your own repository:

```powershell
python -m leakshield <REPOSITORY_PATH>
```

**LeakShield helps developers catch supported secrets and security-sensitive code patterns before they become a bigger problem.**
---

# License

No license is currently specified in the repository.
