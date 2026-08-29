"""Safe demo source containing patterns for LeakShield's AST detectors."""

import os
import subprocess


def demonstrate_unsafe_patterns():
    eval("demo_expression")
    exec("demo_value = 1")
    os.system("echo leakshield-demo")
    subprocess.Popen(["echo", "leakshield-demo"], shell=True)
