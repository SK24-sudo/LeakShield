"""Safe demo code with no security patterns."""

import subprocess


def safe_function():
    """Use subprocess safely."""
    subprocess.run(["echo", "hello"], shell=False)
    return "safe"


def get_config():
    """Get config from environment."""
    import os
    return os.environ.get("API_KEY", "default")