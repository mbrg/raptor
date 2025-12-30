#!/usr/bin/env python3
"""
RAPTOR Plugin Dependency Checker

This script validates that all dependencies for a RAPTOR plugin are satisfied.
It's designed to be called by Claude Code before running plugin commands.

Usage:
    python3 raptor-deps-check.py <plugin-name>
    python3 raptor-deps-check.py raptor-scan
    python3 raptor-deps-check.py --all
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class DependencyChecker:
    """Check and report on plugin dependencies."""

    PLUGINS_DIR = Path(__file__).parent

    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.plugin_dir = self.PLUGINS_DIR / plugin_name
        self.manifest_path = self.plugin_dir / ".claude-plugin" / "plugin.json"
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def load_manifest(self) -> Optional[Dict]:
        """Load the plugin manifest."""
        if not self.manifest_path.exists():
            self.errors.append(f"Plugin manifest not found: {self.manifest_path}")
            return None

        try:
            with open(self.manifest_path) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            self.errors.append(f"Invalid JSON in manifest: {e}")
            return None

    def check_python_version(self, required: str) -> bool:
        """Check if Python version meets requirement."""
        import re

        match = re.match(r'>=(\d+)\.(\d+)', required)
        if not match:
            self.warnings.append(f"Could not parse Python version requirement: {required}")
            return True

        req_major, req_minor = int(match.group(1)), int(match.group(2))
        cur_major, cur_minor = sys.version_info[:2]

        if (cur_major, cur_minor) < (req_major, req_minor):
            self.errors.append(
                f"Python {req_major}.{req_minor}+ required, "
                f"but running {cur_major}.{cur_minor}"
            )
            return False
        return True

    def check_pip_package(self, package: str) -> bool:
        """Check if a pip package is installed."""
        # Parse package name (handle version specs like semgrep>=1.0.0)
        import re
        match = re.match(r'^([a-zA-Z0-9_-]+)', package)
        if not match:
            self.warnings.append(f"Could not parse pip package: {package}")
            return True

        pkg_name = match.group(1)

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", pkg_name],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def check_system_binary(self, binary: str) -> bool:
        """Check if a system binary is available."""
        # Handle "or" specifications like "gcc or clang"
        if " or " in binary:
            alternatives = [b.strip() for b in binary.split(" or ")]
            for alt in alternatives:
                if shutil.which(alt):
                    return True
            return False

        return shutil.which(binary) is not None

    def check_env_var(self, var_spec: str) -> bool:
        """Check if an environment variable is set."""
        # Handle "or" specifications
        if " or " in var_spec:
            vars_to_check = [v.strip() for v in var_spec.split(" or ")]
            for var in vars_to_check:
                if os.environ.get(var):
                    return True
            return False

        return bool(os.environ.get(var_spec))

    def check_dependencies(self, deps: Dict) -> Tuple[bool, List[str], List[str]]:
        """Check all dependencies and return status."""
        all_ok = True

        # Check Python version
        if "python" in deps:
            if not self.check_python_version(deps["python"]):
                all_ok = False

        # Check pip packages
        if "pip" in deps:
            missing_pip = []
            for pkg in deps["pip"]:
                if not self.check_pip_package(pkg):
                    missing_pip.append(pkg)

            if missing_pip:
                all_ok = False
                self.errors.append(
                    f"Missing pip packages: {', '.join(missing_pip)}\n"
                    f"  Install with: pip install {' '.join(missing_pip)}"
                )

        # Check system binaries
        if "system" in deps:
            missing_system = []
            for binary in deps["system"]:
                if not self.check_system_binary(binary):
                    missing_system.append(binary)

            if missing_system:
                all_ok = False
                self.errors.append(
                    f"Missing system dependencies: {', '.join(missing_system)}\n"
                    f"  Install these tools and ensure they're in your PATH"
                )

        # Check environment variables
        if "env" in deps:
            missing_env = []
            for var in deps["env"]:
                if not self.check_env_var(var):
                    missing_env.append(var)

            if missing_env:
                all_ok = False
                self.errors.append(
                    f"Missing environment variables: {', '.join(missing_env)}\n"
                    f"  Set these before running the plugin"
                )

        return all_ok, self.errors, self.warnings

    def check(self) -> bool:
        """Run full dependency check for the plugin."""
        manifest = self.load_manifest()
        if not manifest:
            return False

        deps = manifest.get("dependencies", {})
        if not deps:
            return True  # No dependencies specified

        all_ok, errors, warnings = self.check_dependencies(deps)
        return all_ok

    def report(self) -> str:
        """Generate a human-readable report."""
        manifest = self.load_manifest()
        if not manifest:
            return f"ERROR: {self.errors[0]}"

        deps = manifest.get("dependencies", {})
        if not deps:
            return f"Plugin {self.plugin_name}: No dependencies specified"

        all_ok, errors, warnings = self.check_dependencies(deps)

        lines = []
        lines.append(f"Plugin: {self.plugin_name}")
        lines.append(f"Description: {manifest.get('description', 'N/A')}")
        lines.append("")

        if all_ok:
            lines.append("Status: All dependencies satisfied")
        else:
            lines.append("Status: MISSING DEPENDENCIES")
            lines.append("")
            lines.append("Errors:")
            for error in errors:
                for line in error.split('\n'):
                    lines.append(f"  {line}")

        if warnings:
            lines.append("")
            lines.append("Warnings:")
            for warning in warnings:
                lines.append(f"  {warning}")

        lines.append("")
        lines.append(f"For help: https://github.com/mbrg/raptor/issues")

        return "\n".join(lines)


def check_all_plugins() -> bool:
    """Check all plugins and report."""
    plugins_dir = Path(__file__).parent
    all_ok = True

    for plugin_dir in sorted(plugins_dir.iterdir()):
        if not plugin_dir.is_dir():
            continue
        if plugin_dir.name.startswith('.'):
            continue
        if not (plugin_dir / ".claude-plugin" / "plugin.json").exists():
            continue

        checker = DependencyChecker(plugin_dir.name)
        print(checker.report())
        print("-" * 60)

        if not checker.check():
            all_ok = False

    return all_ok


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 raptor-deps-check.py <plugin-name>")
        print("       python3 raptor-deps-check.py --all")
        sys.exit(1)

    arg = sys.argv[1]

    if arg == "--all":
        success = check_all_plugins()
        sys.exit(0 if success else 1)
    else:
        checker = DependencyChecker(arg)
        print(checker.report())
        sys.exit(0 if checker.check() else 1)


if __name__ == "__main__":
    main()
