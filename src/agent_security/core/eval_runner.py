# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test runner for outcome-based security test suites."""

import shutil
import subprocess
import sys
from pathlib import Path


class SecurityEvalRunner:
    """Discovers and executes security boundary pytest suites."""

    def __init__(self, project_dir: str | Path):
        self.project_dir = Path(project_dir).resolve()

    def run_tests(self, test_file: str | None = None) -> tuple[bool, str]:
        # Determine pytest executable (prefer project .venv or active interpreter to avoid network index syncs)
        venv_pytest = self.project_dir / ".venv" / "bin" / "pytest"
        if venv_pytest.exists():
            cmd = [str(venv_pytest), "-v"]
        elif shutil.which("pytest"):
            cmd = ["pytest", "-v"]
        elif sys.executable:
            cmd = [sys.executable, "-m", "pytest", "-v"]
        elif shutil.which("uv"):
            cmd = ["uv", "run", "--no-sync", "pytest", "-v"]
        else:
            cmd = ["pytest", "-v"]

        if test_file:
            # Defend against path traversal in test_file parameter
            target_path = (self.project_dir / test_file).resolve()
            if not target_path.is_relative_to(self.project_dir):
                return False, f"Security Violation: Target test_file '{test_file}' resolves outside project root."
            if not target_path.exists():
                return False, f"Test file not found: {test_file}"
            cmd.append(str(target_path.relative_to(self.project_dir)))
        else:
            if (self.project_dir / "tests" / "test_agent.py").exists():
                cmd.append("tests/test_agent.py")
            elif (self.project_dir / "tests").exists():
                cmd.append("tests")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(self.project_dir),
            )
            output = res.stdout or res.stderr
            passed = res.returncode == 0
            return passed, output
        except Exception as e:
            return False, f"Failed to execute pytest suite: {e}"
