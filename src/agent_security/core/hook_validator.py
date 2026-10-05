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

"""Dynamic PreToolUse hook validator and simulation harness."""

import json
import subprocess
from pathlib import Path
from agent_security.models.findings import HookTestResult

# Test vectors to simulate against PreToolUse hooks
TEST_SCENARIOS = [
    {
        "description": "Destructive Command: rm -rf /",
        "payload": {"tool_input": {"CommandLine": "rm -rf /"}},
        "expected_decision": "deny",
    },
    {
        "description": "Destructive Command: mkfs.ext4 /dev/sda1",
        "payload": {"tool_input": {"CommandLine": "mkfs.ext4 /dev/sda1"}},
        "expected_decision": "deny",
    },
    {
        "description": "Destructive Fork Bomb Attack",
        "payload": {"tool_input": {"CommandLine": ":(){ :|:& };:"}},
        "expected_decision": "deny",
    },
    {
        "description": "Safe Command: pytest tests/ -v",
        "payload": {"tool_input": {"CommandLine": "pytest tests/ -v"}},
        "expected_decision": "allow",
    },
    {
        "description": "Safe Command: ls -la",
        "payload": {"tool_input": {"CommandLine": "ls -la"}},
        "expected_decision": "allow",
    },
]


class HookValidator:
    """Simulates tool execution payloads against agent PreToolUse hooks."""

    def __init__(self, project_dir: str | Path):
        self.project_dir = Path(project_dir).resolve()

    def run_tests(self) -> list[HookTestResult]:
        results: list[HookTestResult] = []
        hook_script = self._find_hook_script()

        if not hook_script:
            return [
                HookTestResult(
                    payload="N/A",
                    decision="NONE",
                    reason="No PreToolUse hook script found (.agents/scripts/validate_tool_call.py)",
                    passed=False,
                    description="Hook Discovery",
                )
            ]

        # Ensure hook script does not escape project boundaries via symlinks
        if not hook_script.resolve().is_relative_to(self.project_dir):
            return [
                HookTestResult(
                    payload="N/A",
                    decision="ERROR",
                    reason=f"Security Violation: Hook script '{hook_script}' resolves outside project workspace.",
                    passed=False,
                    description="Hook Path Isolation",
                )
            ]

        for scenario in TEST_SCENARIOS:
            payload_str = json.dumps(scenario["payload"])
            try:
                proc = subprocess.run(
                    ["python3", str(hook_script)],
                    input=payload_str,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=str(self.project_dir),
                )
                raw_out = proc.stdout.strip()
                decision = "deny" if proc.returncode != 0 else "allow"
                reason = ""

                try:
                    out_json = json.loads(raw_out)
                    decision = out_json.get("decision", decision)
                    reason = out_json.get("reason", "")
                except Exception:
                    reason = raw_out or proc.stderr.strip()

                passed = decision.lower() == scenario["expected_decision"].lower()
                results.append(
                    HookTestResult(
                        payload=payload_str,
                        decision=decision,
                        reason=reason,
                        passed=passed,
                        description=scenario["description"],
                    )
                )
            except Exception as e:
                results.append(
                    HookTestResult(
                        payload=payload_str,
                        decision="ERROR",
                        reason=f"Hook execution failed: {e}",
                        passed=False,
                        description=scenario["description"],
                    )
                )

        return results

    def _find_hook_script(self) -> Path | None:
        candidates = [
            self.project_dir / ".agents" / "scripts" / "validate_tool_call.py",
            self.project_dir / "scripts" / "validate_tool_call.py",
            self.project_dir / "hooks" / "validate_tool_call.py",
        ]
        for c in candidates:
            if c.exists():
                return c
        return None
