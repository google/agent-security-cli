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

"""Human-In-The-Loop (HITL) and Excessive Agency AST validator for mutating agent tools."""

import ast
import re
from pathlib import Path
from agent_security.models.findings import HITLFinding, Severity

# Action keywords that represent high-impact, irreversible mutations
MUTATING_KEYWORDS = ("delete", "remove", "refund", "payout", "transfer", "grant", "drop", "terminate", "purchase", "execute_payment")
HITL_PATTERNS = ("approval", "confirm", "hitl", "human_in_the_loop", "interrupt", "verify_token", "require_confirmation")


class HITLValidator:
    """Audits agent tool functions for missing Human-In-The-Loop authorization gates."""

    def __init__(self, project_dir: str | Path):
        self.project_dir = Path(project_dir).resolve()

    def validate(self) -> list[HITLFinding]:
        findings: list[HITLFinding] = []
        if self.project_dir.is_file():
            py_files = [self.project_dir]
            base_dir = self.project_dir.parent
        else:
            py_files = list(self.project_dir.rglob("*.py"))
            base_dir = self.project_dir

        for file_path in py_files:
            if any(part in file_path.parts for part in [".venv", "venv", ".git", "__pycache__", ".pytest_cache"]):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(content)
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    fn_name_lower = node.name.lower()
                    matched_action = next((kw for kw in MUTATING_KEYWORDS if kw in fn_name_lower), None)

                    if matched_action:
                        # Inspect function body for HITL guard or confirmation
                        fn_source = ast.get_source_segment(content, node) or ""
                        has_hitl = any(pat in fn_source.lower() for pat in HITL_PATTERNS)

                        if not has_hitl:
                            try:
                                rel_path = str(file_path.relative_to(base_dir))
                            except Exception:
                                rel_path = str(file_path.name)
                            findings.append(
                                HITLFinding(
                                    tool_name=node.name,
                                    file_path=rel_path,
                                    line_number=node.lineno,
                                    mutating_action=matched_action,
                                    has_hitl_gate=False,
                                    severity=Severity.HIGH,
                                    remediation=f"Tool performs high-impact mutation ('{matched_action}'). Enforce Human-In-The-Loop approval gate or confirmation token verification.",
                                )
                            )

        return findings
