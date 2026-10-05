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

"""Automated STRIDE Threat Modeling Engine for Agentic Architectures."""

import ast
import re
from pathlib import Path
from agent_security.models.findings import STRIDEThreat, Severity

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


class STRIDEThreatModeler:
    """Performs AST-driven STRIDE threat modeling against agent tool definitions."""

    def __init__(self, project_dir: str | Path):
        self.project_dir = Path(project_dir).resolve()

    def analyze(self) -> list[STRIDEThreat]:
        threats: list[STRIDEThreat] = []
        py_files = list(self.project_dir.rglob("*.py"))

        for file_path in py_files:
            try:
                real_file = file_path.resolve()
                if not real_file.is_relative_to(self.project_dir):
                    continue
            except Exception:
                continue

            if any(part in file_path.parts for part in [".venv", "venv", ".git", "__pycache__", ".pytest_cache"]):
                continue

            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(content)
            except Exception:
                continue

            try:
                rel_path = str(file_path.relative_to(self.project_dir))
            except Exception:
                rel_path = str(file_path)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # 1. Spoofing: Check for IDOR vulnerabilities (untrusted user_id in model args)
                    param_names = [arg.arg for arg in node.args.args]
                    if any(p in param_names for p in ["user_id", "caller_id", "account_id", "tenant_id"]):
                        threats.append(
                            STRIDEThreat(
                                category="Spoofing",
                                threat_id="TM-SPOOF-01",
                                target_component=f"{rel_path}:{node.name}",
                                severity=Severity.HIGH,
                                description=f"Function '{node.name}' accepts caller identity as a tool argument ({', '.join(p for p in param_names if 'id' in p)}). Susceptible to IDOR spoofing.",
                                remediation="Inject caller identity from authenticated JWT/OAuth session context rather than LLM-generated arguments.",
                            )
                        )

                    # 2. Tampering: Global mutable state modifications
                    for child in ast.walk(node):
                        if isinstance(child, ast.Subscript) and isinstance(child.ctx, ast.Store):
                            threats.append(
                                STRIDEThreat(
                                    category="Tampering",
                                    threat_id="TM-TAMP-02",
                                    target_component=f"{rel_path}:{node.name}",
                                    severity=Severity.HIGH,
                                    description=f"In-memory state mutation detected in tool '{node.name}'. Vulnerable to concurrent race conditions.",
                                    remediation="Use transactional storage (Cloud SQL, AlloyDB, Datastore) with ACID optimistic locking.",
                                )
                            )
                            break

                    # 3. Elevation of Privilege: Privileged functions lacking auth gates
                    if any(prefix in node.name.lower() for prefix in ["admin_", "sudo_", "grant_", "override_"]):
                        threats.append(
                            STRIDEThreat(
                                category="Elevation of Privilege",
                                threat_id="TM-ELEV-05",
                                target_component=f"{rel_path}:{node.name}",
                                severity=Severity.CRITICAL,
                                description=f"Privileged method '{node.name}' detected without explicit RBAC role validation decorator.",
                                remediation="Enforce role-based access control (RBAC) and human-in-the-loop verification.",
                            )
                        )

                # 4. Denial of Service: Unbounded while loops in agent execution nodes
                elif isinstance(node, ast.While):
                    if isinstance(node.test, ast.Constant) and node.test.value is True:
                        threats.append(
                            STRIDEThreat(
                                category="Denial of Service",
                                threat_id="TM-DOS-04",
                                target_component=f"{rel_path}:line_{node.lineno}",
                                severity=Severity.MEDIUM,
                                description=f"Unbounded 'while True' loop detected at line {node.lineno}. Risk of infinite reasoning loop and Denial of Wallet.",
                                remediation="Set explicit recursion limits (e.g. max_iterations = 10) and execution timeouts.",
                            )
                        )

            # 5. Information Disclosure: Hardcoded keys
            api_key_pattern = r"""(?i)[a-z0-9_]*api[_-]?key\s*=\s*["'][^"'\n]{8,}["']"""
            if re.search(api_key_pattern, content) or ("AIza" + "Sy") in content:
                threats.append(
                    STRIDEThreat(
                        category="Information Disclosure",
                        threat_id="TM-INFO-03",
                        target_component=f"{rel_path}",
                        severity=Severity.CRITICAL,
                        description="Plaintext credentials or hardcoded API key signature present in source file.",
                        remediation="Store secrets in Google Cloud Secret Manager and inject at runtime via environment variables.",
                    )
                )

        return threats
