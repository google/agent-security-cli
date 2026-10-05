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

"""Identity & Authentication Architecture Auditor for AI Agents."""

import ast
import re
from pathlib import Path
from typing import Any
from agent_security.models.findings import Finding, Severity


class IdentityAuditor:
    """Audits whether an agent uses Service Account ADC, Static Keys, or Delegated User Identity."""

    def __init__(self, project_dir: str | Path):
        self.project_dir = Path(project_dir).resolve()

    def audit_identity(self) -> dict[str, Any]:
        report = {
            "has_hardcoded_sa_keys": False,
            "uses_adc_service_account": False,
            "uses_delegated_user_identity": False,
            "has_ambient_authority_tools": False,
            "findings": [],
            "service_account_names": [],
        }

        # 1. Check for Static Service Account Keys (.json)
        json_keys = list(self.project_dir.rglob("*.json"))
        for jk in json_keys:
            if any(part in jk.parts for part in [".venv", "venv", ".git", "node_modules"]):
                continue
            try:
                content = jk.read_text(encoding="utf-8", errors="ignore")
                if '"type": "service_account"' in content and '"private_key":' in content:
                    report["has_hardcoded_sa_keys"] = True
                    report["findings"].append(
                        Finding(
                            rule_id="IAM-STATIC-KEY-01",
                            title="Hardcoded Service Account Private Key File",
                            description=f"Static Service Account key JSON detected: {jk.name}",
                            severity=Severity.CRITICAL,
                            file_path=str(jk.relative_to(self.project_dir)),
                            remediation="Delete static key file and use Workload Identity Federation or Cloud Run attached Service Accounts.",
                        )
                    )
            except Exception:
                continue

        # 2. Check Python code for ADC vs OAuth User Token Propagation
        py_files = list(self.project_dir.rglob("*.py"))
        for pf in py_files:
            if any(part in pf.parts for part in [".venv", "venv", ".git"]):
                continue
            try:
                content = pf.read_text(encoding="utf-8", errors="ignore")
                if "google.auth.default()" in content or "DefaultCredentials" in content:
                    report["uses_adc_service_account"] = True

                if "tool_context" in content or "user_token" in content or "oauth_token" in content:
                    report["uses_delegated_user_identity"] = True

                # Check if tool functions take raw user_id as an LLM argument without context injection
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        param_names = [a.arg for a in node.args.args]
                        if any(p in param_names for p in ["user_id", "account_id", "customer_id"]):
                            report["has_ambient_authority_tools"] = True
                            report["findings"].append(
                                Finding(
                                    rule_id="IAM-AMBIENT-AUTHORITY-02",
                                    title="Ambient Authority / IDOR in Tool Arguments",
                                    description=f"Tool '{node.name}' relies on model-provided identity ('{', '.join(p for p in param_names if 'id' in p)}') instead of verified session context.",
                                    severity=Severity.HIGH,
                                    file_path=str(pf.relative_to(self.project_dir)),
                                    line_number=node.lineno,
                                    remediation="Inject authenticated user identity from the API Gateway / OAuth token into tool_context rather than trusting model arguments.",
                                )
                            )
            except Exception:
                continue

        # 3. Check Terraform for Service Accounts
        tf_files = list(self.project_dir.rglob("*.tf"))
        for tf in tf_files:
            try:
                tf_content = tf.read_text(encoding="utf-8", errors="ignore")
                sa_matches = re.findall(r'resource\s+"google_service_account"\s+"([^"]+)"', tf_content)
                report["service_account_names"].extend(sa_matches)
            except Exception:
                continue

        return report
