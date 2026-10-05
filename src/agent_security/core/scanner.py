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

"""Static code and secret scanner for AI Agent codebases."""

import json
import os
import re
import subprocess
from pathlib import Path
from agent_security.models.findings import Finding, Severity

# Maximum file size to scan (5 MB) to prevent ReDoS / memory exhaustion
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# Static regex patterns for agent security checks
SECURITY_PATTERNS = [
    (
        r"AI" + r"zaSy[A-Za-z0-9_\-]{20,}",
        "detect-hardcoded-google-api-key",
        "Hardcoded Google API Key",
        Severity.CRITICAL,
        "Plaintext Google API key detected in code.",
        "Remove API key and use ADC (Application Default Credentials) or Google Cloud Secret Manager.",
    ),
    (
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
        "detect-hardcoded-private-key",
        "Hardcoded Private Key Certificate",
        Severity.CRITICAL,
        "Cryptographic private key detected in source code.",
        "Remove private key and store in Google Cloud Secret Manager or KMS.",
    ),
    (
        r"""(?i)[a-z0-9_]*api[_-]?key\s*=\s*["'][^"'\n]{8,}["']""",
        "detect-hardcoded-generic-api-key",
        "Hardcoded API Key Argument",
        Severity.HIGH,
        "Direct assignment of API key string parameter in model/agent initialization.",
        "Inject API key via environment variable (e.g. GEMINI_API_KEY) or Secret Manager.",
    ),
    (
        r"\b(?:pickle\.loads|yaml\.unsafe_load)\s*\(",
        "detect-insecure-deserialization",
        "Insecure Deserialization",
        Severity.CRITICAL,
        "Unsafe deserialization can execute arbitrary code on untrusted payloads.",
        "Use safe serialization formats like json or yaml.safe_load.",
    ),
    (
        r"\b(?:eval|exec)\s*\(",
        "detect-dynamic-code-execution",
        "Unsafe Dynamic Code Execution (eval/exec)",
        Severity.HIGH,
        "Dynamic code evaluation on LLM/user inputs allows remote code execution.",
        "Avoid eval/exec; use safe sandboxed tool interpreters (e.g. gVisor).",
    ),
    (
        r"(subprocess\.(?:Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True)",
        "detect-unsafe-shell-execution",
        "Unsafe Shell Execution (shell=True)",
        Severity.HIGH,
        "Direct execution of shell commands with shell=True invites command injection.",
        "Use list arguments without shell=True or guard via PreToolUse hooks.",
    ),
    (
        r"\bos\.system\s*\(",
        "detect-os-system-call",
        "Dangerous os.system Invocations",
        Severity.HIGH,
        "Raw os.system execution bypasses agent sandboxing.",
        "Avoid raw shell commands; route tools through typed ADK tools with pre-tool validation.",
    ),
]


class StaticScanner:
    """Scans agent project files for security violations and secret leaks."""

    def __init__(self, project_dir: str | Path):
        self.project_dir = Path(project_dir).resolve()

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Built-in AST / Regex Scanning across python files
        findings.extend(self._scan_regex())

        # 2. Run Semgrep if rules exist and semgrep is present
        semgrep_findings = self._scan_semgrep()
        if semgrep_findings:
            existing_locs = {(f.file_path, f.line_number) for f in findings}
            for sf in semgrep_findings:
                if (sf.file_path, sf.line_number) not in existing_locs:
                    findings.append(sf)

        return findings

    def _scan_regex(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.project_dir.is_file():
            py_files = [self.project_dir]
            base_dir = self.project_dir.parent
        else:
            py_files = list(self.project_dir.rglob("*.py"))
            base_dir = self.project_dir

        for file_path in py_files:
            # Prevent Symlink Traversal out of workspace
            try:
                real_file = file_path.resolve()
                if not real_file.is_relative_to(base_dir):
                    continue
            except Exception:
                continue

            # Skip virtual environments and hidden caches
            if any(part in file_path.parts for part in [".venv", "venv", ".git", "__pycache__", ".pytest_cache"]):
                continue

            # Skip large files (> 5MB)
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                for pattern, rule_id, title, severity, desc, remed in SECURITY_PATTERNS:
                    if re.search(pattern, line):
                        try:
                            rel_path = str(file_path.relative_to(self.project_dir))
                        except Exception:
                            rel_path = str(file_path)

                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                title=title,
                                description=desc,
                                severity=severity,
                                file_path=rel_path,
                                line_number=line_idx,
                                code_snippet=line.strip(),
                                remediation=remed,
                            )
                        )

        return findings

    def _scan_semgrep(self) -> list[Finding]:
        rules_path = self.project_dir / ".semgrep" / "rules.yaml"
        if not rules_path.exists():
            return []

        findings: list[Finding] = []
        try:
            cmd = ["semgrep", "scan", "--json", f"--config={rules_path}", str(self.project_dir)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.stdout:
                data = json.loads(res.stdout)
                for item in data.get("results", []):
                    sev_str = item.get("extra", {}).get("severity", "ERROR").upper()
                    sev = Severity.CRITICAL if sev_str == "ERROR" else Severity.MEDIUM
                    try:
                        rel_path = os.path.relpath(item.get("path", ""), str(self.project_dir))
                    except Exception:
                        rel_path = item.get("path", "")
                    findings.append(
                        Finding(
                            rule_id=item.get("check_id", "semgrep-rule"),
                            title="Semgrep Static Rule Violation",
                            description=item.get("extra", {}).get("message", "Rule violation detected."),
                            severity=sev,
                            file_path=rel_path,
                            line_number=item.get("start", {}).get("line"),
                            code_snippet=item.get("extra", {}).get("lines", "").strip(),
                            remediation="Remediate code per the configured Semgrep rule guideline.",
                        )
                    )
        except Exception:
            pass

        return findings
