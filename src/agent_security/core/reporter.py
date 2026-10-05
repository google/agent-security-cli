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

"""Report generation and Google Cloud Storage export engine."""

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from agent_security.models.findings import AuditReport

# Strict GCS URI validation regex (prevents flag injection / parameter tampering)
GCS_URI_REGEX = re.compile(r"^gs://[a-z0-9][a-z0-9._\-]{1,61}[a-z0-9](/[a-zA-Z0-9._\-/]*)?/?$")


class Reporter:
    """Generates structured Markdown/JSON reports and handles Cloud exports."""

    @staticmethod
    def generate_markdown(report: AuditReport) -> str:
        md = []
        md.append(f"# Agent Security Audit Report: {report.project_name}")
        md.append(f"**Audit Timestamp:** {report.timestamp}  ")
        md.append(f"**Target Project Path:** `{report.project_path}`  ")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 1. Executive Summary")
        md.append("```")
        md.append(
            f"Static Findings: {len(report.static_findings)} | "
            f"STRIDE Threats: {len(report.stride_threats)} | "
            f"Prompt Guard: {sum(1 for p in report.prompt_guard_results if p.safe)}/{len(report.prompt_guard_results)} safe | "
            f"MCP Risks: {len(report.mcp_findings)} | "
            f"Unshielded Mutating Tools: {len(report.hitl_findings)} | "
            f"IAM Findings: {len(report.iam_findings)} | "
            f"Hook Tests: {sum(1 for h in report.hook_tests if h.passed)}/{len(report.hook_tests)} | "
            f"Pytest: {'PASSED' if report.test_suite_passed else 'FAILED'}"
        )
        md.append("```")
        md.append("")

        # 2. Static Findings
        md.append("## 2. Static Security Findings")
        if not report.static_findings:
            md.append("✅ *No static security vulnerabilities or secret leaks detected.*")
        else:
            md.append("| Severity | Rule ID | File Location | Finding & Remediation |")
            md.append("| :--- | :--- | :--- | :--- |")
            for f in report.static_findings:
                loc = f"`{f.file_path}:{f.line_number}`" if f.line_number else f"`{f.file_path}`"
                md.append(f"| **{f.severity.value}** | `{f.rule_id}` | {loc} | **{f.title}**<br>{f.description}<br>*Remediation:* {f.remediation} |")
        md.append("")

        # 3. STRIDE Threats
        md.append("## 3. STRIDE Threat Model Assessment")
        if not report.stride_threats:
            md.append("✅ *No architectural STRIDE threats identified.*")
        else:
            md.append("| Category | Threat ID | Component | Severity | Description & Fix |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for t in report.stride_threats:
                md.append(f"| **{t.category}** | `{t.threat_id}` | `{t.target_component}` | **{t.severity.value}** | {t.description}<br>*Fix:* {t.remediation} |")
        md.append("")

        # 4. Prompt Guard
        md.append("## 4. Prompt Guard & Cognitive Injection Defense")
        if not report.prompt_guard_results:
            md.append("✅ *No prompt guard evaluations executed.*")
        else:
            md.append("| Status | Test ID | Attack Vector | Safety Assessment & Remediation |")
            md.append("| :--- | :--- | :--- | :--- |")
            for p in report.prompt_guard_results:
                status_icon = "✅ PASSED" if p.safe else "❌ FLAGGED"
                md.append(f"| {status_icon} | `{p.test_id}` | **{p.attack_category}** | {p.reason}<br>*Remediation:* {p.remediation} |")
        md.append("")

        # 5. MCP Server Security
        md.append("## 5. Model Context Protocol (MCP) Security Audit")
        if not report.mcp_findings:
            md.append("✅ *No MCP configuration vulnerabilities or SSRF vectors detected.*")
        else:
            md.append("| Severity | Server Name | Endpoint / Command | Risk & Remediation |")
            md.append("| :--- | :--- | :--- | :--- |")
            for m in report.mcp_findings:
                md.append(f"| **{m.severity.value}** | `{m.server_name}` | `{m.endpoint_or_command}` | {m.risk_description}<br>*Fix:* {m.remediation} |")
        md.append("")

        # 6. Human-In-The-Loop (HITL) Verification
        md.append("## 6. Human-In-The-Loop (HITL) Mutating Tool Verification")
        if not report.hitl_findings:
            md.append("✅ *All state-modifying actions have Human-In-The-Loop approval gates verified.*")
        else:
            md.append("| Severity | Tool Name | Mutation Type | Location | Remediation |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for h in report.hitl_findings:
                md.append(f"| **{h.severity.value}** | `{h.tool_name}` | `{h.mutating_action.upper()}` | `{h.file_path}:{h.line_number}` | {h.remediation} |")
        md.append("")

        # 7. IAM & Agent Identity Architecture
        md.append("## 7. IAM & Agent Identity Architecture")
        if not report.iam_findings and not report.iam_summary:
            md.append("✅ *No IAM or authentication architecture risks detected.*")
        else:
            if report.iam_summary:
                md.append("### Identity Configuration Matrix")
                md.append("| Architecture Component | Status / Assessment |")
                md.append("| :--- | :--- |")
                md.append(f"| Static SA Keys | {'❌ Hardcoded Key Present' if report.iam_summary.get('has_hardcoded_sa_keys') else '✅ Clean (No static keys)'} |")
                md.append(f"| Service Account ADC | {'✅ Enabled (Application Default Credentials)' if report.iam_summary.get('uses_adc_service_account') else '⚠️ Not detected explicitly'} |")
                md.append(f"| Delegated User Identity | {'✅ Enabled (OAuth / Tool Context propagation)' if report.iam_summary.get('uses_delegated_user_identity') else '❌ Missing (Ambient Authority)'} |")
                md.append(f"| Tool Identity Gating | {'❌ Risky (Accepts raw model user_id)' if report.iam_summary.get('has_ambient_authority_tools') else '✅ Secure (No unverified model identity args)'} |")
                md.append("")

            if report.iam_findings:
                md.append("### IAM Vulnerability Findings")
                md.append("| Severity | Rule ID | File Location | Finding & Remediation |")
                md.append("| :--- | :--- | :--- | :--- |")
                for f in report.iam_findings:
                    loc = f"`{f.file_path}:{f.line_number}`" if f.line_number else f"`{f.file_path}`"
                    md.append(f"| **{f.severity.value}** | `{f.rule_id}` | {loc} | **{f.title}**<br>{f.description}<br>*Remediation:* {f.remediation} |")
                md.append("")
            else:
                md.append("✅ *No IAM vulnerability findings detected.*")
                md.append("")

        # 8. PreToolUse Dynamic Hook Tests
        md.append("## 8. PreToolUse Dynamic Hook Gating")
        md.append("| Status | Test Scenario | Decision | Reason / Output |")
        md.append("| :--- | :--- | :--- | :--- |")
        for h in report.hook_tests:
            status_icon = "✅ PASSED" if h.passed else "❌ FAILED"
            md.append(f"| {status_icon} | {h.description} | `{h.decision.upper()}` | {h.reason or 'Allowed by policy'} |")
        md.append("")

        # 9. Outcome Test Suite
        md.append("## 9. Security Test Suite Execution")
        md.append(f"**Overall Status:** {'✅ PASSED' if report.test_suite_passed else '❌ FAILED'}")
        if report.test_suite_output:
            md.append("```text")
            md.append(report.test_suite_output.strip())
            md.append("```")

        return "\n".join(md)

    @staticmethod
    def export_to_gcs(local_file: str | Path, gcs_uri: str) -> tuple[bool, str]:
        """Uploads a local report file to a Google Cloud Storage URI."""
        local_path = Path(local_file).resolve()
        if not local_path.exists():
            return False, f"Local file not found: {local_path}"

        if not GCS_URI_REGEX.match(gcs_uri.strip()):
            return False, f"Security Violation: Invalid or unsafe GCS URI '{gcs_uri}'."

        cmd_bin = "gcloud" if shutil.which("gcloud") else "gsutil"
        if cmd_bin == "gcloud":
            cmd = ["gcloud", "storage", "cp", str(local_path), gcs_uri]
        else:
            cmd = ["gsutil", "cp", str(local_path), gcs_uri]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                return True, f"Successfully uploaded {local_path.name} to {gcs_uri}"
            return False, f"GCS upload failed: {res.stderr or res.stdout}"
        except Exception as e:
            return False, f"GCS export error: {e}"
