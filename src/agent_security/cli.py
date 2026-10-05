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

"""Click / Typer CLI dispatcher for Agent Security & Quality Engineering."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import click
from rich.panel import Panel
from rich.table import Table

from agent_security.core.eval_runner import SecurityEvalRunner
from agent_security.core.hitl_validator import HITLValidator
from agent_security.core.hook_validator import HookValidator
from agent_security.core.identity_auditor import IdentityAuditor
from agent_security.core.mcp_auditor import MCPAuditor
from agent_security.core.prompt_guard import PromptGuard
from agent_security.core.reporter import Reporter
from agent_security.core.scanner import StaticScanner
from agent_security.core.threat_modeler import STRIDEThreatModeler
from agent_security.models.findings import AuditReport
from agent_security.ui.console import (
    console,
    get_severity_badge,
    print_banner,
    render_findings_table,
    render_hitl_findings_table,
    render_hook_tests_table,
    render_mcp_findings_table,
    render_prompt_guard_table,
    render_stride_table,
)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.2.0", prog_name="agent-security")
def cli():
    """Enterprise AI Agent Security & Evaluation CLI."""
    pass


@cli.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Output findings as JSON.")
def scan_cmd(path: str, json_output: bool):
    """Scan agent code for hardcoded secrets, unsafe shell calls, and Semgrep rules."""
    if not json_output:
        print_banner()
        console.print(f"[bold]🔍 Scanning agent project at:[/bold] [dim]{Path(path).resolve()}[/dim]\n")

    scanner = StaticScanner(path)
    findings = scanner.scan()

    if json_output:
        print(json.dumps([f.model_dump() for f in findings], indent=2))
        sys.exit(1 if any(f.severity.value in ["CRITICAL", "HIGH"] for f in findings) else 0)

    render_findings_table(findings)
    if any(f.severity.value in ["CRITICAL", "HIGH"] for f in findings):
        console.print("[bold red]❌ Blocking security findings detected![/bold red]")
        sys.exit(1)


@cli.command("threat-model")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, type=click.Path(), help="Output path for threat_model.md")
def threat_model_cmd(path: str, output: str | None):
    """Run automated STRIDE threat modeling on agent components and tools."""
    print_banner()
    console.print(f"[bold]🛡️  Performing STRIDE Threat Assessment on:[/bold] [dim]{Path(path).resolve()}[/dim]\n")

    modeler = STRIDEThreatModeler(path)
    threats = modeler.analyze()

    render_stride_table(threats)

    if output:
        out_path = Path(output).resolve()
        content = [f"# STRIDE Threat Model: {Path(path).name}\n"]
        for t in threats:
            content.append(f"### [{t.category}] {t.threat_id}: {t.target_component}\n- **Severity:** {t.severity.value}\n- **Description:** {t.description}\n- **Remediation:** {t.remediation}\n")
        out_path.write_text("\n".join(content), encoding="utf-8")
        console.print(f"[green]Saved STRIDE assessment to: {out_path}[/green]")


@cli.command("prompt-guard")
@click.argument("path", default=".", type=click.Path(exists=True))
def prompt_guard_cmd(path: str):
    """Evaluate prompt injection, system prompt extraction, and crescendo defenses."""
    print_banner()
    console.print(f"[bold]🛡️  Running Prompt Guard Evaluation on:[/bold] [dim]{Path(path).resolve()}[/dim]\n")

    guard = PromptGuard(path)
    results = guard.evaluate_instructions()
    render_prompt_guard_table(results)

    if not all(r.safe for r in results):
        console.print("[bold yellow]⚠️  Prompt Guard identified instruction weaknesses.[/bold yellow]")


@cli.command("mcp-check")
@click.argument("path", default=".", type=click.Path(exists=True))
def mcp_check_cmd(path: str):
    """Audit Model Context Protocol (MCP) servers for SSRF and insecure transport."""
    print_banner()
    console.print(f"[bold]🌐 Auditing Model Context Protocol (MCP) Configurations at:[/bold] [dim]{Path(path).resolve()}[/dim]\n")

    auditor = MCPAuditor(path)
    findings = auditor.audit()
    render_mcp_findings_table(findings)


@cli.command("hitl-check")
@click.argument("path", default=".", type=click.Path(exists=True))
def hitl_check_cmd(path: str):
    """Verify Human-In-The-Loop approval gates on mutating and high-impact tools."""
    print_banner()
    console.print(f"[bold]👤 Checking Human-In-The-Loop (HITL) Gates at:[/bold] [dim]{Path(path).resolve()}[/dim]\n")

    validator = HITLValidator(path)
    findings = validator.validate()
    render_hitl_findings_table(findings)


@cli.command("iam-check")
@click.argument("path", default=".", type=click.Path(exists=True))
def iam_check_cmd(path: str):
    """Audit whether the agent uses Service Account ADC, Static Keys, or Delegated User Identity."""
    print_banner()
    console.print(f"[bold]🔑 Auditing IAM & Agent Identity Architecture at:[/bold] [dim]{Path(path).resolve()}[/dim]\n")

    auditor = IdentityAuditor(path)
    res = auditor.audit_identity()

    table = Table(title="IAM & Identity Architecture Findings", show_header=True, header_style="bold green")
    table.add_column("Architecture Component", style="bold", width=30)
    table.add_column("Status / Assessment", width=50)

    # 1. Static Keys
    if res["has_hardcoded_sa_keys"]:
        table.add_row("Static SA Keys", "[bold red]CRITICAL: Hardcoded .json Service Account key found[/bold red]")
    else:
        table.add_row("Static SA Keys", "[bold green]✅ Clean: No static service account keys found[/bold green]")

    # 2. Service Account ADC
    if res["uses_adc_service_account"]:
        table.add_row("Service Account ADC", "[bold green]✅ Present: Uses Application Default Credentials (ADC)[/bold green]")
    else:
        table.add_row("Service Account ADC", "[yellow]⚠️  Not detected explicitly[/yellow]")

    # 3. Delegated User Identity
    if res["uses_delegated_user_identity"]:
        table.add_row("Delegated User Identity", "[bold green]✅ Present: Tool context / OAuth token propagation enabled[/bold green]")
    else:
        table.add_row("Delegated User Identity", "[bold red]❌ Missing: Agent operates via Ambient Authority (No tool context propagation)[/bold red]")

    # 4. Ambient Authority
    if res["has_ambient_authority_tools"]:
        table.add_row("Tool Identity Gating", "[bold red]❌ Risky: Tools accept plain user_id arguments from model[/bold red]")
    else:
        table.add_row("Tool Identity Gating", "[bold green]✅ Secure: Tools do not trust raw model identity arguments[/bold green]")

    console.print(table)
    console.print()

    if res["findings"]:
        render_findings_table(res["findings"])


@cli.command("hook-check")
@click.argument("path", default=".", type=click.Path(exists=True))
def hook_check_cmd(path: str):
    """Simulate destructive and safe payloads against PreToolUse hooks."""
    print_banner()
    console.print(f"[bold]🪝 Validating PreToolUse Hooks at:[/bold] [dim]{Path(path).resolve()}[/dim]\n")

    validator = HookValidator(path)
    results = validator.run_tests()
    render_hook_tests_table(results)

    if not all(r.passed for r in results):
        console.print("[bold red]❌ PreToolUse Hook safety tests failed![/bold red]")
        sys.exit(1)


@cli.command("test")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--test-file", "-f", default=None, help="Specific test file to execute.")
def test_cmd(path: str, test_file: str | None):
    """Execute outcome-based security test suites (pytest)."""
    print_banner()
    console.print(f"[bold]🧪 Running Security Boundary Test Suite at:[/bold] [dim]{Path(path).resolve()}[/dim]\n")

    runner = SecurityEvalRunner(path)
    passed, output = runner.run_tests(test_file)

    console.print(Panel(output.strip(), title="Pytest Execution Output", border_style="green" if passed else "red"))

    if not passed:
        console.print("[bold red]❌ Security test suite failed![/bold red]")
        sys.exit(1)
    else:
        console.print("[bold green]✅ All outcome security assertions passed![/bold green]")


@cli.command("audit")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--to-gcs", default=None, help="Export comprehensive audit report to GCS URI (e.g. gs://bucket/path/)")
@click.option("--output-file", "-o", default=None, help="Save report to local Markdown file.")
def audit_cmd(path: str, to_gcs: str | None, output_file: str | None):
    """Run full end-to-end security audit pipeline and export report."""
    print_banner()
    target_path = Path(path).resolve()
    console.print(f"[bold]🛡️  Executing Full Agent Security Audit on:[/bold] [dim]{target_path}[/dim]\n")

    # 1. Static Scan
    console.print("[bold cyan]1/8. Running Static Secret & Code Scanner...[/bold cyan]")
    scanner = StaticScanner(target_path)
    static_findings = scanner.scan()

    # 2. STRIDE Threat Modeling
    console.print("[bold cyan]2/8. Running STRIDE Threat Modeler...[/bold cyan]")
    threat_modeler = STRIDEThreatModeler(target_path)
    stride_threats = threat_modeler.analyze()

    # 3. Prompt Guard
    console.print("[bold cyan]3/8. Running Prompt Guard Evaluation...[/bold cyan]")
    prompt_guard = PromptGuard(target_path)
    prompt_guard_results = prompt_guard.evaluate_instructions()

    # 4. MCP Server Security Audit
    console.print("[bold cyan]4/8. Auditing Model Context Protocol (MCP) Configurations...[/bold cyan]")
    mcp_auditor = MCPAuditor(target_path)
    mcp_findings = mcp_auditor.audit()

    # 5. Human-In-The-Loop Verification
    console.print("[bold cyan]5/8. Validating Human-In-The-Loop (HITL) Mutating Gates...[/bold cyan]")
    hitl_validator = HITLValidator(target_path)
    hitl_findings = hitl_validator.validate()

    # 6. IAM & Identity Architecture Audit
    console.print("[bold cyan]6/8. Auditing IAM & Agent Identity Architecture...[/bold cyan]")
    identity_auditor = IdentityAuditor(target_path)
    iam_res = identity_auditor.audit_identity()
    iam_findings = iam_res.get("findings", [])

    # 7. PreToolUse Dynamic Hook Tests
    console.print("[bold cyan]7/8. Validating PreToolUse Security Hooks...[/bold cyan]")
    hook_validator = HookValidator(target_path)
    hook_tests = hook_validator.run_tests()

    # 8. Outcome-Based Security Test Suite
    console.print("[bold cyan]8/8. Running Outcome-Based Security Test Suite...[/bold cyan]")
    eval_runner = SecurityEvalRunner(target_path)
    test_passed, test_out = eval_runner.run_tests()
    console.print(f"Test Suite Status: [bold {'green' if test_passed else 'red'}]{'PASSED' if test_passed else 'FAILED'}[/bold {'green' if test_passed else 'red'}]\n")

    # Build Audit Report
    report = AuditReport(
        project_name=target_path.name,
        project_path=str(target_path),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        static_findings=static_findings,
        stride_threats=stride_threats,
        prompt_guard_results=prompt_guard_results,
        mcp_findings=mcp_findings,
        hitl_findings=hitl_findings,
        iam_findings=iam_findings,
        iam_summary=iam_res,
        hook_tests=hook_tests,
        test_suite_passed=test_passed,
        test_suite_output=test_out,
    )

    # Render Terminal Summary Tables
    render_findings_table(static_findings)
    render_stride_table(stride_threats)
    render_prompt_guard_table(prompt_guard_results)
    render_mcp_findings_table(mcp_findings)
    render_hitl_findings_table(hitl_findings)
    if iam_findings:
        render_findings_table(iam_findings)
    render_hook_tests_table(hook_tests)

    # Generate Markdown Report
    report_md = Reporter.generate_markdown(report)
    out_file = Path(output_file).resolve() if output_file else (target_path / "AGENT_SECURITY_AUDIT_REPORT.md")
    out_file.write_text(report_md, encoding="utf-8")
    console.print(f"[bold green]📄 Full Audit Report generated:[/bold green] {out_file}")

    # GCS Export if specified
    if to_gcs:
        target_gcs_uri = to_gcs if to_gcs.endswith(".md") else f"{to_gcs.rstrip('/')}/{out_file.name}"
        console.print(f"[bold blue]☁️  Exporting audit report to GCS:[/bold blue] {target_gcs_uri}...")
        ok, msg = Reporter.export_to_gcs(out_file, target_gcs_uri)
        if ok:
            console.print(f"[bold green]✅ {msg}[/bold green]\n")
        else:
            console.print(f"[bold red]❌ {msg}[/bold red]\n")

    # Evaluate Overall Pass/Fail
    blocking_static = any(f.severity.value in ["CRITICAL", "HIGH"] for f in static_findings)
    blocking_iam = any(f.severity.value in ["CRITICAL", "HIGH"] for f in iam_findings)
    blocking_hooks = not all(h.passed for h in hook_tests)
    if blocking_static or blocking_iam or blocking_hooks or not test_passed:
        console.print("[bold red]⛔ AUDIT FAILED: One or more security controls or tests failed.[/bold red]")
        sys.exit(1)
    else:
        console.print("[bold green]🎉 AUDIT PASSED: All enterprise security boundaries verified.[/bold green]")


@cli.command("info")
def info_cmd():
    """Display active security toolchain capabilities and inspection modules."""
    print_banner()
    table = Table(title="Agent Security Toolchain & Capabilities", show_header=True, header_style="bold cyan")
    table.add_column("Capability", style="bold", width=25)
    table.add_column("Details / Underlying Technology", width=55)

    table.add_row("Static Code & Secret Scanner", "Regex + Semgrep rules (API keys, os.system, shell=True)")
    table.add_row("STRIDE Threat Modeler", "AST inspection for unverified user_id, in-memory races, missing RBAC")
    table.add_row("Prompt Guard Red-Team", "Simulates prompt injection, extraction, and crescendo drift attacks")
    table.add_row("MCP Server Auditor", "Audits Model Context Protocol server endpoints for SSRF & unpinned tools")
    table.add_row("Human-In-The-Loop (HITL)", "AST verification of approval gates on mutating tool functions")
    table.add_row("PreToolUse Dynamic Interceptor", "Simulates test vectors against `.agents/scripts/validate_tool_call.py`")
    table.add_row("Outcome-Based Security Tests", "Pytest automated execution for single-use coupons & identity gates")
    table.add_row("Google Cloud Storage Export", "Integrated `gcloud storage` / `gsutil` multi-cloud export engine")

    console.print(table)
    console.print()


if __name__ == "__main__":
    cli()
