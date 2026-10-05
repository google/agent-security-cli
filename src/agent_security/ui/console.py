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

"""Rich UI and terminal styling helpers for Agent Security CLI."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from agent_security.models.findings import (
    Finding,
    HITLFinding,
    HookTestResult,
    MCPAuditFinding,
    PromptGuardResult,
    Severity,
    STRIDEThreat,
)

console = Console()


def print_banner() -> None:
    """Prints the Agent Security CLI banner."""
    banner_text = Text()
    banner_text.append("🛡️  Agent Security CLI ", style="bold cyan")
    banner_text.append("v0.2.0\n", style="dim")
    banner_text.append("Enterprise Shift-Left Security & STRIDE Threat Evaluation", style="italic")
    console.print(Panel(banner_text, border_style="cyan", padding=(0, 2)))


def get_severity_badge(sev: Severity | str) -> str:
    """Returns a colored severity badge."""
    val = sev.value if isinstance(sev, Severity) else str(sev).upper()
    if val == "CRITICAL":
        return "[bold white on red] CRITICAL [/bold white on red]"
    elif val == "HIGH":
        return "[bold white on dark_orange] HIGH [/bold white on dark_orange]"
    elif val == "MEDIUM":
        return "[bold black on yellow] MEDIUM [/bold black on yellow]"
    elif val == "LOW":
        return "[bold white on blue] LOW [/bold white on blue]"
    return "[bold white on grey50] INFO [/bold white on grey50]"


def render_findings_table(findings: list[Finding]) -> None:
    """Renders static code findings in a formatted Rich table."""
    if not findings:
        console.print("[bold green]✅ No static security vulnerabilities detected![/bold green]\n")
        return

    table = Table(title="Static Security Findings", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Rule ID", style="cyan", no_wrap=False)
    table.add_column("Location", style="dim", no_wrap=False)
    table.add_column("Finding & Remediation", no_wrap=False)

    for f in findings:
        loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
        desc = f"[bold]{f.title}[/bold]\n{f.description}\n[green]Remediation: {f.remediation}[/green]"
        table.add_row(get_severity_badge(f.severity), f.rule_id, loc, desc)

    console.print(table)
    console.print()


def render_stride_table(threats: list[STRIDEThreat]) -> None:
    """Renders STRIDE threats in a table."""
    if not threats:
        console.print("[bold green]✅ No STRIDE threats identified.[/bold green]\n")
        return

    table = Table(title="STRIDE Threat Model Matrix", show_header=True, header_style="bold blue")
    table.add_column("Category", style="bold yellow", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Component", style="cyan", no_wrap=False)
    table.add_column("Threat Description & Remediation", no_wrap=False)

    for t in threats:
        desc = f"{t.description}\n[green]Fix: {t.remediation}[/green]"
        table.add_row(t.category, get_severity_badge(t.severity), t.target_component, desc)

    console.print(table)
    console.print()


def render_hook_tests_table(results: list[HookTestResult]) -> None:
    """Renders PreToolUse hook simulation results."""
    table = Table(title="PreToolUse Dynamic Hook Gating", show_header=True, header_style="bold green")
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Test Scenario", no_wrap=False)
    table.add_column("Decision", no_wrap=True)
    table.add_column("Hook Reason / Diagnostic", no_wrap=False)

    for r in results:
        status = "[bold green]PASSED[/bold green]" if r.passed else "[bold red]FAILED[/bold red]"
        table.add_row(status, r.description, r.decision.upper(), r.reason or "Allowed by policy")

    console.print(table)
    console.print()


def render_prompt_guard_table(results: list[PromptGuardResult]) -> None:
    """Renders Prompt Guard adversarial red-team results."""
    table = Table(title="Prompt Guard & Cognitive Injection Defense", show_header=True, header_style="bold red")
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Attack Vector", style="bold cyan", no_wrap=False)
    table.add_column("Payload Excerpt", no_wrap=False)
    table.add_column("Safety Assessment & Remediation", no_wrap=False)

    for r in results:
        status = "[bold green]PASSED[/bold green]" if r.safe else "[bold red]FLAGGED[/bold red]"
        payload_preview = r.prompt_payload[:40] + ("..." if len(r.prompt_payload) > 40 else "")
        desc = f"{r.reason}\n[green]Remediation: {r.remediation}[/green]"
        table.add_row(status, r.attack_category, payload_preview, desc)

    console.print(table)
    console.print()


def render_mcp_findings_table(findings: list[MCPAuditFinding]) -> None:
    """Renders MCP server audit findings."""
    if not findings:
        console.print("[bold green]✅ No MCP configuration vulnerabilities detected.[/bold green]\n")
        return

    table = Table(title="Model Context Protocol (MCP) Security Audit", show_header=True, header_style="bold dark_orange")
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Server Name", style="cyan", no_wrap=False)
    table.add_column("Endpoint / Command", no_wrap=False)
    table.add_column("Risk & Remediation", no_wrap=False)

    for m in findings:
        desc = f"{m.risk_description}\n[green]Fix: {m.remediation}[/green]"
        table.add_row(get_severity_badge(m.severity), m.server_name, m.endpoint_or_command, desc)

    console.print(table)
    console.print()


def render_hitl_findings_table(findings: list[HITLFinding]) -> None:
    """Renders Human-In-The-Loop missing gate findings."""
    if not findings:
        console.print("[bold green]✅ All mutating tool actions have Human-In-The-Loop gates verified.[/bold green]\n")
        return

    table = Table(title="Mutating Tools & Excessive Agency (HITL)", show_header=True, header_style="bold yellow")
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Tool Name", style="cyan", no_wrap=False)
    table.add_column("Mutation Type", style="bold red", no_wrap=False)
    table.add_column("Remediation", no_wrap=False)

    for h in findings:
        table.add_row(get_severity_badge(h.severity), f"{h.tool_name} ({h.file_path}:{h.line_number})", h.mutating_action.upper(), h.remediation)

    console.print(table)
    console.print()
