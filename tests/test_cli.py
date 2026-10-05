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

"""Unit tests for the Agent Security CLI commands."""

import json
from click.testing import CliRunner
import pytest
from agent_security.cli import cli
from agent_security.core.mcp_auditor import MCPAuditor
from agent_security.models.findings import Severity


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_help(runner):
    """Test help option returns commands list."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Enterprise AI Agent Security & Evaluation CLI" in result.output
    assert "scan" in result.output
    assert "threat-model" in result.output
    assert "prompt-guard" in result.output
    assert "mcp-check" in result.output
    assert "hitl-check" in result.output
    assert "iam-check" in result.output
    assert "hook-check" in result.output
    assert "audit" in result.output


def test_cli_info(runner):
    """Test info command displays toolchain capabilities."""
    result = runner.invoke(cli, ["info"])
    assert result.exit_code == 0
    assert "Capabilities" in result.output or "Scanner" in result.output


def test_cli_threat_model_on_sample(runner, tmp_path):
    """Test threat model command generates findings on sample code."""
    sample_agent = tmp_path / "agent.py"
    sample_agent.write_text(
        """
DISCOUNT_CODES_DB = {"CODE": 10}
def redeem_discount(user_id: str, code: str):
    pass
""",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["threat-model", str(tmp_path)])
    assert result.exit_code == 0
    assert "STRIDE Threat Model Matrix" in result.output
    assert "redeem_discount" in result.output


def test_cli_prompt_guard(runner, tmp_path):
    """Test prompt guard evaluates agent instructions."""
    sample_agent = tmp_path / "agent.py"
    sample_agent.write_text(
        """from google.adk.agents import Agent
agent = Agent(name="test_agent", instruction="You are a helpful assistant.")
""",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["prompt-guard", str(tmp_path)])
    assert result.exit_code == 0
    assert "Prompt Guard & Cognitive Injection Defense" in result.output


def test_cli_hitl_check(runner, tmp_path):
    """Test HITL validator flags unshielded mutating tools."""
    sample_agent = tmp_path / "tools.py"
    sample_agent.write_text(
        "def delete_customer_account(account_id: str):\n    pass\n",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["hitl-check", str(tmp_path)])
    assert result.exit_code == 0
    assert "Mutating Tools & Excessive Agency" in result.output
    assert "delete_customer_account" in result.output


def test_cli_mcp_check(runner, tmp_path):
    """Test MCP auditor flags cleartext HTTP and dangerous npx commands."""
    mcp_config = tmp_path / "mcp.json"
    mcp_config.write_text(
        json.dumps({
            "mcpServers": {
                "insecure_server": {"url": "http://insecure-api.internal/mcp"},
                "unpinned_tool": {"command": "npx -y dangerous-tool"}
            }
        }),
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["mcp-check", str(tmp_path)])
    assert result.exit_code == 0
    assert "Model Context Protocol (MCP) Security Audit" in result.output
    assert "insecure_server" in result.output


def test_cli_iam_check(runner, tmp_path):
    """Test IAM auditor detects ADC and ambient authority tools."""
    sample_app = tmp_path / "app.py"
    sample_app.write_text(
        "import google.auth\n_, project = google.auth.default()\n\ndef get_orders(user_id: str):\n    pass\n",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["iam-check", str(tmp_path)])
    assert result.exit_code == 0
    assert "IAM & Identity Architecture Findings" in result.output
    assert "Service Account ADC" in result.output


def test_mcp_auditor_ssrf_priority(tmp_path):
    """Verify MCP auditor flags metadata SSRF as CRITICAL and generic HTTP as HIGH."""
    mcp_config = tmp_path / "mcp.json"
    mcp_config.write_text(
        json.dumps({
            "mcpServers": {
                "metadata_ssrf": {"url": "http://169.254.169.254/computeMetadata/v1/"},
                "localhost_ssrf": {"url": "http://localhost:8080/mcp"},
                "cleartext_http": {"url": "http://external-api.example.com/mcp"},
            }
        }),
        encoding="utf-8",
    )

    auditor = MCPAuditor(tmp_path)
    findings = auditor.audit()
    finding_map = {f.server_name: f for f in findings}

    assert "metadata_ssrf" in finding_map
    assert finding_map["metadata_ssrf"].severity == Severity.CRITICAL
    assert "SSRF" in finding_map["metadata_ssrf"].risk_description

    assert "localhost_ssrf" in finding_map
    assert finding_map["localhost_ssrf"].severity == Severity.CRITICAL

    assert "cleartext_http" in finding_map
    assert finding_map["cleartext_http"].severity == Severity.HIGH
    assert "Cleartext HTTP" in finding_map["cleartext_http"].risk_description


def test_cli_scan_json_output_exit_code(runner, tmp_path):
    """Verify scan --json-output exits with 1 when critical findings are found."""
    vulnerable_file = tmp_path / "leak.py"
    vulnerable_file.write_text(
        "OPENAI_API" + '_KEY = "sk-1234567890123456789012345678901234567890"\n',
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["scan", str(tmp_path), "--json-output"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert len(data) > 0
    assert any(f["severity"] in ["CRITICAL", "HIGH"] for f in data)


def test_cli_audit_full_pipeline(runner, tmp_path):
    """Verify audit command executes 8-step pipeline and writes report."""
    app_file = tmp_path / "agent.py"
    app_file.write_text(
        """from google.adk.agents import Agent
agent = Agent(name="secure_agent", instruction="Helpful and safe.")
""",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["audit", str(tmp_path)])
    # Output should include 8 steps
    assert "1/8. Running Static Secret & Code Scanner" in result.output
    assert "6/8. Auditing IAM & Agent Identity Architecture" in result.output
    assert "8/8. Running Outcome-Based Security Test Suite" in result.output

    report_file = tmp_path / "AGENT_SECURITY_AUDIT_REPORT.md"
    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert "# Agent Security Audit Report" in content
    assert "IAM & Agent Identity Architecture" in content
