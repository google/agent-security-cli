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

"""Pydantic v2 data models for security findings and scan results."""

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(..., description="Unique rule or vulnerability identifier.")
    title: str = Field(..., description="Short descriptive title.")
    description: str = Field(..., description="Detailed description of the issue.")
    severity: Severity = Field(..., description="Severity level.")
    file_path: str = Field(..., description="Path to the offending file.")
    line_number: int | None = Field(default=None, description="Line number if available.")
    code_snippet: str | None = Field(default=None, description="Code snippet containing the issue.")
    remediation: str = Field(..., description="Actionable remediation advice.")


class HookTestResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    payload: str
    decision: str  # allow / deny / ask
    reason: str | None = None
    passed: bool
    description: str


class STRIDEThreat(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: str  # Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
    threat_id: str
    target_component: str
    severity: Severity
    description: str
    remediation: str


class PromptGuardResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    test_id: str
    attack_category: str  # Direct Injection, Indirect Injection, System Prompt Extraction, Crescendo
    prompt_payload: str
    simulated_response: str
    safe: bool
    reason: str
    remediation: str


class MCPAuditFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    server_name: str
    config_file: str
    endpoint_or_command: str
    severity: Severity
    is_allowlisted: bool
    risk_description: str
    remediation: str


class HITLFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool_name: str
    file_path: str
    line_number: int
    mutating_action: str  # delete, refund, grant, payout, execute
    has_hitl_gate: bool
    severity: Severity
    remediation: str


class AuditReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    project_name: str
    project_path: str
    timestamp: str
    static_findings: list[Finding] = Field(default_factory=list)
    stride_threats: list[STRIDEThreat] = Field(default_factory=list)
    hook_tests: list[HookTestResult] = Field(default_factory=list)
    prompt_guard_results: list[PromptGuardResult] = Field(default_factory=list)
    mcp_findings: list[MCPAuditFinding] = Field(default_factory=list)
    hitl_findings: list[HITLFinding] = Field(default_factory=list)
    iam_findings: list[Finding] = Field(default_factory=list)
    iam_summary: dict[str, Any] = Field(default_factory=dict)
    test_suite_passed: bool = True
    test_suite_output: str = ""
