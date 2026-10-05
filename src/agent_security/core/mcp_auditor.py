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

"""Model Context Protocol (MCP) server security and SSRF configuration auditor."""

import json
import re
from pathlib import Path
from agent_security.models.findings import MCPAuditFinding, Severity

# Trusted enterprise MCP provider domains and patterns
ALLOWED_MCP_SCHEMES = ("https://", "stdio")
DANGEROUS_COMMANDS = ("npx -y", "curl", "wget", "bash -c", "sh -c", "eval")


class MCPAuditor:
    """Audits MCP server configurations for SSRF, unpinned tools, and insecure transports."""

    def __init__(self, project_dir: str | Path):
        self.project_dir = Path(project_dir).resolve()

    def audit(self) -> list[MCPAuditFinding]:
        findings: list[MCPAuditFinding] = []
        config_files = self._find_mcp_configs()

        if not config_files:
            return findings

        for config_path in config_files:
            try:
                content = config_path.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(content)
            except Exception:
                continue

            servers = data.get("mcpServers", {}) or data.get("servers", {})
            for name, cfg in servers.items():
                command = cfg.get("command", "")
                args = " ".join(cfg.get("args", []))
                url = cfg.get("url", "")
                full_cmd = f"{command} {args}".strip()

                # Check 1: SSRF endpoints (Cloud metadata IP, localhost, loopback)
                if url:
                    if re.search(r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google\.internal)(?::\d+)?(?:/.*)?$", url, re.IGNORECASE):
                        findings.append(
                            MCPAuditFinding(
                                server_name=name,
                                config_file=str(config_path.relative_to(self.project_dir)),
                                endpoint_or_command=url,
                                severity=Severity.CRITICAL,
                                is_allowlisted=False,
                                risk_description="MCP Server targets internal loopback or cloud metadata IP (169.254.169.254). Severe SSRF risk.",
                                remediation="Isolate internal services and block agent tools from querying cloud metadata endpoints.",
                            )
                        )
                    elif url.startswith("http://"):
                        findings.append(
                            MCPAuditFinding(
                                server_name=name,
                                config_file=str(config_path.relative_to(self.project_dir)),
                                endpoint_or_command=url,
                                severity=Severity.HIGH,
                                is_allowlisted=False,
                                risk_description="Cleartext HTTP transport detected for MCP Server. Vulnerable to MITM and eavesdropping.",
                                remediation="Enforce HTTPS or mutual TLS (mTLS) for all external MCP servers.",
                            )
                        )

                # Check 2: Dangerous auto-download command execution (e.g. npx -y)
                if any(dang in full_cmd for dang in DANGEROUS_COMMANDS):
                    findings.append(
                        MCPAuditFinding(
                            server_name=name,
                            config_file=str(config_path.relative_to(self.project_dir)),
                            endpoint_or_command=full_cmd,
                            severity=Severity.HIGH,
                            is_allowlisted=False,
                            risk_description="MCP Server uses dynamic execution or unpinned package download (e.g. npx -y). Supply chain hijack risk.",
                            remediation="Pin tool binaries to specific verified versions or container images.",
                        )
                    )

        return findings

    def _find_mcp_configs(self) -> list[Path]:
        configs: list[Path] = []
        candidates = [
            self.project_dir / ".agents" / "mcp.json",
            self.project_dir / "mcp.json",
            self.project_dir / "mcp_servers.json",
        ]
        for c in candidates:
            if c.exists():
                configs.append(c)
        return configs
