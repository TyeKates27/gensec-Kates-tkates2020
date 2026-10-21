"""Secure file-analysis tools exposed through an MCP stdio server.

Author: Tye Kates
FAU ID: tkates2020
"""

import re
from typing import Literal, TypedDict

from mcp.server.fastmcp import FastMCP


Severity = Literal["critical", "high", "medium", "low"]


class Finding(TypedDict):
    """A security issue detected in analyzed text."""

    category: str
    severity: Severity
    description: str
    evidence: str
    line: int


class FindingSummary(TypedDict):
    """Aggregate counts and explanations for a set of findings."""

    total_findings: int
    overall_severity: str
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    explanations: list[str]


class Recommendation(TypedDict):
    """A practical remediation suggestion for a finding category."""

    category: str
    priority: str
    action: str


mcp = FastMCP("Secure File Analysis")

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"""(?i)\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b"""
            r"""\s*[:=]\s*(['"])(?!your[_ -]|change[_ -]me|example\b)[^'"\n]{8,}\1"""
        ),
        "A credential-like value is assigned directly in the text.",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "A value matches the format of an AWS access key identifier.",
    ),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "A private key block marker is present.",
    ),
)

_SQL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"""(?i)\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE)\b"""
            r""".{0,240}(?:\+\s*[A-Za-z_]\w*|%\s*(?:\([^)]+\))?s\b|\{[A-Za-z_]\w*\})"""
        ),
        "SQL text appears to be combined with a variable or formatting placeholder.",
    ),
    (
        re.compile(r"""(?i)\b(?:execute|executemany)\s*\(\s*f['"]"""),
        "A dynamically interpolated f-string is passed to a SQL execution method.",
    ),
)

_SHELL_PATTERNS: tuple[tuple[re.Pattern[str], Severity, str], ...] = (
    (
        re.compile(r"(?i)\brm\s+-rf(?:\s|$)"),
        "critical",
        "A recursive, forceful file-deletion command is present.",
    ),
    (
        re.compile(r"(?i)\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash)\b"),
        "high",
        "Downloaded content is piped directly to a shell.",
    ),
    (
        re.compile(r"(?i)\bchmod\s+0?777\b"),
        "medium",
        "Permissions are set to allow unrestricted access.",
    ),
    (
        re.compile(r"(?i)\b(?:powershell|pwsh)\b[^\n]*-(?:enc|encodedcommand)\b"),
        "high",
        "PowerShell is invoked with an encoded command.",
    ),
    (
        re.compile(r"(?i)\bmkfs(?:\.\w+)?\b|\bdd\b[^\n]*\bof=/dev/"),
        "critical",
        "A command capable of overwriting or formatting a device is present.",
    ),
)

_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")


def _validate_findings(findings: list[Finding]) -> None:
    """Reject malformed findings rather than silently dropping security data."""
    required_fields = {"category", "severity", "description", "evidence", "line"}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or not required_fields.issubset(finding):
            raise ValueError(
                f"Finding at index {index} must include "
                "category, severity, description, evidence, and line."
            )
        if any(
            not isinstance(finding[field], str) or not finding[field]
            for field in ("category", "description", "evidence")
        ):
            raise ValueError(
                f"Finding at index {index} must have non-empty text fields."
            )
        if finding["severity"] not in _SEVERITY_ORDER:
            raise ValueError(
                f"Finding at index {index} has an unsupported severity."
            )
        if type(finding["line"]) is not int or finding["line"] < 1:
            raise ValueError(f"Finding at index {index} must have a positive line number.")


@mcp.tool()
def analyze_text_security(text: str) -> list[Finding]:
    """Scan text for hardcoded credentials, SQL injection indicators, and risky shell commands.

    Secret values are never copied into the returned findings. Line numbers refer
    to the one-based line number in the supplied text.
    """
    findings: list[Finding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern, description in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "category": "hardcoded_secret",
                        "severity": "high",
                        "description": description,
                        "evidence": "Credential-like content detected; value redacted.",
                        "line": line_number,
                    }
                )
                break

        for pattern, description in _SQL_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "category": "sql_injection_indicator",
                        "severity": "medium",
                        "description": description,
                        "evidence": "SQL construction or execution pattern detected.",
                        "line": line_number,
                    }
                )
                break

        matched_shell = next(
            (
                (severity, description)
                for pattern, severity, description in _SHELL_PATTERNS
                if pattern.search(line)
            ),
            None,
        )
        if matched_shell is not None:
            severity, description = matched_shell
            findings.append(
                {
                    "category": "dangerous_shell_command",
                    "severity": severity,
                    "description": description,
                    "evidence": "A potentially destructive or unsafe shell pattern was detected.",
                    "line": line_number,
                }
            )

    return findings


@mcp.tool()
def summarize_findings(findings: list[Finding]) -> FindingSummary:
    """Summarize findings by severity and category with explanations.

    Each finding must use the schema returned by ``analyze_text_security``.
    """
    _validate_findings(findings)

    severity_counts = {severity: 0 for severity in _SEVERITY_ORDER}
    category_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding["severity"]] += 1
        category = finding["category"]
        category_counts[category] = category_counts.get(category, 0) + 1

    overall_severity = next(
        (
            severity
            for severity in _SEVERITY_ORDER
            if severity_counts[severity] > 0
        ),
        "none",
    )
    explanations = [
        f"{severity.title()}: {count} finding(s)."
        for severity, count in severity_counts.items()
        if count
    ]
    if not findings:
        explanations.append("No suspicious patterns were detected.")

    return {
        "total_findings": len(findings),
        "overall_severity": overall_severity,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "explanations": explanations,
    }


@mcp.tool()
def security_recommendations(findings: list[Finding]) -> list[Recommendation]:
    """Return actionable remediation steps for the supplied security findings."""
    _validate_findings(findings)

    recommendations_by_category: dict[str, Recommendation] = {
        "hardcoded_secret": {
            "category": "hardcoded_secret",
            "priority": "high",
            "action": (
                "Remove the credential from source, rotate it if it may have been "
                "exposed, and load future secrets from a managed secret store or "
                "environment variable."
            ),
        },
        "sql_injection_indicator": {
            "category": "sql_injection_indicator",
            "priority": "medium",
            "action": (
                "Replace SQL string construction with parameterized queries, and "
                "validate inputs at the application boundary."
            ),
        },
        "dangerous_shell_command": {
            "category": "dangerous_shell_command",
            "priority": "high",
            "action": (
                "Avoid executing the command where possible. If shell execution is "
                "required, use a fixed executable with an argument list, validate "
                "inputs, and require confirmation for destructive operations."
            ),
        },
    }
    categories = sorted({finding["category"] for finding in findings})
    recommendations: list[Recommendation] = []
    for category in categories:
        category_findings = [
            finding for finding in findings if finding["category"] == category
        ]
        priority = next(
            severity
            for severity in _SEVERITY_ORDER
            if any(finding["severity"] == severity for finding in category_findings)
        )
        if category in recommendations_by_category:
            recommendation = recommendations_by_category[category].copy()
            recommendation["priority"] = priority
        else:
            recommendation = {
                "category": category,
                "priority": priority,
                "action": (
                    "Investigate the flagged pattern, remove unnecessary risk, and "
                    "apply the least-privilege and input-validation controls "
                    "appropriate to its use."
                ),
            }
        recommendations.append(recommendation)
    return recommendations


if __name__ == "__main__":
    mcp.run(transport="stdio")