"""Coordinate the Homework 4 security tools and the official Filesystem MCP server.

Author: Tye Kates
FAU ID: tkates2020
"""

import asyncio
import json
import os
import shutil
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from mcp.types import CallToolResult, TextContent


CUSTOM_TOOLS = {
    "analyze_text_security",
    "summarize_findings",
    "security_recommendations",
}
FILESYSTEM_READ_TOOLS = ("read_text_file", "read_file")


def _tool_result_value(result: CallToolResult, tool_name: str) -> Any:
    """Return a tool's successful structured result or readable text."""
    if result.isError:
        details = "\n".join(
            block.text for block in result.content if isinstance(block, TextContent)
        )
        raise RuntimeError(
            f"MCP tool {tool_name!r} failed: {details or 'no error details returned'}"
        )

    structured_content = result.structuredContent
    if structured_content is not None:
        if isinstance(structured_content, dict):
            return structured_content.get("result", structured_content)
        return structured_content

    text_blocks = [
        block.text for block in result.content if isinstance(block, TextContent)
    ]
    if text_blocks:
        return "\n".join(text_blocks)
    raise RuntimeError(f"MCP tool {tool_name!r} returned no usable content.")


def _file_text(result: CallToolResult, tool_name: str) -> str:
    """Extract and validate text returned by the Filesystem MCP server."""
    value = _tool_result_value(result, tool_name)
    if isinstance(value, dict):
        value = value.get("content", value.get("text"))
    if not isinstance(value, str):
        raise RuntimeError(
            f"Filesystem tool {tool_name!r} returned a non-text file result."
        )
    return value


def _display_result(title: str, value: Any) -> None:
    """Print a tool result as readable, consistently formatted JSON."""
    print(f"\n{title}")
    print(json.dumps(value, indent=2, ensure_ascii=False))


async def run_agent() -> None:
    """Discover both MCP servers and run the coordinated security workflow."""
    hw4_dir = Path(__file__).resolve().parent
    sample_dir = (hw4_dir / "sample_files").resolve(strict=True)
    sample_file = (sample_dir / "insecure_demo.py").resolve(strict=True)
    if not sample_dir.is_dir() or not sample_file.is_file():
        raise FileNotFoundError(f"Expected sample file is missing: {sample_file}")
    if not sample_file.is_relative_to(sample_dir):
        raise ValueError("The requested sample file is outside the allowed directory.")

    custom_server_path = hw4_dir / "mcp-server.py"
    if not custom_server_path.is_file():
        raise FileNotFoundError(f"Custom MCP server not found: {custom_server_path}")
    npx_path = shutil.which("npx")
    if npx_path is None:
        nvm_node_bins = Path.home() / ".nvm" / "versions" / "node"
        npx_candidates = sorted(nvm_node_bins.glob("*/bin/npx"))
        if npx_candidates:
            npx_path = str(npx_candidates[-1])
    if npx_path is None:
        raise FileNotFoundError(
            "Could not find npx. Install Node.js/npm or add npx to PATH."
        )

    custom_parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(custom_server_path)],
        cwd=str(hw4_dir),
    )
    filesystem_parameters = StdioServerParameters(
        command=npx_path,
        args=[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            str(sample_dir),
        ],
        cwd=str(hw4_dir),
        env={
            **os.environ,
            "PATH": os.pathsep.join(
                (str(Path(npx_path).parent), os.environ.get("PATH", ""))
            ),
        },
    )

    async with AsyncExitStack() as stack:
        custom_read, custom_write = await stack.enter_async_context(
            stdio_client(custom_parameters)
        )
        custom_session = await stack.enter_async_context(
            ClientSession(custom_read, custom_write)
        )
        filesystem_read, filesystem_write = await stack.enter_async_context(
            stdio_client(filesystem_parameters)
        )
        filesystem_session = await stack.enter_async_context(
            ClientSession(filesystem_read, filesystem_write)
        )

        await custom_session.initialize()
        await filesystem_session.initialize()
        custom_listing = await custom_session.list_tools()
        filesystem_listing = await filesystem_session.list_tools()

        custom_tool_names = {tool.name for tool in custom_listing.tools}
        filesystem_tool_names = {tool.name for tool in filesystem_listing.tools}
        missing_custom_tools = CUSTOM_TOOLS - custom_tool_names
        if missing_custom_tools:
            raise RuntimeError(
                "Custom MCP server is missing required tools: "
                + ", ".join(sorted(missing_custom_tools))
            )

        read_tool = next(
            (name for name in FILESYSTEM_READ_TOOLS if name in filesystem_tool_names),
            None,
        )
        if read_tool is None:
            raise RuntimeError(
                "Filesystem MCP server exposes neither read_text_file nor read_file."
            )

        print("Discovered MCP tools by server:")
        print(
            "  Custom security server: "
            + ", ".join(sorted(custom_tool_names))
        )
        print(
            "  @modelcontextprotocol/server-filesystem: "
            + ", ".join(sorted(filesystem_tool_names))
        )
        print(f"\nFile path: {sample_file}")
        print("Filesystem access is restricted to: " + str(sample_dir))

        file_contents = _file_text(
            await filesystem_session.call_tool(
                read_tool, {"path": str(sample_file)}
            ),
            read_tool,
        )
        findings = _tool_result_value(
            await custom_session.call_tool(
                "analyze_text_security", {"text": file_contents}
            ),
            "analyze_text_security",
        )
        if not isinstance(findings, list) or any(
            not isinstance(finding, dict)
            or not {
                "category",
                "severity",
                "description",
                "evidence",
                "line",
            }.issubset(finding)
            for finding in findings
        ):
            raise RuntimeError(
                "analyze_text_security returned an unexpected result; "
                "expected a list of complete finding objects."
            )
        _display_result("Security findings", findings)

        summary = _tool_result_value(
            await custom_session.call_tool(
                "summarize_findings", {"findings": findings}
            ),
            "summarize_findings",
        )
        if not isinstance(summary, dict) or not {
            "total_findings",
            "overall_severity",
            "severity_counts",
            "category_counts",
            "explanations",
        }.issubset(summary):
            raise RuntimeError(
                "summarize_findings returned an unexpected result; "
                "expected a complete summary object."
            )
        _display_result("Findings summary", summary)

        recommendations = _tool_result_value(
            await custom_session.call_tool(
                "security_recommendations", {"findings": findings}
            ),
            "security_recommendations",
        )
        if not isinstance(recommendations, list) or any(
            not isinstance(recommendation, dict)
            or not {"category", "priority", "action"}.issubset(recommendation)
            for recommendation in recommendations
        ):
            raise RuntimeError(
                "security_recommendations returned an unexpected result; "
                "expected a list of complete recommendation objects."
            )
        _display_result("Security recommendations", recommendations)
        print(
            "\nWorkflow completed: Filesystem read succeeded and all three "
            "custom security tools returned valid results."
        )
        print(
            "This is a deterministic MCP workflow. An LLM-driven LangChain "
            "agent would additionally require LangChain MCP adapters, "
            "LangGraph/LangChain agent dependencies, and configured model "
            "credentials or a locally available model."
        )


def main() -> int:
    """Run the async client and report expected connection/tool errors."""
    try:
        asyncio.run(run_agent())
    except (FileNotFoundError, McpError, OSError, RuntimeError, ValueError) as error:
        print(f"Agent failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
