TOOL_SCOPE_MAP = {
    "gpu.submit.dev": "gpu.job.submit",
    "gpu.read": "gpu.job.read",
    "pr.comment": "pr.comment",
    "repo.read": "repo.read",
}


def scopes_for_tools(requested_tools):
    unknown_tools = [tool for tool in requested_tools if tool not in TOOL_SCOPE_MAP]
    scopes = sorted({TOOL_SCOPE_MAP[tool] for tool in requested_tools if tool in TOOL_SCOPE_MAP})
    return scopes, unknown_tools
