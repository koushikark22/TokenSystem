TOOLS = {
    "gpu.read": {
        "tool": "gpu.read",
        "scope": "gpu.job.read",
        "risk_level": "low",
        "approval": "none",
    },
    "gpu.submit.dev": {
        "tool": "gpu.submit.dev",
        "scope": "gpu.job.submit",
        "risk_level": "medium",
        "approval": "manual_only",
    },
    "deploy.prod": {
        "tool": "deploy.prod",
        "scope": "deploy.prod",
        "risk_level": "high",
        "approval": "always",
    },
    "repo.comment": {
        "tool": "repo.comment",
        "scope": "pr.comment",
        "risk_level": "low",
        "approval": "none",
    },
}

RISK_PRIORITY = {"low": 1, "medium": 2, "high": 3}


def get_tool(tool_name):
    return TOOLS.get(tool_name)


def list_tools():
    return list(TOOLS.values())


def scopes_for_tools(tool_names):
    scopes = []
    for name in tool_names or []:
        tool = get_tool(name)
        if tool and tool["scope"] not in scopes:
            scopes.append(tool["scope"])
    return scopes


def highest_risk(tool_names):
    risks = [get_tool(name)["risk_level"] for name in tool_names or [] if get_tool(name)]
    if not risks:
        return "low"
    return max(risks, key=lambda level: RISK_PRIORITY.get(level, 0))


def approval_required_for_tools(tool_names, agent_mode="manual", environment="dev"):
    needs_approval = False
    for name in tool_names or []:
        tool = get_tool(name)
        if not tool:
            continue
        approval_type = tool["approval"]
        if approval_type == "always":
            needs_approval = True
        elif approval_type == "manual_only":
            if not (agent_mode == "autonomous" and environment == "dev"):
                needs_approval = True
    return needs_approval
