import uuid

from token_utils import STATE_DIR, json_load, json_save, now

TASK_DB = STATE_DIR / "agent_tasks.json"


def _load_tasks():
    return json_load(TASK_DB, {})


def _save_tasks(tasks):
    json_save(TASK_DB, tasks)


def create_task(task_data):
    tasks = _load_tasks()
    task_id = task_data.get("task_id") or f"task-{uuid.uuid4()}"
    ts = now()
    task = {
        "task_id": task_id,
        "agent_id": task_data.get("agent_id"),
        "initiating_user": task_data.get("initiating_user"),
        "agent_mode": task_data.get("agent_mode", "manual"),
        "goal": task_data.get("goal", ""),
        "requested_tools": task_data.get("requested_tools", []),
        "requested_scopes": task_data.get("requested_scopes", []),
        "environment": task_data.get("environment", "dev"),
        "risk_level": task_data.get("risk_level", "low"),
        "approval_required": bool(task_data.get("approval_required", False)),
        "approval_status": task_data.get("approval_status", "not_required"),
        "status": task_data.get("status", "created"),
        "created_at": task_data.get("created_at", ts),
        "updated_at": task_data.get("updated_at", ts),
        "policy_id": task_data.get("policy_id", "jwt-demo-policy"),
        "policy_version": task_data.get("policy_version", "2026.05"),
        "decision_id": task_data.get("decision_id"),
        "reason": task_data.get("reason", ""),
    }
    tasks[task_id] = task
    _save_tasks(tasks)
    return task


def get_task(task_id):
    return _load_tasks().get(task_id)


def update_task(task_id, updates):
    tasks = _load_tasks()
    task = tasks.get(task_id)
    if not task:
        return None
    task.update(updates or {})
    task["updated_at"] = now()
    tasks[task_id] = task
    _save_tasks(tasks)
    return task


def approve_task(task_id, reason="approved"):
    return update_task(task_id, {
        "approval_status": "approved",
        "status": "approved",
        "reason": reason,
    })


def list_tasks():
    return list(_load_tasks().values())
