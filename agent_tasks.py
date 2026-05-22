from token_utils import STATE_DIR, json_load, json_save

AGENT_TASK_DB = STATE_DIR / "agent_tasks.json"


def load_tasks():
    return json_load(AGENT_TASK_DB, {})


def save_tasks(tasks):
    json_save(AGENT_TASK_DB, tasks)


def persist_task(task):
    tasks = load_tasks()
    tasks[task["task_id"]] = task
    save_tasks(tasks)
    return task
