import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from agent_tasks import save_tasks
from devctl import AUDIT_DB, TOKEN_URL, run_agentic_task_demo
from token_utils import json_load, json_save

HOST = "127.0.0.1"
PORT = 8500
DASHBOARD_PATH = Path(__file__).parent / "static" / "agentic_dashboard.html"


def _filtered_audit_events():
    events = json_load(AUDIT_DB, [])
    wanted = {
        "agent_task_created",
        "agent_task_approval_denied",
        "agent_task_approved",
        "agent_task_token_failed",
        "agent_task_token_issued",
    }
    return [e for e in events if e.get("event_type") in wanted][-50:]


class AgenticUIHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send_html(DASHBOARD_PATH.read_text(encoding="utf-8"))
            return
        if self.path == "/api/audit":
            self._send_json({"events": _filtered_audit_events()})
            return
        self._send_json({"error": "not_found"}, 404)

    def do_POST(self):
        if self.path == "/api/run-demo":
            try:
                summary = run_agentic_task_demo(return_summary=True)
                self._send_json({"ok": True, "summary": summary, "audit": _filtered_audit_events()})
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc), "hint": f"ensure token service is running at {TOKEN_URL}"}, 500)
            return
        if self.path == "/api/reset":
            save_tasks({})
            json_save(AUDIT_DB, [])
            self._send_json({"ok": True, "message": "demo state reset"})
            return
        self._send_json({"error": "not_found"}, 404)


def main():
    server = HTTPServer((HOST, PORT), AgenticUIHandler)
    print("Agentic task UI running at http://localhost:8500")
    server.serve_forever()


if __name__ == "__main__":
    main()
