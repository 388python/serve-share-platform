#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import subprocess
import os
import sys

API_KEY = os.environ.get("AGENT_API_KEY", "tea-platform-agent-key")
VIRT_TYPE = os.environ.get("VIRT_TYPE", "lxd")

class AgentHandler(BaseHTTPRequestHandler):
    def _check_auth(self):
        api_key = self.headers.get("X-API-Key", "")
        return api_key == API_KEY

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return
        if self.path == "/status":
            self._send_json({"status": "ok", "virt_type": VIRT_TYPE})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return
        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
        
        if self.path == "/create":
            name = body.get("name", f"vm-{body.get('cpu','1')}-{body.get('memory','1024')}")
            cpu = body.get("cpu", 1)
            memory = body.get("memory", 1024)  # MB
            disk = body.get("disk", 10)  # GB
            virt = body.get("virt_type", VIRT_TYPE)
            
            if virt == "lxd":
                # lxc launch ubuntu:22.04 {name} -c limits.cpu={cpu} -c limits.memory={memory}MB
                cmd = f"lxc launch ubuntu:22.04 {name} -c limits.cpu={cpu} -c limits.memory={memory}MB"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                self._send_json({"status": "created" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})
            elif virt == "kvm":
                # virt-install
                cmd = f"virt-install --name {name} --vcpus {cpu} --memory {memory} --disk size={disk} --import --os-variant ubuntu22.04 --noautoconsole"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                self._send_json({"status": "created" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return
        name = self.path.strip("/")
        if not name:
            self._send_json({"error": "name required"}, 400)
            return
        
        if VIRT_TYPE == "lxd":
            cmd = f"lxc delete --force {name}"
        else:
            cmd = f"virsh destroy {name} && virsh undefine {name}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        self._send_json({"status": "deleted" if result.returncode == 0 else "error"})

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 19527), AgentHandler)
    print(f"Agent running on port 19527, virt_type={VIRT_TYPE}")
    server.serve_forever()