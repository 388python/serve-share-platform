#!/usr/bin/env bash
set -euo pipefail

VIRT_TYPE="${1:-lxd}"
AGENT_API_KEY="${2:-}"
INSTALL_DIR="/opt/tea-agent"

if [ -z "${AGENT_API_KEY}" ]; then
    echo "[tea-agent] AGENT_API_KEY is required. Usage: install.sh <lxd|kvm> <agent_api_key>" >&2
    exit 1
fi

echo "[tea-agent] Installing with virt_type=${VIRT_TYPE}"

# --- Install virtualization dependencies ---
if [ "${VIRT_TYPE}" = "lxd" ]; then
    echo "[tea-agent] Installing LXD..."
    apt-get update -qq
    apt-get install -y -qq lxd
    lxd init --auto
elif [ "${VIRT_TYPE}" = "kvm" ]; then
    echo "[tea-agent] Installing KVM/libvirt..."
    apt-get update -qq
    apt-get install -y -qq qemu-kvm libvirt-daemon-system virtinst
    systemctl enable libvirtd
    systemctl start libvirtd
else
    echo "[tea-agent] Unknown virt_type: ${VIRT_TYPE}"
    exit 1
fi

# --- Install python3 if missing ---
if ! command -v python3 &>/dev/null; then
    apt-get install -y -qq python3
fi

# --- Deploy agent script ---
mkdir -p "${INSTALL_DIR}"
cat > "${INSTALL_DIR}/agent.py" << 'PYEOF'
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import subprocess
import os
import sys

API_KEY = os.environ.get("AGENT_API_KEY")
if not API_KEY:
    raise SystemExit("AGENT_API_KEY is required")
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

    def _log_request(self):
        print(f"[agent] {self.command} {self.path}")

    def do_GET(self):
        self._log_request()
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return
        if self.path == "/status":
            status_info = {"status": "ok", "virt_type": VIRT_TYPE}
            try:
                if VIRT_TYPE == "lxd":
                    result = subprocess.run("lxc list --format json", shell=True, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        status_info["containers"] = json.loads(result.stdout)
                    else:
                        status_info["error"] = result.stderr
                elif VIRT_TYPE == "kvm":
                    result = subprocess.run("virsh list --all --name", shell=True, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        vms = [v for v in result.stdout.strip().split("\n") if v]
                        status_info["vms"] = vms
                    else:
                        status_info["error"] = result.stderr
            except Exception as e:
                status_info["error"] = str(e)
            self._send_json(status_info)
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        self._log_request()
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
                cmd = f"lxc launch ubuntu:22.04 {name} -c limits.cpu={cpu} -c limits.memory={memory}MB"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                self._send_json({"status": "created" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})
            elif virt == "kvm":
                cmd = f"virt-install --name {name} --vcpus {cpu} --memory {memory} --disk size={disk} --import --os-variant ubuntu22.04 --noautoconsole"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                self._send_json({"status": "created" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})
            else:
                self._send_json({"error": f"unsupported virt_type: {virt}"}, 400)

        elif self.path.startswith("/start/"):
            name = self.path[len("/start/"):]
            if not name:
                self._send_json({"error": "name required"}, 400)
                return
            if VIRT_TYPE == "lxd":
                cmd = f"lxc start {name}"
            else:
                cmd = f"virsh start {name}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            self._send_json({"status": "started" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})

        elif self.path.startswith("/stop/"):
            name = self.path[len("/stop/"):]
            if not name:
                self._send_json({"error": "name required"}, 400)
                return
            if VIRT_TYPE == "lxd":
                cmd = f"lxc stop {name}"
            else:
                cmd = f"virsh shutdown {name}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            self._send_json({"status": "stopped" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})

        else:
            self._send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        self._log_request()
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
            cmd = f"virsh destroy {name} 2>/dev/null; virsh undefine {name} --remove-all-storage"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        self._send_json({"status": "deleted" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 19527), AgentHandler)
    print(f"Agent running on port 19527, virt_type={VIRT_TYPE}")
    server.serve_forever()
PYEOF

chmod +x "${INSTALL_DIR}/agent.py"

# --- Set up systemd service ---
cat > /etc/systemd/system/tea-agent.service << SYSEOF
[Unit]
Description=Tea Server Platform Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/agent.py
Environment=AGENT_API_KEY=${AGENT_API_KEY}
Environment=VIRT_TYPE=${VIRT_TYPE}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSEOF

systemctl daemon-reload
systemctl enable tea-agent
systemctl start tea-agent

echo "[tea-agent] Installation complete. Agent running on port 19527."
