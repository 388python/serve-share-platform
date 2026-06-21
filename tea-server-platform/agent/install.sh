#!/usr/bin/env bash
set -euo pipefail

VIRT_TYPE="${1:-lxd}"
AGENT_API_KEY="${2:-}"
PLATFORM_URL="${3:-http://localhost:3000}"
INSTALL_DIR="/opt/tea-agent"

if [ -z "${AGENT_API_KEY}" ]; then
    echo "[tea-agent] AGENT_API_KEY is required. Usage: curl -sL <url> | bash -s -- <lxd|kvm> <agent_api_key> <platform_url>" >&2
    exit 1
fi

echo "[tea-agent] Installing with virt_type=${VIRT_TYPE}, platform=${PLATFORM_URL}"

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
from urllib.parse import urlparse
import json
import subprocess
import os
import re
import sys
import threading
import time
import urllib.request

API_KEY = os.environ.get("AGENT_API_KEY")
if not API_KEY:
    raise SystemExit("AGENT_API_KEY is required")
VIRT_TYPE = os.environ.get("VIRT_TYPE", "lxd")
PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:3000")

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

def report_stats_loop():
    """Background thread to report machine stats to platform"""
    while True:
        try:
            result = subprocess.run(
                ["lxc", "list", "name=machine-", "--format", "csv", "-c", "n"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                machine_name = line.strip()
                try:
                    info_result = subprocess.run(
                        ["lxc", "info", machine_name],
                        capture_output=True, text=True, timeout=10
                    )
                    cpu_usage = 0.0
                    memory_used = 0
                    memory_total = 0
                    for info_line in info_result.stdout.split("\n"):
                        info_line = info_line.strip()
                        if "CPU usage:" in info_line:
                            match = re.search(r'(\d+\.?\d*)', info_line.split("CPU usage:")[1])
                            if match:
                                cpu_usage = float(match.group(1))
                        elif "Memory usage:" in info_line:
                            match = re.search(r'(\d+)', info_line.split("Memory usage:")[1])
                            if match:
                                memory_used = int(match.group(1))
                        elif "Memory:" in info_line:
                            match = re.search(r'(\d+)', info_line.split("Memory:")[1])
                            if match:
                                memory_total = int(match.group(1))
                    stats = {
                        "machine_name": machine_name,
                        "cpu_usage_percent": cpu_usage,
                        "memory_used_mb": float(memory_used),
                        "memory_total_mb": float(memory_total),
                        "disk_used_gb": 0,
                        "disk_total_gb": 10.0,
                        "bandwidth_rx_mbps": 0,
                        "bandwidth_tx_mbps": 0,
                        "uptime_seconds": 0,
                        "process_count": 0
                    }
                    data = json.dumps(stats).encode()
                    req = urllib.request.Request(
                        f"{PLATFORM_URL}/api/v1/agent/stats",
                        data=data,
                        headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=10) as response:
                        pass
                except Exception as e:
                    print(f"Failed to report stats for {machine_name}: {e}")
        except Exception as e:
            print(f"Stats reporting error: {e}")
        time.sleep(60)

def detect_hardware():
    hardware = {}
    try:
        result = subprocess.run(["nproc", "--all"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            hardware["cpu_cores"] = int(result.stdout.strip())
    except:
        pass
    try:
        result = subprocess.run(["grep", "MemTotal", "/proc/meminfo"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2 and parts[1].isdigit():
                kb = int(parts[1])
                hardware["memory_gb"] = round(kb / 1024.0 / 1024.0, 2)
    except:
        pass
    try:
        result = subprocess.run(["df", "-BG", "/"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 2:
                    size_str = parts[1].rstrip("G").strip()
                    if size_str.isdigit():
                        hardware["disk_gb"] = int(size_str)
    except:
        pass
    try:
        result = subprocess.run(["bash", "-c", "cat /etc/os-release 2>/dev/null | grep -E '^NAME=|^VERSION=' | tr '\\n' ' ' | sed 's/NAME=//;s/VERSION=//g' | tr -d '\\\"' || uname -srm"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            hardware["linux_version"] = result.stdout.strip()
    except:
        pass
    return hardware

def register_with_platform():
    hardware = detect_hardware()
    payload = {"virt_type": VIRT_TYPE, "platform_url": PLATFORM_URL}
    payload.update(hardware)
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        payload["ip"] = s.getsockname()[0]
        s.close()
    except:
        pass
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{PLATFORM_URL.rstrip('/')}/api/v1/agent/register",
            data=data,
            headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode())
            print(f"[agent] Registered with platform: {result}")
    except Exception as e:
        print(f"[agent] Failed to register with platform: {e}")

if __name__ == "__main__":
    register_thread = threading.Thread(target=register_with_platform, daemon=True)
    register_thread.start()
    stats_thread = threading.Thread(target=report_stats_loop, daemon=True)
    stats_thread.start()
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
Environment=PLATFORM_URL=${PLATFORM_URL}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSEOF

systemctl daemon-reload
systemctl enable tea-agent
systemctl start tea-agent

echo "[tea-agent] Installation complete. Agent running on port 19527."
