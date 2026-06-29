#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" != "0" ]; then
    echo "[tea-agent] ERROR: This script must be run as root" >&2
    exit 1
fi

VIRT_TYPE="${1:-lxd}"
AGENT_API_KEY="${2:-}"
PLATFORM_URL="${3:-http://localhost:3000}"
INSTALL_DIR="/opt/tea-agent"
AGENT_URL="${PLATFORM_URL}/api/v1/agent/script"

if [ -z "${AGENT_API_KEY}" ]; then
    echo "[tea-agent] AGENT_API_KEY is required. Usage: curl -sL <url> | bash -s -- <lxd|kvm> <agent_api_key> <platform_url>" >&2
    exit 1
fi

echo "[tea-agent] Installing with virt_type=${VIRT_TYPE}, platform=${PLATFORM_URL}"

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

if ! command -v python3 &>/dev/null; then
    apt-get install -y -qq python3
fi

mkdir -p "${INSTALL_DIR}"

echo "[tea-agent] Downloading latest agent script..."
if curl -s -f -o "${INSTALL_DIR}/agent.py" "${AGENT_URL}"; then
    echo "[tea-agent] Agent script downloaded successfully"
else
    echo "[tea-agent] WARNING: Failed to download agent from platform, using embedded version"
    cat > "${INSTALL_DIR}/agent.py" << 'PYEOF'
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import json
import subprocess
import os
import re
import threading
import time
import urllib.request

API_KEY = os.environ.get("AGENT_API_KEY")
if not API_KEY:
    raise SystemExit("AGENT_API_KEY is required")
VIRT_TYPE = os.environ.get("VIRT_TYPE", "lxd")
PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:3000")
OPENGFW_ENABLED = os.environ.get("OPENGFW_ENABLED", "false").lower() == "true"

class AgentHandler(BaseHTTPRequestHandler):
    def _check_auth(self):
        api_key = self.headers.get("X-API-Key", "")
        return api_key == API_KEY

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _get_virt_type_from_name(self, name):
        if name.startswith("machine-"):
            return "lxd"
        return VIRT_TYPE

    def do_GET(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        path = urlparse(self.path).path

        if path == "/status":
            virt_info = self._detect_virtualization()
            self._send_json({"status": "ok", "virt_type": VIRT_TYPE, "virtualization": virt_info})
        elif path == "/virtualization":
            virt_info = self._detect_virtualization()
            self._send_json(virt_info)
        elif path == "/ports":
            self._handle_get_ports()
        elif path == "/processes":
            self._handle_get_processes()
        elif path.startswith("/traffic/"):
            machine_id = path.split("/")[-1]
            self._handle_get_traffic(machine_id)
        elif path == "/opengfw/status":
            self._handle_opengfw_status()
        elif path == "/opengfw/install":
            self._handle_opengfw_install()
        elif path == "/opengfw/config":
            self._handle_opengfw_config()
        elif path == "/opengfw/refresh":
            self._handle_opengfw_refresh()
        elif path == "/opengfw/uninstall":
            self._handle_opengfw_uninstall()
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_get_ports(self):
        try:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5
            )
            ports = []
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    addr = parts[3]
                    if ":" in addr:
                        port_str = addr.split(":")[-1]
                        try:
                            port = int(port_str)
                            ports.append({"port": port, "proto": "tcp"})
                        except ValueError:
                            pass
            self._send_json({"listening_ports": ports})
        except Exception as e:
            self._send_json({"error": str(e), "listening_ports": []})

    def _handle_get_processes(self):
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=5
            )
            processes = []
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append({
                        "name": parts[10].split()[0] if parts[10] else "",
                        "pid": parts[1],
                        "cmd": parts[10][:100]
                    })
            self._send_json({"processes": processes})
        except Exception as e:
            self._send_json({"error": str(e), "processes": []})

    def _handle_get_traffic(self, machine_id):
        container_name = f"machine-{machine_id}"
        try:
            result = subprocess.run(
                ["lxc", "info", container_name],
                capture_output=True, text=True, timeout=10
            )
            rx_bytes = 0
            tx_bytes = 0
            for line in result.stdout.split("\n"):
                if "RX:" in line:
                    match = re.search(r'(\d+)', line.split("RX:")[1])
                    if match:
                        rx_bytes = int(match.group(1))
                if "TX:" in line:
                    match = re.search(r'(\d+)', line.split("TX:")[1])
                    if match:
                        tx_bytes = int(match.group(1))

            rx_mbps = (rx_bytes * 8) / (300 * 1_000_000)
            tx_mbps = (tx_bytes * 8) / (300 * 1_000_000)

            self._send_json({
                "bandwidth_mbps": max(rx_mbps, tx_mbps),
                "rx_mbps": rx_mbps,
                "tx_mbps": tx_mbps
            })
        except Exception as e:
            self._send_json({"error": str(e), "bandwidth_mbps": 0})

    def _handle_opengfw_status(self):
        try:
            opengfw_exists = os.path.exists("/usr/local/bin/opengfw")

            result = subprocess.run(
                ["pgrep", "-f", "opengfw"],
                capture_output=True, text=True
            )
            opengfw_running = result.returncode == 0

            config_exists = os.path.exists("/etc/opengfw/config.yaml")

            nft_result = subprocess.run(
                ["nft", "list", "table", "opengfw"],
                capture_output=True, text=True
            )
            nft_rules_exist = nft_result.returncode == 0

            self._send_json({
                "installed": opengfw_exists,
                "running": opengfw_running,
                "configured": config_exists,
                "nft_rules_active": nft_rules_exist,
                "message": "OpenGFW status on host machine"
            })
        except Exception as e:
            self._send_json({"error": str(e), "installed": False, "running": False})

    def _handle_opengfw_install(self):
        try:
            subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=120)
            subprocess.run([
                "apt-get", "install", "-y", "-qq",
                "golang-go", "git", "nftables", "kmod"
            ], capture_output=True, timeout=180)

            work_dir = "/tmp/opengfw-build"
            os.makedirs(work_dir, exist_ok=True)

            subprocess.run(["rm", "-rf", work_dir], capture_output=True)
            subprocess.run(
                ["git", "clone", "https://github.com/chika0801/opengfw.git", work_dir],
                capture_output=True, timeout=120
            )

            build_result = subprocess.run(
                ["go", "build", "-o", "/usr/local/bin/opengfw"],
                cwd=work_dir,
                capture_output=True, text=True, timeout=300
            )

            if build_result.returncode != 0:
                self._send_json({
                    "status": "error",
                    "error": f"Build failed: {build_result.stderr.decode() if isinstance(build_result.stderr, bytes) else build_result.stderr}"
                })
                return

            subprocess.run(["chmod", "+x", "/usr/local/bin/opengfw"], capture_output=True)

            os.makedirs("/etc/opengfw", exist_ok=True)

            subprocess.run(["systemctl", "enable", "nftables"], capture_output=True)
            subprocess.run(["systemctl", "start", "nftables"], capture_output=True)

            self._send_json({
                "status": "installed",
                "message": "OpenGFW installed successfully on host machine"
            })
        except Exception as e:
            self._send_json({"status": "error", "error": str(e)})

    def _handle_opengfw_config(self):
        try:
            req = urllib.request.Request(
                f"{PLATFORM_URL}/api/v1/opengfw/config",
                headers={"X-API-Key": API_KEY},
                method="GET"
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                config = json.loads(response.read().decode())

            if not config.get("enabled"):
                self._send_json({
                    "status": "disabled",
                    "message": "OpenGFW is disabled on platform"
                })
                return

            rules = config.get("rules", [])
            yaml_content = self._generate_opengfw_yaml(rules)

            with open("/etc/opengfw/config.yaml", "w") as f:
                f.write(yaml_content)

            self._apply_nftables_rules(rules)

            subprocess.run(["pkill", "-f", "opengfw"], capture_output=True)
            subprocess.Popen(
                ["/usr/local/bin/opengfw", "-c", "/etc/opengfw/config.yaml"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            self._send_json({
                "status": "configured",
                "rules_count": len(rules),
                "message": "OpenGFW configured and restarted"
            })
        except Exception as e:
            self._send_json({"status": "error", "error": str(e)})

    def _generate_opengfw_yaml(self, rules):
        actions = []
        for rule in rules:
            proto = rule.get("protocol", "")
            action = rule.get("action", "block")

            if proto == "shadowsocks":
                actions.append(f'  - id: "block_shadowsocks"\n    match: "payload,56,0,0,0,0,0,0,0,0,6,0xff,0x17"\n    action: {action}')
            elif proto == "wireguard":
                actions.append(f'  - id: "block_wireguard"\n    match: "payload,0,0,0,0,0,0,0,0,0,17,0,51820"\n    action: {action}')
            elif proto == "openvpn":
                actions.append(f'  - id: "block_openvpn"\n    match: "payload,0,0,0,0,0,0,0,0,0,6,0,1194"\n    action: {action}')
            elif proto == "trojan":
                actions.append(f'  - id: "block_trojan"\n    match: "payload,0,0,0,0,0,0,0,0,0,6,0,443"\n    action: {action}')
            elif proto in ["vmess", "vless", "xray"]:
                actions.append(f'  - id: "block_{proto}"\n    match: "payload,0,0,0,0,0,0,0,0,0,6,0,80"\n    action: {action}')
            elif proto == "clash":
                actions.append(f'  - id: "block_clash"\n    match: "payload,0,0,0,0,0,0,0,0,0,6,0,7890"\n    action: {action}')

        yaml = f'''listen: ":4480"
log:
  level: info
  file: /var/log/opengfw.log
actions:
{chr(10).join(actions)}
'''
        return yaml

    def _apply_nftables_rules(self, rules):
        try:
            nft_script = '''
flush ruleset
table ip opengfw {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iif lo accept
    }
    chain outbound {
        type filter hook output priority 0; policy accept;
        meta iif-name lxdbr0 tcp dport { 1080, 8388, 51820, 1194, 443, 80, 7890 } counter log prefix "OPENGFW_BLOCK: " drop
    }
}
'''

            subprocess.run(["bash", "-c", f"echo '{nft_script}' | nft -f -"], capture_output=True)

        except Exception as e:
            print(f"NFTables configuration error: {e}")

    def _handle_opengfw_refresh(self):
        self._handle_opengfw_config()

    def _handle_opengfw_uninstall(self):
        try:
            subprocess.run(["pkill", "-f", "opengfw"], capture_output=True)

            subprocess.run(["rm", "-f", "/usr/local/bin/opengfw"], capture_output=True)

            subprocess.run(["rm", "-rf", "/etc/opengfw"], capture_output=True)

            subprocess.run(["nft", "delete", "table", "ip", "opengfw"], capture_output=True)

            self._send_json({
                "status": "uninstalled",
                "message": "OpenGFW removed from host machine"
            })
        except Exception as e:
            self._send_json({"status": "error", "error": str(e)})

    def _get_machine_stats(self, machine_name):
        try:
            result = subprocess.run(
                ["lxc", "info", machine_name],
                capture_output=True, text=True, timeout=10
            )
            
            cpu_usage = 0.0
            memory_used = 0
            memory_total = 0
            uptime = 0
            
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "CPU usage:" in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        cpu_usage = float(match.group(1))
                elif "Memory usage:" in line:
                    match = re.search(r'(\d+)(?:MiB|KiB|MB|GB)', line)
                    if match:
                        memory_used = int(match.group(1))
                elif "Memory:" in line:
                    match = re.search(r'(\d+)(?:MiB|KiB|MB|GB)', line)
                    if match:
                        memory_total = int(match.group(1))
            
            disk_used = 0
            disk_total = 0
            try:
                disk_result = subprocess.run(
                    ["lxc", "exec", machine_name, "--", "df", "-h", "/"],
                    capture_output=True, text=True, timeout=10
                )
                for line in disk_result.stdout.split("\n"):
                    match = re.search(r'/dev/\w+\s+\d+[GM]\s+(\d+)[GM]\s+', line)
                    if match:
                        disk_used = int(match.group(1))
            except:
                pass
            
            try:
                proc_result = subprocess.run(
                    ["lxc", "exec", machine_name, "--", "ps", "aux"],
                    capture_output=True, text=True, timeout=10
                )
                process_count = len(proc_result.stdout.strip().split("\n")) - 1
            except:
                process_count = 0
            
            return {
                "cpu_usage_percent": cpu_usage,
                "memory_used_mb": float(memory_used),
                "memory_total_mb": float(memory_total),
                "disk_used_gb": float(disk_used),
                "disk_total_gb": float(disk_total) if disk_total > 0 else 10.0,
                "uptime_seconds": uptime,
                "process_count": process_count
            }
        except Exception as e:
            return {
                "cpu_usage_percent": 0,
                "memory_used_mb": 0,
                "memory_total_mb": 0,
                "disk_used_gb": 0,
                "disk_total_gb": 0,
                "uptime_seconds": 0,
                "process_count": 0
            }

    def do_POST(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}

        path = urlparse(self.path).path

        if path == "/create":
            self._handle_create(body)
        elif path.startswith("/stop/"):
            name = path.split("/")[-1]
            self._handle_stop(name)
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_create(self, body):
        name = body.get("name", f"vm-{body.get('cpu','1')}-{body.get('memory','1024')}")
        cpu = body.get("cpu", 1)
        memory = body.get("memory", 1024)
        disk = body.get("disk", 10)
        virt = body.get("virt_type", VIRT_TYPE)

        if virt == "lxd":
            cmd = [
                "lxc", "launch", "ubuntu:22.04", name,
                "-c", f"limits.cpu={cpu}",
                "-c", f"limits.memory={memory}MB",
                "-c", f"limits.disk={disk}GB"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                cmd = [
                    "lxc", "launch", "ubuntu:22.04", name,
                    "-c", f"limits.cpu={cpu}",
                    "-c", f"limits.memory={memory}MB"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
            self._send_json({
                "status": "created" if result.returncode == 0 else "error",
                "output": result.stdout,
                "error": result.stderr
            })

        elif virt == "kvm":
            disk_path = f"/var/lib/libvirt/images/{name}.qcow2"

            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-b",
                 "/var/lib/libvirt/images/base-ubuntu.qcow2", "-F", "qcow2", disk_path],
                capture_output=True, timeout=30
            )

            cmd = [
                "virt-install",
                "--name", name,
                "--vcpus", str(cpu),
                "--memory", str(memory),
                "--disk", f"path={disk_path},format=qcow2",
                "--boot", "hd",
                "--os-variant", "ubuntu22.04",
                "--noautoconsole",
                "--graphics", "none"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self._send_json({
                "status": "created" if result.returncode == 0 else "error",
                "output": result.stdout,
                "error": result.stderr
            })
        else:
            self._send_json({"error": f"unsupported virt_type: {virt}"})

    def _handle_stop(self, name):
        if not name:
            self._send_json({"error": "name required"}, 400)
            return

        virt = self._get_virt_type_from_name(name)

        if virt == "lxd":
            subprocess.run(["lxc", "stop", name], capture_output=True, timeout=30)
            cmd = ["lxc", "delete", "--force", name]
        else:
            subprocess.run(["virsh", "destroy", name], capture_output=True)
            cmd = ["virsh", "undefine", name, "--nvram"]

        result = subprocess.run(cmd, capture_output=True, text=True)
        self._send_json({
            "status": "stopped" if result.returncode == 0 else "error",
            "output": result.stdout,
            "error": result.stderr
        })

    def do_DELETE(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        path = urlparse(self.path).path
        name = path.strip("/")

        if not name:
            self._send_json({"error": "name required"}, 400)
            return

        virt = self._get_virt_type_from_name(name)

        if virt == "lxd":
            subprocess.run(["lxc", "stop", name], capture_output=True)
            cmd = ["lxc", "delete", "--force", name]
        else:
            subprocess.run(["virsh", "destroy", name], capture_output=True)
            cmd = ["virsh", "undefine", name, "--nvram", "--delete-all-storage"]

        result = subprocess.run(cmd, capture_output=True, text=True)
        self._send_json({
            "status": "deleted" if result.returncode == 0 else "error",
            "output": result.stdout,
            "error": result.stderr
        })

    def _detect_virtualization(self):
        result = {
            "supported": False,
            "virt_types": [],
            "details": {},
        }
        try:
            kvm_supported = False
            vt_x_supported = False
            vt_d_supported = False

            result_cpuinfo = subprocess.run(
                ["grep", "-E", "(vmx|svm)", "/proc/cpuinfo"],
                capture_output=True, text=True, timeout=10
            )
            if result_cpuinfo.returncode == 0:
                if "vmx" in result_cpuinfo.stdout:
                    vt_x_supported = True
                if "svm" in result_cpuinfo.stdout:
                    vt_d_supported = True

            try:
                result_kvm = subprocess.run(
                    ["lsmod"], capture_output=True, text=True, timeout=10
                )
                if "kvm_intel" in result_kvm.stdout or "kvm_amd" in result_kvm.stdout:
                    kvm_supported = True
            except Exception:
                pass

            if vt_x_supported or vt_d_supported:
                result["virt_types"].append("kvm")
                if kvm_supported:
                    result["details"]["kvm"] = "enabled"
                else:
                    result["details"]["kvm"] = "supported but not loaded"

            lxd_supported = False
            try:
                result_lxc = subprocess.run(["which", "lxc"], capture_output=True, text=True, timeout=5)
                if result_lxc.returncode == 0:
                    lxd_supported = True
                    result["virt_types"].append("lxd")
                    result["details"]["lxd"] = "installed"
            except Exception:
                pass

            if result["virt_types"]:
                result["supported"] = True

            result["details"]["vt_x_supported"] = vt_x_supported
            result["details"]["vt_d_supported"] = vt_d_supported
            result["details"]["kvm_loaded"] = kvm_supported
            result["details"]["lxd_installed"] = lxd_supported

        except Exception as e:
            pass

        return result

def report_stats_loop():
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
                
                stats = {}
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
                    
                    try:
                        disk_result = subprocess.run(
                            ["lxc", "exec", machine_name, "--", "df", "-BG", "/"],
                            capture_output=True, text=True, timeout=10
                        )
                        for dline in disk_result.stdout.strip().split("\n"):
                            if dline.startswith("/dev"):
                                parts = dline.split()
                                if len(parts) >= 3:
                                    disk_used = int(parts[2].replace("G", ""))
                                    disk_total = int(parts[1].replace("G", ""))
                                    break
                    except:
                        disk_used = 0
                        disk_total = 0
                    
                    stats = {
                        "machine_name": machine_name,
                        "cpu_usage_percent": cpu_usage,
                        "memory_used_mb": float(memory_used),
                        "memory_total_mb": float(memory_total),
                        "disk_used_gb": float(disk_used),
                        "disk_total_gb": float(disk_total) if disk_total > 0 else 10.0,
                        "bandwidth_rx_mbps": 0,
                        "bandwidth_tx_mbps": 0,
                        "uptime_seconds": 0,
                        "process_count": 0
                    }
                except Exception as e:
                    continue
                
                try:
                    import urllib.request
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
        result = subprocess.run(
            ["nproc", "--all"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            hardware["cpu_cores"] = int(result.stdout.strip())
    except:
        pass

    try:
        result = subprocess.run(
            ["grep", "MemTotal", "/proc/meminfo"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2 and parts[1].isdigit():
                kb = int(parts[1])
                hardware["memory_gb"] = round(kb / 1024.0 / 1024.0, 2)
    except:
        pass

    try:
        result = subprocess.run(
            ["df", "-BG", "/"],
            capture_output=True, text=True, timeout=10
        )
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
        result = subprocess.run(
            ["bash", "-c", "cat /etc/os-release 2>/dev/null | grep -E '^NAME=|^VERSION=' | tr '\\n' ' ' | sed 's/NAME=//;s/VERSION=//g' | tr -d '\"' || uname -srm"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            hardware["linux_version"] = result.stdout.strip()
    except:
        pass

    return hardware

def register_with_platform():
    hardware = detect_hardware()
    payload = {
        "virt_type": VIRT_TYPE,
        "platform_url": PLATFORM_URL,
    }
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
fi

chmod +x "${INSTALL_DIR}/agent.py"

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
