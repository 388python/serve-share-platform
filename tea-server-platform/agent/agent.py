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
import hashlib
import random
import string

API_KEY = os.environ.get("AGENT_API_KEY")
if not API_KEY:
    raise SystemExit("AGENT_API_KEY is required")
VIRT_TYPE = os.environ.get("VIRT_TYPE", "lxd")
PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:3000")
OPENGFW_ENABLED = os.environ.get("OPENGFW_ENABLED", "false").lower() == "true"
PLATFORM_SSH_PUBKEY = os.environ.get("PLATFORM_SSH_PUBKEY", "")

# 系统镜像映射
SYSTEM_IMAGES = {
    "ubuntu:22.04": {"lxd": "ubuntu:22.04", "kvm": "/var/lib/libvirt/images/base-ubuntu-22.04.qcow2"},
    "ubuntu:24.04": {"lxd": "ubuntu:24.04", "kvm": "/var/lib/libvirt/images/base-ubuntu-24.04.qcow2"},
    "debian:12": {"lxd": "images:debian/12", "kvm": "/var/lib/libvirt/images/base-debian-12.qcow2"},
    "debian:11": {"lxd": "images:debian/11", "kvm": "/var/lib/libvirt/images/base-debian-11.qcow2"},
    "centos:9": {"lxd": "images:centos/9-Stream", "kvm": "/var/lib/libvirt/images/base-centos-9.qcow2"},
    "alpine:3.19": {"lxd": "images:alpine/3.19", "kvm": "/var/lib/libvirt/images/base-alpine-3.19.qcow2"},
}

# 应用镜像配置
APP_IMAGES = {
    "mc": {
        "name": "Minecraft Server",
        "docker_image": "itzg/minecraft-server",
        "ports": [25565],
        "env": {"EULA": "TRUE"},
        "setup_cmd": None,
    },
    "sub2api": {
        "name": "Subscription Converter",
        "docker_image": "tindy2013/subconverter",
        "ports": [25500],
        "env": {},
        "setup_cmd": None,
    },
    "newapi": {
        "name": "New API (One API Fork)",
        "docker_image": "calciumion/new-api",
        "ports": [3000],
        "env": {"SQL_DSN": ""},
        "gen_secrets": {"SESSION_SECRET": 32},
        "setup_cmd": None,
    },
    "cliproxyapi": {
        "name": "CLI Proxy API",
        "docker_image": "ghcr.io/metacubx/cliproxyapi:latest",
        "ports": [8080],
        "env": {},
        "setup_cmd": None,
    },
    "nginx": {
        "name": "Nginx Web Server",
        "docker_image": "nginx:alpine",
        "ports": [80, 443],
        "env": {},
        "setup_cmd": None,
    },
    "mysql": {
        "name": "MySQL Database",
        "docker_image": "mysql:8.0",
        "ports": [3306],
        "env": {},
        "gen_secrets": {"MYSQL_ROOT_PASSWORD": 16},
        "setup_cmd": None,
    },
    "redis": {
        "name": "Redis Cache",
        "docker_image": "redis:alpine",
        "ports": [6379],
        "env": {},
        "setup_cmd": None,
    },
}

def _parse_memory_value(line):
    """Parse memory value with unit and convert to MB"""
    match = re.search(r'(\d+)\s*(MiB|KiB|MB|GB|KB|B)', line, re.IGNORECASE)
    if match:
        value = int(match.group(1))
        unit = match.group(2).lower()
        if unit == 'kib' or unit == 'kb':
            return value / 1024
        elif unit == 'mib' or unit == 'mb':
            return value
        elif unit == 'gb':
            return value * 1024
        elif unit == 'b':
            return value / (1024 * 1024)
    return 0

def generate_password(length=12):
    """Generate random password"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def _lxc_exec(name, cmd, timeout=30):
    """Execute command inside LXD container"""
    return subprocess.run(
        ["lxc", "exec", name, "--", "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout
    )

def _inject_ssh_key(name, public_key, virt="lxd"):
    """Inject SSH public key and enable SSH service"""
    if not public_key:
        return
    
    if virt == "lxd":
        # Create .ssh directory with proper permissions
        _lxc_exec(name, "mkdir -p /root/.ssh && chmod 700 /root/.ssh", timeout=10)
        
        # Append public key to authorized_keys
        _lxc_exec(name, f"echo '{public_key}' >> /root/.ssh/authorized_keys", timeout=10)
        
        # Fix permissions
        _lxc_exec(name, "chmod 600 /root/.ssh/authorized_keys && chown -R root:root /root/.ssh", timeout=10)
        
        # Ensure sshd is installed and running
        _lxc_exec(name, "which sshd || (apt-get update && apt-get install -y openssh-server)", timeout=120)
        
        # Enable and start SSH
        _lxc_exec(name, "mkdir -p /run/sshd && /usr/sbin/sshd || service ssh start || systemctl start sshd 2>/dev/null || true", timeout=20)

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
            self._send_json({"status": "ok", "virt_type": VIRT_TYPE})
        elif path == "/images":
            self._handle_get_images()
        elif path == "/app-images":
            self._handle_get_app_images()
        elif path == "/ports":
            self._handle_get_ports()
        elif path == "/processes":
            self._handle_get_processes()
        elif path.startswith("/traffic/"):
            machine_id = path.split("/")[-1]
            self._handle_get_traffic(machine_id)
        elif path.startswith("/machine/"):
            name = path.split("/")[-1]
            self._handle_get_machine_info(name)
        elif path.startswith("/console/"):
            name = path.split("/")[-1]
            self._handle_get_console(name)
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

    def _handle_get_images(self):
        """Get available system images"""
        self._send_json({"images": list(SYSTEM_IMAGES.keys())})

    def _handle_get_app_images(self):
        """Get available application images"""
        apps = []
        for id, config in APP_IMAGES.items():
            apps.append({
                "id": id,
                "name": config["name"],
                "docker_image": config["docker_image"],
                "ports": config["ports"],
            })
        self._send_json({"app_images": apps})

    def _handle_get_machine_info(self, name):
        """Get machine info including ports and status"""
        try:
            virt = self._get_virt_type_from_name(name)
            
            if virt == "lxd":
                result = subprocess.run(
                    ["lxc", "list", name, "--format", "json"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    if data:
                        info = data[0]
                        status = info.get("status", "unknown")
                        ipv4 = ""
                        for addr in info.get("state", {}).get("network", {}).values():
                            for a in addr.get("addresses", []):
                                if a.get("family") == "inet":
                                    ipv4 = a.get("address", "")
                                    break
                        
                        # Get SSH port (from NAT mapping if exists)
                        ssh_port = 22
                        
                        self._send_json({
                            "name": name,
                            "status": status,
                            "ip": ipv4,
                            "ssh_port": ssh_port,
                            "virt_type": virt,
                        })
                    else:
                        self._send_json({"error": "machine not found"}, 404)
                else:
                    self._send_json({"error": result.stderr}, 500)
            else:
                # KVM
                result = subprocess.run(
                    ["virsh", "dominfo", name],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    status = "running" if "running" in result.stdout else "stopped"
                    self._send_json({
                        "name": name,
                        "status": status,
                        "ssh_port": 22,
                        "virt_type": virt,
                    })
                else:
                    self._send_json({"error": "machine not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_get_console(self, name):
        """Get console access info (web terminal port)"""
        try:
            # Check if novnc is running for this machine
            result = subprocess.run(
                ["docker", "ps", "--filter", f"name=novnc-{name}", "--format", "{{.Ports}}"],
                capture_output=True, text=True, timeout=5
            )
            
            web_port = 0
            if result.returncode == 0 and result.stdout:
                match = re.search(r'0.0.0.0:(\d+)', result.stdout)
                if match:
                    web_port = int(match.group(1))
            
            if web_port == 0:
                # Start novnc container
                web_port = random.randint(6080, 6999)
                subprocess.run([
                    "docker", "run", "-d", "--name", f"novnc-{name}",
                    "-p", f"{web_port}:6080",
                    "-e", f"VNC_HOST={name}",
                    "dorowu/ubuntu-desktop-lxde-vnc"
                ], capture_output=True, timeout=30)
            
            self._send_json({
                "name": name,
                "web_port": web_port,
                "web_url": f"http://{os.environ.get('HOST_IP', 'localhost')}:{web_port}",
            })
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_get_ports(self):
        """Get listening ports"""
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
        """Get running processes"""
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
        """Get traffic stats"""
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
        """Get OpenGFW status"""
        try:
            opengfw_exists = os.path.exists("/usr/local/bin/opengfw")
            result = subprocess.run(["pgrep", "-f", "opengfw"], capture_output=True, text=True)
            opengfw_running = result.returncode == 0
            config_exists = os.path.exists("/etc/opengfw/config.yaml")
            nft_result = subprocess.run(["nft", "list", "table", "opengfw"], capture_output=True, text=True)
            nft_rules_exist = nft_result.returncode == 0

            self._send_json({
                "installed": opengfw_exists,
                "running": opengfw_running,
                "configured": config_exists,
                "nft_rules_active": nft_rules_exist,
            })
        except Exception as e:
            self._send_json({"error": str(e), "installed": False, "running": False})

    def _handle_opengfw_install(self):
        """Install OpenGFW"""
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
                self._send_json({"status": "error", "error": build_result.stderr})
                return

            subprocess.run(["chmod", "+x", "/usr/local/bin/opengfw"], capture_output=True)
            os.makedirs("/etc/opengfw", exist_ok=True)
            subprocess.run(["systemctl", "enable", "nftables"], capture_output=True)
            subprocess.run(["systemctl", "start", "nftables"], capture_output=True)

            self._send_json({"status": "installed"})
        except Exception as e:
            self._send_json({"status": "error", "error": str(e)})

    def _handle_opengfw_config(self):
        """Configure OpenGFW"""
        try:
            req = urllib.request.Request(
                f"{PLATFORM_URL}/api/v1/opengfw/config",
                headers={"X-API-Key": API_KEY},
                method="GET"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                config = json.loads(response.read().decode())

            if not config.get("enabled"):
                self._send_json({"status": "disabled"})
                return

            rules = config.get("rules", [])
            yaml_content = self._generate_opengfw_yaml(rules)
            with open("/etc/opengfw/config.yaml", "w") as f:
                f.write(yaml_content)

            self._apply_nftables_rules(rules)

            subprocess.run(["pkill", "-f", "opengfw"], capture_output=True)
            subprocess.Popen(
                ["/usr/local/bin/opengfw", "-c", "/etc/opengfw/config.yaml"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            self._send_json({"status": "configured", "rules_count": len(rules)})
        except Exception as e:
            self._send_json({"status": "error", "error": str(e)})

    def _generate_opengfw_yaml(self, rules):
        """Generate OpenGFW YAML"""
        actions = []
        for rule in rules:
            proto = rule.get("protocol", "")
            action = rule.get("action", "block")
            sig = rule.get("match_signature", "")
            if sig:
                actions.append(f'  - id: "block_{proto}"\n    match: "{sig}"\n    action: {action}')

        yaml = f'''listen: ":4480"
log:
  level: info
  file: /var/log/opengfw.log
actions:
{chr(10).join(actions)}
'''
        return yaml

    def _apply_nftables_rules(self, rules):
        """Apply nftables rules"""
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
            print(f"NFTables error: {e}")

    def _handle_opengfw_refresh(self):
        self._handle_opengfw_config()

    def _handle_opengfw_uninstall(self):
        """Uninstall OpenGFW"""
        try:
            subprocess.run(["pkill", "-f", "opengfw"], capture_output=True)
            subprocess.run(["rm", "-f", "/usr/local/bin/opengfw"], capture_output=True)
            subprocess.run(["rm", "-rf", "/etc/opengfw"], capture_output=True)
            subprocess.run(["nft", "delete", "table", "ip", "opengfw"], capture_output=True)
            self._send_json({"status": "uninstalled"})
        except Exception as e:
            self._send_json({"status": "error", "error": str(e)})

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
        elif path.startswith("/reinstall/"):
            name = path.split("/")[-1]
            self._handle_reinstall(name, body)
        elif path.startswith("/exec/"):
            name = path.split("/")[-1]
            self._handle_exec(name, body)
        elif path.startswith("/app-install/"):
            name = path.split("/")[-1]
            self._handle_app_install(name, body)
        elif path.startswith("/app-uninstall/"):
            name = path.split("/")[-1]
            self._handle_app_uninstall(name, body)
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_create(self, body):
        """Create VM/container with image and app support"""
        name = body.get("name", f"vm-{body.get('cpu','1')}-{body.get('memory','1024')}")
        cpu = body.get("cpu", 1)
        memory = body.get("memory", 1024)
        disk = body.get("disk", 10)
        virt = body.get("virt_type", VIRT_TYPE)
        image = body.get("image", "ubuntu:22.04")
        app_image = body.get("app_image", "")
        ssh_public_key = body.get("ssh_public_key", PLATFORM_SSH_PUBKEY)
        
        # Generate root password
        root_password = generate_password(16)

        if virt == "lxd":
            # Get LXD image alias
            lxd_image = SYSTEM_IMAGES.get(image, {}).get("lxd", "ubuntu:22.04")
            
            cmd = [
                "lxc", "launch", lxd_image, name,
                "-c", f"limits.cpu={cpu}",
                "-c", f"limits.memory={memory}MB",
                "-c", f"limits.disk={disk}GB"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Try without disk limit
                cmd = [
                    "lxc", "launch", lxd_image, name,
                    "-c", f"limits.cpu={cpu}",
                    "-c", f"limits.memory={memory}MB"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Set root password
                subprocess.run([
                    "lxc", "exec", name, "--", 
                    "bash", "-c", f"echo 'root:{root_password}' | chpasswd"
                ], capture_output=True, timeout=30)
                
                # Inject platform SSH public key and enable SSH
                _inject_ssh_key(name, ssh_public_key, "lxd")
                
                # Install Docker if app_image requires it
                app_secrets = {}
                
                if app_image and APP_IMAGES.get(app_image, {}).get("docker_image"):
                    subprocess.run([
                        "lxc", "exec", name, "--",
                        "bash", "-c", "apt-get update && apt-get install -y docker.io && systemctl start docker"
                    ], capture_output=True, timeout=120)
                    
                    # Install the app
                    app_config = APP_IMAGES.get(app_image, {})
                    if app_config:
                        # Generate dynamic secrets
                        generated_secrets = {}
                        gen_secrets = app_config.get("gen_secrets", {})
                        for secret_key, length in gen_secrets.items():
                            generated_secrets[secret_key] = generate_password(length)
                        app_secrets = generated_secrets
                        
                        docker_cmd = [
                            "lxc", "exec", name, "--",
                            "docker", "run", "-d",
                            "--name", app_image,
                        ]
                        for port in app_config.get("ports", []):
                            docker_cmd.extend(["-p", f"{port}:{port}"])
                        for key, val in app_config.get("env", {}).items():
                            if val:
                                docker_cmd.extend(["-e", f"{key}={val}"])
                        for key, val in generated_secrets.items():
                            docker_cmd.extend(["-e", f"{key}={val}"])
                        docker_cmd.append(app_config["docker_image"])
                        subprocess.run(docker_cmd, capture_output=True, timeout=60)
                
                # Get IP
                ip_result = subprocess.run(
                    ["lxc", "list", name, "--format", "csv", "-c", "4"],
                    capture_output=True, text=True, timeout=10
                )
                ip = ip_result.stdout.strip() if ip_result.returncode == 0 else ""
                
                self._send_json({
                    "status": "created",
                    "ip": ip,
                    "ssh_port": 22,
                    "root_password": root_password,
                    "image": image,
                    "app_image": app_image,
                    "app_secrets": app_secrets,
                    "output": result.stdout,
                })
            else:
                self._send_json({
                    "status": "error",
                    "error": result.stderr
                })

        elif virt == "kvm":
            kvm_base = SYSTEM_IMAGES.get(image, {}).get("kvm", "/var/lib/libvirt/images/base-ubuntu.qcow2")
            disk_path = f"/var/lib/libvirt/images/{name}.qcow2"

            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-b", kvm_base, "-F", "qcow2", disk_path],
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
                "--graphics", "vnc,listen=0.0.0.0,port=-1",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Get VNC port
                vnc_result = subprocess.run(
                    ["virsh", "vncdisplay", name],
                    capture_output=True, text=True, timeout=10
                )
                vnc_port = 5900
                if vnc_result.returncode == 0:
                    match = re.search(r':(\d+)', vnc_result.stdout)
                    if match:
                        vnc_port = 5900 + int(match.group(1))
                
                self._send_json({
                    "status": "created",
                    "ssh_port": 22,
                    "vnc_port": vnc_port,
                    "root_password": root_password,
                    "image": image,
                    "app_image": app_image,
                    "output": result.stdout,
                })
            else:
                self._send_json({
                    "status": "error",
                    "error": result.stderr
                })
        else:
            self._send_json({"error": f"unsupported virt_type: {virt}"})

    def _handle_stop(self, name):
        """Stop VM/container"""
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
        
        # Also stop any associated novnc container
        subprocess.run(["docker", "rm", "-f", f"novnc-{name}"], capture_output=True)
        
        self._send_json({
            "status": "stopped" if result.returncode == 0 else "error",
            "output": result.stdout,
            "error": result.stderr
        })

    def _handle_reinstall(self, name, body):
        """Reinstall VM/container with new image"""
        image = body.get("image", "ubuntu:22.04")
        app_image = body.get("app_image", "")
        ssh_public_key = body.get("ssh_public_key", PLATFORM_SSH_PUBKEY)
        
        # First stop and delete
        self._handle_stop(name)
        
        # Then recreate with new image
        time.sleep(2)
        
        # Get original specs from platform
        try:
            req = urllib.request.Request(
                f"{PLATFORM_URL}/api/v1/machine/{name.replace('machine-', '')}",
                headers={"X-API-Key": API_KEY},
                method="GET"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                machine_info = json.loads(response.read().decode())
            
            create_body = {
                "name": name,
                "cpu": machine_info.get("cpu_cores", 1),
                "memory": int(machine_info.get("memory_gb", 1) * 1024),
                "disk": machine_info.get("disk_gb", 10),
                "virt_type": machine_info.get("virt_type", VIRT_TYPE),
                "image": image,
                "app_image": app_image,
                "ssh_public_key": ssh_public_key,
            }
            self._handle_create(create_body)
        except Exception as e:
            self._send_json({"status": "error", "error": str(e)})

    def _handle_exec(self, name, body):
        """Execute command in VM/container"""
        command = body.get("command", "")
        if not command:
            self._send_json({"error": "command required"}, 400)
            return
        
        virt = self._get_virt_type_from_name(name)
        
        if virt == "lxd":
            result = subprocess.run(
                ["lxc", "exec", name, "--", "bash", "-c", command],
                capture_output=True, text=True, timeout=60
            )
        else:
            # KVM - use ssh or guestfish
            result = subprocess.run(
                ["virsh", "qemu-agent-command", name, f"'{command}'"],
                capture_output=True, text=True, timeout=60
            )
        
        self._send_json({
            "status": "success" if result.returncode == 0 else "error",
            "stdout": result.stdout,
            "stderr": result.stderr,
        })

    def _handle_app_install(self, name, body):
        """Install application in VM/container"""
        app_image = body.get("app_image", "")
        if not app_image:
            self._send_json({"error": "app_image required"}, 400)
            return
        
        app_config = APP_IMAGES.get(app_image)
        if not app_config:
            self._send_json({"error": f"unknown app: {app_image}"}, 400)
            return
        
        virt = self._get_virt_type_from_name(name)
        
        if virt == "lxd":
            # Ensure Docker is installed
            subprocess.run([
                "lxc", "exec", name, "--",
                "bash", "-c", "apt-get update -qq && apt-get install -y -qq docker.io && systemctl start docker"
            ], capture_output=True, timeout=120)
            
            # Generate dynamic secrets
            generated_secrets = {}
            gen_secrets = app_config.get("gen_secrets", {})
            for secret_key, length in gen_secrets.items():
                generated_secrets[secret_key] = generate_password(length)
            
            # Build docker run command
            docker_cmd = ["lxc", "exec", name, "--", "docker", "run", "-d", "--name", app_image]
            for port in app_config.get("ports", []):
                docker_cmd.extend(["-p", f"{port}:{port}"])
            for key, val in app_config.get("env", {}).items():
                if val:
                    docker_cmd.extend(["-e", f"{key}={val}"])
            for key, val in generated_secrets.items():
                docker_cmd.extend(["-e", f"{key}={val}"])
            docker_cmd.append(app_config["docker_image"])
            
            result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60)
            
            self._send_json({
                "status": "installed" if result.returncode == 0 else "error",
                "app_name": app_config["name"],
                "ports": app_config["ports"],
                "secrets": generated_secrets,
                "output": result.stdout,
                "error": result.stderr,
            })
        else:
            self._send_json({"error": "KVM app install not supported yet"}, 400)

    def _handle_app_uninstall(self, name, body):
        """Uninstall application from VM/container"""
        app_image = body.get("app_image", "")
        if not app_image:
            self._send_json({"error": "app_image required"}, 400)
            return
        
        virt = self._get_virt_type_from_name(name)
        
        if virt == "lxd":
            result = subprocess.run([
                "lxc", "exec", name, "--",
                "docker", "rm", "-f", app_image
            ], capture_output=True, text=True, timeout=30)
            
            self._send_json({
                "status": "uninstalled" if result.returncode == 0 else "error",
                "output": result.stdout,
                "error": result.stderr,
            })
        else:
            self._send_json({"error": "KVM app uninstall not supported yet"}, 400)

    def do_DELETE(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        path = urlparse(self.path).path
        name = path.strip("/")

        if not name:
            self._send_json({"error": "name required"}, 400)
            return

        self._handle_stop(name)

def report_stats_loop():
    """Background thread to report stats"""
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
                    memory_used = 0.0
                    memory_total = 0.0
                    
                    for info_line in info_result.stdout.split("\n"):
                        info_line = info_line.strip()
                        if "CPU usage:" in info_line:
                            match = re.search(r'(\d+\.?\d*)', info_line.split("CPU usage:")[1])
                            if match:
                                cpu_usage = float(match.group(1))
                        elif "Memory usage:" in info_line:
                            memory_used = _parse_memory_value(info_line)
                        elif "Memory:" in info_line:
                            memory_total = _parse_memory_value(info_line)
                    
                    stats = {
                        "machine_name": machine_name,
                        "cpu_usage_percent": cpu_usage,
                        "memory_used_mb": memory_used,
                        "memory_total_mb": memory_total,
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
                    print(f"Stats error for {machine_name}: {e}")
        except Exception as e:
            print(f"Stats loop error: {e}")
        
        time.sleep(60)

def detect_hardware():
    """Detect hardware specs"""
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

    return hardware

def register_with_platform():
    """Register agent with platform"""
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
            print(f"[agent] Registered: {result}")
    except Exception as e:
        print(f"[agent] Register failed: {e}")

if __name__ == "__main__":
    register_thread = threading.Thread(target=register_with_platform, daemon=True)
    register_thread.start()

    stats_thread = threading.Thread(target=report_stats_loop, daemon=True)
    stats_thread.start()
    
    server = HTTPServer(("0.0.0.0", 19527), AgentHandler)
    print(f"Agent running on port 19527, virt_type={VIRT_TYPE}")
    server.serve_forever()