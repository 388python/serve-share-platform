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
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')

API_KEY = os.environ.get("AGENT_API_KEY")
if not API_KEY:
    raise SystemExit("AGENT_API_KEY is required")
VIRT_TYPE = os.environ.get("VIRT_TYPE", "lxd")
PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:3000")
OPENGFW_ENABLED = os.environ.get("OPENGFW_ENABLED", "false").lower() == "true"
PLATFORM_SSH_PUBKEY = os.environ.get("PLATFORM_SSH_PUBKEY", "")

# 端口映射范围
PORT_RANGE_START = 20000
PORT_RANGE_END = 30000

# 已使用的端口
USED_PORTS = set()

# 系统镜像映射
SYSTEM_IMAGES = {
    # Linux
    "ubuntu:22.04": {"lxd": "ubuntu:22.04", "kvm": "/var/lib/libvirt/images/base-ubuntu-22.04.qcow2", "type": "linux", "ssh": True},
    "ubuntu:24.04": {"lxd": "ubuntu:24.04", "kvm": "/var/lib/libvirt/images/base-ubuntu-24.04.qcow2", "type": "linux", "ssh": True},
    "debian:12": {"lxd": "images:debian/12", "kvm": "/var/lib/libvirt/images/base-debian-12.qcow2", "type": "linux", "ssh": True},
    "debian:11": {"lxd": "images:debian/11", "kvm": "/var/lib/libvirt/images/base-debian-11.qcow2", "type": "linux", "ssh": True},
    "centos:9": {"lxd": "images:centos/9-Stream", "kvm": "/var/lib/libvirt/images/base-centos-9.qcow2", "type": "linux", "ssh": True},
    "alpine:3.19": {"lxd": "images:alpine/3.19", "kvm": "/var/lib/libvirt/images/base-alpine-3.19.qcow2", "type": "linux", "ssh": True},
    # Windows - 自动下载/构建，支持SSH和RDP
    "windows:2019": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win2019.qcow2", "type": "windows", "ssh": True, "rdp": True},
    "windows:2022": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win2022.qcow2", "type": "windows", "ssh": True, "rdp": True},
    "windows:2025": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win2025.qcow2", "type": "windows", "ssh": True, "rdp": True},
    "windows:10": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win10.qcow2", "type": "windows", "ssh": True, "rdp": True},
    "windows:11": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win11.qcow2", "type": "windows", "ssh": True, "rdp": True},
}

# Windows VirtIO 驱动 ISO 路径（用于 ISO 安装方式）
VIRTIO_ISO_PATH = "/var/lib/libvirt/images/virtio-win.iso"

# Windows 自动应答文件路径（用于 ISO 安装方式）
WINDOWS_AUTOUNATTEND_PATH = "/var/lib/libvirt/images/autounattend.xml"

# Windows 镜像自动下载配置
# 注意：需要合法的 Windows 镜像授权，以下是一些示例源
# 实际使用时替换为您自己托管的或合法的镜像
WINDOWS_IMAGE_SOURCES = {
    # 这些URL是示例，实际使用时需要替换为有效的镜像源
    # 可以使用 virt-builder 构建评估版，或从微软评估中心下载
    "windows:2019": "",
    "windows:2022": "",
    "windows:2025": "",
    "windows:10": "",
    "windows:11": "",
}

# virt-builder 官方支持的 Windows 版本（评估版）
VIRTBUILDER_WINDOWS_MAP = {
    "windows:2019": "win10",  # Windows 10/Server 2019 评估版
    "windows:2022": "win10",  # Windows Server 2022 评估版
    "windows:2025": "win10",  # Windows Server 2025 评估版
    "windows:10": "win10",
    "windows:11": "win11",
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

def allocate_port():
    """分配一个可用端口"""
    global USED_PORTS
    for port in range(PORT_RANGE_START, PORT_RANGE_END):
        if port not in USED_PORTS:
            # 检查端口是否真的可用
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5
            )
            if f":{port}" not in result.stdout:
                USED_PORTS.add(port)
                return port
    raise Exception("No available ports")

def release_port(port):
    """释放端口"""
    global USED_PORTS
    USED_PORTS.discard(port)

def ensure_dependencies():
    """自动安装所需依赖"""
    deps = [
        ("qemu-img", "qemu-utils"),
        ("virt-install", "virtinst"),
        ("virsh", "libvirt-clients"),
        ("curl", "curl"),
        ("ss", "iproute2"),
    ]
    
    for cmd, pkg in deps:
        result = subprocess.run(["which", cmd], capture_output=True)
        if result.returncode != 0:
            logging.info(f"Installing {pkg}...")
            subprocess.run([
                "apt-get", "update", "-qq"
            ], capture_output=True, timeout=120)
            subprocess.run([
                "apt-get", "install", "-y", "-qq", pkg
            ], capture_output=True, timeout=180)
    
    # 安装 libguestfs-tools 用于 virt-builder
    result = subprocess.run(["which", "virt-builder"], capture_output=True)
    if result.returncode != 0:
        logging.info("Installing libguestfs-tools for Windows support...")
        subprocess.run([
            "apt-get", "install", "-y", "-qq", 
            "libguestfs-tools", "linux-image-generic"
        ], capture_output=True, timeout=300)
    
    # 确保 libvirtd 运行
    subprocess.run(["systemctl", "start", "libvirtd"], capture_output=True)
    subprocess.run(["systemctl", "enable", "libvirtd"], capture_output=True)
    
    logging.info("Dependencies installed")

def setup_port_forwarding(host_port, vm_ip, vm_port, protocol="tcp"):
    """设置端口转发规则"""
    # 使用 iptables 设置 NAT
    subprocess.run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", protocol, "--dport", str(host_port),
        "-j", "DNAT", "--to-destination", f"{vm_ip}:{vm_port}"
    ], capture_output=True)
    
    subprocess.run([
        "iptables", "-t", "nat", "-A", "POSTROUTING",
        "-p", protocol, "-d", vm_ip, "--dport", str(vm_port),
        "-j", "MASQUERADE"
    ], capture_output=True)
    
    logging.info(f"Port forwarding: {host_port} -> {vm_ip}:{vm_port}")

def remove_port_forwarding(host_port, vm_ip, vm_port, protocol="tcp"):
    """移除端口转发规则"""
    subprocess.run([
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-p", protocol, "--dport", str(host_port),
        "-j", "DNAT", "--to-destination", f"{vm_ip}:{vm_port}"
    ], capture_output=True, stderr=subprocess.DEVNULL)
    
    subprocess.run([
        "iptables", "-t", "nat", "-D", "POSTROUTING",
        "-p", protocol, "-d", vm_ip, "--dport", str(vm_port),
        "-j", "MASQUERADE"
    ], capture_output=True, stderr=subprocess.DEVNULL)

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
                    
                    # Check if noVNC is running
                    novnc_result = subprocess.run(
                        ["docker", "ps", "--filter", f"name=novnc-{name}", "--format", "{{.Ports}}"],
                        capture_output=True, text=True, timeout=5
                    )
                    novnc_port = 0
                    if novnc_result.returncode == 0 and novnc_result.stdout:
                        match = re.search(r'0.0.0.0:(\d+)', novnc_result.stdout)
                        if match:
                            novnc_port = int(match.group(1))
                    
                    # Get image type to determine if it's Windows
                    image = os.path.basename(
                        subprocess.run(
                            ["virsh", "domblklist", name, "--details"],
                            capture_output=True, text=True, timeout=10
                        ).stdout.split("\n")[2] if subprocess.run(
                            ["virsh", "domblklist", name, "--details"],
                            capture_output=True, text=True, timeout=10
                        ).returncode == 0 else ""
                    )
                    
                    response_data = {
                        "name": name,
                        "status": status,
                        "virt_type": virt,
                        "vnc_port": vnc_port,
                        "novnc_port": novnc_port,
                    }
                    
                    # Check if this is a Windows VM based on image path
                    for win_image, config in SYSTEM_IMAGES.items():
                        if config.get("type") == "windows":
                            base_path = config.get("kvm", "")
                            if base_path and base_path in image:
                                response_data.update({
                                    "os_type": "windows",
                                    "rdp_port": config.get("rdp_port", 3389),
                                    "ssh_port": None,
                                    "note": "Windows 虚拟机"
                                })
                                break
                    else:
                        response_data.update({
                            "os_type": "linux",
                            "ssh_port": 22,
                        })
                    
                    self._send_json(response_data)
                else:
                    self._send_json({"error": "machine not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _setup_novnc(self, name, vnc_port):
        """Setup noVNC container for KVM VNC access"""
        try:
            # Remove existing novnc container if any
            subprocess.run(
                ["docker", "rm", "-f", f"novnc-{name}"],
                capture_output=True, timeout=5
            )
            
            # Find an available port
            web_port = random.randint(7900, 8999)
            
            # Start novnc container that connects to VNC
            # Using the standard novnc image with websocket proxy
            result = subprocess.run([
                "docker", "run", "-d",
                "--name", f"novnc-{name}",
                "-p", f"{web_port}:6080",
                f"novnc/novnc:latest",
                "--vnc", f"127.0.0.1:{vnc_port}"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return web_port
            else:
                logging.warning(f"Failed to start novnc: {result.stderr}")
                return 0
        except Exception as e:
            logging.warning(f"novnc setup failed: {e}")
            return 0

    def _prepare_windows_image(self, image, kvm_base):
        """自动下载或生成Windows镜像"""
        # 如果镜像已存在，直接返回
        if os.path.exists(kvm_base):
            print(f"[agent] Windows base image already exists: {kvm_base}")
            return True
        
        # 确保目录存在
        os.makedirs(os.path.dirname(kvm_base), exist_ok=True)
        
        # 获取下载URL
        download_url = WINDOWS_IMAGE_SOURCES.get(image)
        if not download_url:
            print(f"[agent] No download URL for {image}, trying virt-builder")
            return self._build_windows_with_virtbuilder(image, kvm_base)
        
        # 尝试下载镜像
        print(f"[agent] Downloading Windows image from {download_url}")
        print(f"[agent] This may take several minutes...")
        
        try:
            # 使用curl下载，带进度显示
            result = subprocess.run([
                "curl", "-L", "-#",
                "-o", kvm_base,
                download_url
            ], capture_output=True, text=True, timeout=3600)  # 1小时超时
            
            if result.returncode == 0 and os.path.exists(kvm_base):
                # 检查文件大小，确保下载成功
                size = os.path.getsize(kvm_base)
                if size > 100 * 1024 * 1024:  # 大于100MB
                    print(f"[agent] Downloaded Windows image: {size // (1024*1024)}MB")
                    return True
                else:
                    print(f"[agent] Downloaded file too small: {size} bytes")
                    os.remove(kvm_base)
            else:
                print(f"[agent] Download failed: {result.stderr}")
        except Exception as e:
            print(f"[agent] Download error: {e}")
        
        # 下载失败，尝试 virt-builder
        return self._build_windows_with_virtbuilder(image, kvm_base)
    
    def _build_windows_with_virtbuilder(self, image, kvm_base):
        """使用 virt-builder 构建 Windows 镜像"""
        print(f"[agent] Trying virt-builder for {image}")
        
        # 检查 virt-builder 是否可用
        result = subprocess.run(["which", "virt-builder"], capture_output=True)
        if result.returncode != 0:
            print(f"[agent] virt-builder not found, install with: apt-get install libguestfs-tools")
            return False
        
        os_variant = VIRTBUILDER_WINDOWS_MAP.get(image, "win10")
        
        try:
            # virt-builder 构建命令 - 构建评估版Windows
            cmd = [
                "virt-builder", os_variant,
                "--output", kvm_base,
                "--format", "qcow2",
                "--size", "40G",
                "--root-password", "password:ChangeMe123!",
            ]
            
            print(f"[agent] Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            
            if result.returncode == 0 and os.path.exists(kvm_base):
                size = os.path.getsize(kvm_base) // (1024*1024)
                print(f"[agent] Built Windows image with virt-builder: {size}MB")
                return True
            else:
                print(f"[agent] virt-builder failed: {result.stderr}")
        except Exception as e:
            print(f"[agent] virt-builder error: {e}")
        
        return False

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
        user_root_password = body.get("root_password", "")
        user_app_secrets = body.get("app_secrets", {})
        
        # Use user-provided root password if available, otherwise generate one
        root_password = user_root_password if user_root_password else generate_password(16)

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
                        # Use user-provided secrets if available, otherwise generate dynamic ones
                        generated_secrets = {}
                        gen_secrets = app_config.get("gen_secrets", {})
                        for secret_key, length in gen_secrets.items():
                            if secret_key in user_app_secrets and user_app_secrets[secret_key]:
                                generated_secrets[secret_key] = user_app_secrets[secret_key]
                            else:
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
            # 确保依赖已安装
            ensure_dependencies()
            
            # Get image configuration
            image_config = SYSTEM_IMAGES.get(image, {})
            kvm_base = image_config.get("kvm", "/var/lib/libvirt/images/base-ubuntu.qcow2")
            os_type = image_config.get("type", "linux")
            is_windows = os_type == "windows"
            supports_ssh = image_config.get("ssh", True)
            supports_rdp = image_config.get("rdp", False) if is_windows else False
            
            disk_path = f"/var/lib/libvirt/images/{name}.qcow2"

            # Windows 镜像自动准备
            if is_windows:
                logging.info(f"Preparing Windows image for {image}...")
                if not self._prepare_windows_image(image, kvm_base):
                    self._send_json({
                        "status": "error",
                        "error": f"Failed to prepare Windows image. Please ensure virt-builder or network is available."
                    })
                    return
                
                # 确保 VirtIO 驱动 ISO 可用
                if not os.path.exists(VIRTIO_ISO_PATH):
                    logging.info("Downloading VirtIO drivers...")
                    subprocess.run([
                        "curl", "-L", "-o", VIRTIO_ISO_PATH,
                        "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.229-2/virtio-win-0.1.229.iso"
                    ], capture_output=True, timeout=300)
            elif not os.path.exists(kvm_base):
                # Linux base image 不存在，尝试从 LXD 镜像导出
                logging.info(f"Creating Linux base image from LXD...")
                lxd_image = image_config.get("lxd", image)
                if lxd_image:
                    # 创建临时容器导出镜像
                    subprocess.run(["lxc", "launch", lxd_image, "temp-base", "--ephemeral"], 
                                  capture_output=True, timeout=60)
                    time.sleep(5)
                    subprocess.run([
                        "lxc", "exec", "temp-base", "--", 
                        "dd", "if=/dev/sda", "of=/tmp/rootfs.img"
                    ], capture_output=True, timeout=120)
                    subprocess.run(["lxc", "file", "pull", "temp-base/tmp/rootfs.img", kvm_base],
                                  capture_output=True, timeout=60)
                    subprocess.run(["lxc", "delete", "--force", "temp-base"], capture_output=True)
                    subprocess.run(["qemu-img", "convert", "-O", "qcow2", kvm_base + ".img", kvm_base],
                                  capture_output=True)
                    if os.path.exists(kvm_base):
                        logging.info(f"Created base image: {kvm_base}")
                    else:
                        self._send_json({
                            "status": "error",
                            "error": f"Failed to create Linux base image"
                        })
                        return
                else:
                    self._send_json({
                        "status": "error",
                        "error": f"Linux base image not found: {kvm_base}"
                    })
                    return
            
            # Create disk from base image
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-b", kvm_base, "-F", "qcow2", disk_path, str(disk) + "G"],
                capture_output=True, timeout=30
            )

            # 分配外部端口
            ssh_external_port = allocate_port() if supports_ssh else None
            rdp_external_port = allocate_port() if supports_rdp else None
            vnc_external_port = allocate_port()
            novnc_external_port = allocate_port()

            # Build virt-install command
            if is_windows:
                # Windows VM configuration
                win_ver = image.split(':')[1] if ':' in image else "10"
                cmd = [
                    "virt-install",
                    "--name", name,
                    "--vcpus", str(cpu),
                    "--memory", str(memory),
                    "--disk", f"path={disk_path},format=qcow2,bus=virtio",
                    "--boot", "hd",
                    "--os-variant", f"win{win_ver}",
                    "--noautoconsole",
                    "--graphics", f"vnc,listen=0.0.0.0,port={vnc_external_port - 5900}",
                    "--video", "virtio",
                    "--network", f"bridge=virbr0,model=virtio",
                    "--controller", "usb,model=ehci",
                ]
                
                # Add VirtIO CD-ROM
                if os.path.exists(VIRTIO_ISO_PATH):
                    cmd.extend(["--disk", f"path={VIRTIO_ISO_PATH},device=cdrom"])
            else:
                # Linux VM configuration
                os_variant_map = {
                    "ubuntu:22.04": "ubuntu22.04",
                    "ubuntu:24.04": "ubuntu24.04",
                    "debian:12": "debian12",
                    "debian:11": "debian11",
                    "centos:9": "centos9",
                    "alpine:3.19": "alpine3.19",
                }
                os_variant = os_variant_map.get(image, "ubuntu22.04")
                
                cmd = [
                    "virt-install",
                    "--name", name,
                    "--vcpus", str(cpu),
                    "--memory", str(memory),
                    "--disk", f"path={disk_path},format=qcow2",
                    "--boot", "hd",
                    "--os-variant", os_variant,
                    "--noautoconsole",
                    "--graphics", f"vnc,listen=0.0.0.0,port={vnc_external_port - 5900}",
                    "--network", "bridge=virbr0",
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # 等待VM启动获取IP
                time.sleep(10)
                vm_ip = self._get_vm_ip(name)
                
                # Setup noVNC for web-based VNC access
                novnc_port = self._setup_novnc_port(name, vnc_external_port, novnc_external_port)
                
                # 设置端口转发
                if vm_ip:
                    if ssh_external_port and supports_ssh:
                        setup_port_forwarding(ssh_external_port, vm_ip, 22)
                    if rdp_external_port and supports_rdp:
                        setup_port_forwarding(rdp_external_port, vm_ip, 3389)
                
                # 响应数据
                response_data = {
                    "status": "created",
                    "ip": vm_ip or "",
                    "image": image,
                    "app_image": app_image,
                    "vnc_port": vnc_external_port,
                    "novnc_port": novnc_external_port,
                    "root_password": root_password,
                    "output": result.stdout,
                }
                
                if is_windows:
                    response_data.update({
                        "os_type": "windows",
                        "ssh_port": ssh_external_port,  # Windows 有 OpenSSH
                        "rdp_port": rdp_external_port,
                        "ssh_note": "Windows 内置 OpenSSH Server，端口已映射",
                        "rdp_note": "RDP 端口已映射，可用 mstsc 连接",
                    })
                else:
                    response_data.update({
                        "os_type": "linux",
                        "ssh_port": ssh_external_port,
                    })
                
                self._send_json(response_data)
            else:
                # 释放已分配的端口
                if ssh_external_port: release_port(ssh_external_port)
                if rdp_external_port: release_port(rdp_external_port)
                if vnc_external_port: release_port(vnc_external_port)
                if novnc_external_port: release_port(novnc_external_port)
                
                self._send_json({
                    "status": "error",
                    "error": result.stderr
                })
        else:
            self._send_json({"error": f"unsupported virt_type: {virt}"})

    def _get_vm_ip(self, name, timeout=60):
        """获取KVM虚拟机IP地址"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            # 尝试通过 arp 获取 IP
            result = subprocess.run(
                ["virsh", "domifaddr", name],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                match = re.search(r'\d+\.\d+\.\d+\.\d+', result.stdout)
                if match:
                    return match.group(0)
            
            # 尝试通过 qemu-guest-agent
            result = subprocess.run(
                ["virsh", "qemu-agent-command", name, '{"execute":"guest-network-get-interfaces"}'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    for iface in data.get("return", []):
                        for ip_info in iface.get("ip-addresses", []):
                            if ip_info.get("ip-address-type") == "ipv4":
                                return ip_info.get("ip-address")
                except:
                    pass
            
            # 尝试通过 arp 表
            result = subprocess.run(
                ["arp", "-an"],
                capture_output=True, text=True, timeout=5
            )
            # 查找 virbr0 相关的 IP
            for line in result.stdout.split('\n'):
                if 'virbr0' in line:
                    match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if match:
                        return match.group(0)
            
            time.sleep(2)
        
        return None

    def _setup_novnc_port(self, name, vnc_port, web_port):
        """Setup noVNC web access"""
        try:
            # Remove existing novnc container if any
            subprocess.run(
                ["docker", "rm", "-f", f"novnc-{name}"],
                capture_output=True, timeout=5
            )
            
            # Start novnc container
            result = subprocess.run([
                "docker", "run", "-d",
                "--name", f"novnc-{name}",
                "-p", f"{web_port}:6080",
                "novnc/novnc:latest",
                "--vnc", f"127.0.0.1:{vnc_port}"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                logging.info(f"noVNC started on port {web_port}")
                return web_port
            else:
                logging.warning(f"Failed to start novnc: {result.stderr}")
                release_port(web_port)
                return 0
        except Exception as e:
            logging.warning(f"novnc setup failed: {e}")
            release_port(web_port)
            return 0

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
        
        user_secrets = body.get("secrets", {})
        
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
            
            # Use user-provided secrets if available, otherwise generate dynamic ones
            generated_secrets = {}
            gen_secrets = app_config.get("gen_secrets", {})
            for secret_key, length in gen_secrets.items():
                if secret_key in user_secrets and user_secrets[secret_key]:
                    generated_secrets[secret_key] = user_secrets[secret_key]
                else:
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
    # 自动安装依赖（如果使用KVM）
    if VIRT_TYPE == "kvm":
        print("Checking and installing KVM dependencies...")
        ensure_dependencies()
    
    register_thread = threading.Thread(target=register_with_platform, daemon=True)
    register_thread.start()

    stats_thread = threading.Thread(target=report_stats_loop, daemon=True)
    stats_thread.start()
    
    server = HTTPServer(("0.0.0.0", 19527), AgentHandler)
    print(f"Agent running on port 19527, virt_type={VIRT_TYPE}")
    server.serve_forever()