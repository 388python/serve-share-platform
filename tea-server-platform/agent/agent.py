#!/usr/bin/env python3
"""
TEA Server Platform Agent
管理虚拟机/容器生命周期、应用部署、网络配置等功能
"""

import json
import logging
import os
import random
import re
import socket
import string
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
logger = logging.getLogger(__name__)

# =============================================================================
# 配置常量
# =============================================================================

API_KEY = os.environ.get("AGENT_API_KEY")
if not API_KEY:
    raise SystemExit("AGENT_API_KEY is required")

VIRT_TYPE = os.environ.get("VIRT_TYPE", "lxd")
PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:3000")
OPENGFW_ENABLED = os.environ.get("OPENGFW_ENABLED", "false").lower() == "true"
PLATFORM_SSH_PUBKEY = os.environ.get("PLATFORM_SSH_PUBKEY", "")

PORT_RANGE_START = 20000
PORT_RANGE_END = 30000

AGENT_PORT = 19527
STATS_REPORT_INTERVAL = 60

USED_PORTS: set = set()
USED_PORTS_LOCK = threading.Lock()

VIRTIO_ISO_PATH = "/var/lib/libvirt/images/virtio-win.iso"
WINDOWS_AUTOUNATTEND_PATH = "/var/lib/libvirt/images/autounattend.xml"


def escape_shell_arg(s: str) -> str:
    """Escape a string for safe use in shell commands.
    Returns the string wrapped in single quotes with internal single quotes escaped."""
    return "'" + s.replace("'", "'\\''") + "'"


def escape_xml_attr(s: str) -> str:
    """Escape a string for safe use in XML attribute values."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&apos;"))

SYSTEM_IMAGES: Dict[str, Dict[str, Any]] = {
    "ubuntu:22.04": {"lxd": "ubuntu:22.04", "kvm": "/var/lib/libvirt/images/base-ubuntu-22.04.qcow2", "type": "linux", "ssh": True},
    "ubuntu:24.04": {"lxd": "ubuntu:24.04", "kvm": "/var/lib/libvirt/images/base-ubuntu-24.04.qcow2", "type": "linux", "ssh": True},
    "debian:12": {"lxd": "images:debian/12", "kvm": "/var/lib/libvirt/images/base-debian-12.qcow2", "type": "linux", "ssh": True},
    "debian:11": {"lxd": "images:debian/11", "kvm": "/var/lib/libvirt/images/base-debian-11.qcow2", "type": "linux", "ssh": True},
    "centos:9": {"lxd": "images:centos/9-Stream", "kvm": "/var/lib/libvirt/images/base-centos-9.qcow2", "type": "linux", "ssh": True},
    "alpine:3.19": {"lxd": "images:alpine/3.19", "kvm": "/var/lib/libvirt/images/base-alpine-3.19.qcow2", "type": "linux", "ssh": True},
    "windows:2019": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win2019.qcow2", "type": "windows", "ssh": True, "rdp": True},
    "windows:2022": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win2022.qcow2", "type": "windows", "ssh": True, "rdp": True},
    "windows:2025": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win2025.qcow2", "type": "windows", "ssh": True, "rdp": True},
    "windows:10": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win10.qcow2", "type": "windows", "ssh": True, "rdp": True},
    "windows:11": {"lxd": None, "kvm": "/var/lib/libvirt/images/base-win11.qcow2", "type": "windows", "ssh": True, "rdp": True},
}

WINDOWS_IMAGE_SOURCES: Dict[str, str] = {
    "windows:2019": "",
    "windows:2022": "",
    "windows:2025": "",
    "windows:10": "",
    "windows:11": "",
}

VIRTBUILDER_WINDOWS_MAP: Dict[str, str] = {
    "windows:2019": "win10",
    "windows:2022": "win10",
    "windows:2025": "win10",
    "windows:10": "win10",
    "windows:11": "win11",
}

OS_VARIANT_MAP: Dict[str, str] = {
    "ubuntu:22.04": "ubuntu22.04",
    "ubuntu:24.04": "ubuntu24.04",
    "debian:12": "debian12",
    "debian:11": "debian11",
    "centos:9": "centos9",
    "alpine:3.19": "alpine3.19",
}

APP_IMAGES: Dict[str, Dict[str, Any]] = {
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

DEPENDENCIES: List[Tuple[str, str]] = [
    ("qemu-img", "qemu-utils"),
    ("virt-install", "virtinst"),
    ("virsh", "libvirt-clients"),
    ("curl", "curl"),
    ("ss", "iproute2"),
]


# =============================================================================
# 工具函数 - 通用工具
# =============================================================================

def parse_memory_value(line: str) -> float:
    """Parse memory value with unit and convert to MB"""
    match = re.search(r'(\d+)\s*(MiB|KiB|MB|GB|KB|B)', line, re.IGNORECASE)
    if not match:
        return 0.0

    value = int(match.group(1))
    unit = match.group(2).lower()

    unit_conversions = {
        'b': 1 / (1024 * 1024),
        'kib': 1 / 1024,
        'kb': 1 / 1024,
        'mib': 1,
        'mb': 1,
        'gb': 1024,
    }
    return value * unit_conversions.get(unit, 0)


def generate_password(length: int = 12) -> str:
    """Generate random password"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def generate_secrets(gen_secrets_config: Dict[str, int], user_secrets: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Generate secrets based on config, using user-provided values if available"""
    user_secrets = user_secrets or {}
    generated: Dict[str, str] = {}

    for secret_key, length in gen_secrets_config.items():
        if secret_key in user_secrets and user_secrets[secret_key]:
            generated[secret_key] = user_secrets[secret_key]
        else:
            generated[secret_key] = generate_password(length)

    return generated


def build_docker_run_args(app_config: Dict[str, Any], secrets: Dict[str, str]) -> List[str]:
    """Build docker run command arguments from app config and secrets"""
    args: List[str] = []

    for port in app_config.get("ports", []):
        args.extend(["-p", f"{port}:{port}"])

    for key, val in app_config.get("env", {}).items():
        if val:
            args.extend(["-e", f"{key}={val}"])

    for key, val in secrets.items():
        args.extend(["-e", f"{key}={val}"])

    return args


def platform_request(endpoint: str, method: str = "GET", data: Optional[Dict[str, Any]] = None, timeout: int = 10) -> Dict[str, Any]:
    """Make HTTP request to platform API"""
    url = f"{PLATFORM_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    headers = {"Content-Type": "application/json", "X-API-Key": API_KEY}

    request_data = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=request_data, headers=headers, method=method)

    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode())


# =============================================================================
# 工具函数 - 端口管理
# =============================================================================

def allocate_port() -> int:
    """Allocate an available port from the port range (thread-safe)"""
    with USED_PORTS_LOCK:
        for port in range(PORT_RANGE_START, PORT_RANGE_END):
            if port in USED_PORTS:
                continue

            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5
            )
            if f":{port}" not in result.stdout:
                USED_PORTS.add(port)
                return port

        raise RuntimeError("No available ports in range")


def release_port(port: Optional[int]) -> None:
    """Release an allocated port (thread-safe)"""
    if port is not None:
        with USED_PORTS_LOCK:
            USED_PORTS.discard(port)


def setup_port_forwarding(host_port: int, vm_ip: str, vm_port: int, protocol: str = "tcp") -> None:
    """Setup iptables port forwarding rule"""
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

    logger.info("Port forwarding: %d -> %s:%d", host_port, vm_ip, vm_port)


def remove_port_forwarding(host_port: int, vm_ip: str, vm_port: int, protocol: str = "tcp") -> None:
    """Remove iptables port forwarding rule"""
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


# =============================================================================
# 工具函数 - LXD 相关
# =============================================================================

def lxc_exec(name: str, cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Execute command inside LXD container"""
    return subprocess.run(
        ["lxc", "exec", name, "--", "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout
    )


def inject_ssh_key(name: str, public_key: str, virt: str = "lxd") -> None:
    """Inject SSH public key and enable SSH service"""
    if not public_key:
        return

    if virt == "lxd":
        lxc_exec(name, "mkdir -p /root/.ssh && chmod 700 /root/.ssh", timeout=10)
        lxc_exec(name, f"echo '{public_key}' >> /root/.ssh/authorized_keys", timeout=10)
        lxc_exec(name, "chmod 600 /root/.ssh/authorized_keys && chown -R root:root /root/.ssh", timeout=10)
        lxc_exec(name, "which sshd || (apt-get update && apt-get install -y openssh-server)", timeout=120)
        lxc_exec(name, "mkdir -p /run/sshd && /usr/sbin/sshd || service ssh start || systemctl start sshd 2>/dev/null || true", timeout=20)


def inject_ssh_key_kvm(disk_path: str, public_key: str, user: str = "root") -> bool:
    """Inject SSH public key into KVM VM disk image using virt-customize.
    Returns True on success, False on failure."""
    if not public_key:
        return True

    # 输入校验
    if not disk_path or not os.path.exists(disk_path):
        logger.warning("inject_ssh_key_kvm: invalid disk path: %s", disk_path)
        return False

    # 验证用户名只包含安全字符
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_-]*$', user):
        logger.warning("inject_ssh_key_kvm: invalid username: %s", user)
        return False

    tmp_key_file = f"/tmp/ssh_key_{os.getpid()}_{int(time.time())}.pub"
    try:
        with open(tmp_key_file, "w") as f:
            f.write(public_key.strip() + "\n")

        home_dir = "/root" if user == "root" else f"/home/{user}"
        ssh_dir = f"{home_dir}/.ssh"
        auth_keys = f"{ssh_dir}/authorized_keys"

        cmd = [
            "virt-customize", "-a", disk_path,
            "--mkdir", ssh_dir,
            "--upload", f"{tmp_key_file}:{auth_keys}",
            "--run-command", f"chmod 700 {escape_shell_arg(ssh_dir)}",
            "--run-command", f"chmod 600 {escape_shell_arg(auth_keys)}",
            "--run-command", f"chown -R {escape_shell_arg(user)}:{escape_shell_arg(user)} {escape_shell_arg(ssh_dir)}",
        ]

        # 确保 SSH 服务已安装并启用
        cmd.extend([
            "--run-command", "which sshd || which ssh || (apt-get update && apt-get install -y openssh-server && systemctl enable ssh && systemctl start ssh) || (yum install -y openssh-server && systemctl enable sshd && systemctl start sshd) || true",
        ])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if result.returncode == 0:
            logger.info("SSH key injected into KVM disk: %s", disk_path)
            return True
        else:
            logger.warning("virt-customize SSH injection failed: %s", result.stderr)
            return False
    except subprocess.TimeoutExpired:
        logger.warning("virt-customize SSH injection timed out")
        return False
    except Exception as e:
        logger.warning("inject_ssh_key_kvm error: %s", e)
        return False
    finally:
        if os.path.exists(tmp_key_file):
            try:
                os.remove(tmp_key_file)
            except OSError:
                pass


def generate_windows_autounattend(
    admin_password: str,
    computer_name: str = "WIN-VM",
    enable_rdp: bool = True,
    enable_openssh: bool = True,
    ssh_public_key: str = ""
) -> str:
    """Generate Windows autounattend.xml for unattended installation/setup.
    Returns the path to the generated XML file."""
    xml_content = f'''<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAccounts>
                <AdministratorPassword>
                    <Value>{admin_password}</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <AutoLogon>
                <Password>
                    <Value>{admin_password}</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Username>Administrator</Username>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
            </AutoLogon>
            <ComputerName>{computer_name}</ComputerName>
            <TimeZone>China Standard Time</TimeZone>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>{computer_name}</ComputerName>
            <ProductKey></ProductKey>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <fDenyTSConnections>{'false' if enable_rdp else 'true'}</fDenyTSConnections>
        </component>
    </settings>
</unattend>'''

    xml_path = f"/tmp/autounattend_{os.getpid()}_{int(time.time())}.xml"
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write(xml_content)
    return xml_path


def create_windows_setup_complete_script(
    admin_password: str,
    enable_rdp: bool = True,
    enable_openssh: bool = True,
    ssh_public_key: str = ""
) -> str:
    """Create SetupComplete.cmd script for Windows first boot initialization.
    Returns the path to the script file."""
    rdp_commands = ""
    if enable_rdp:
        rdp_commands = '''
:: Enable RDP
reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
:: Allow RDP through firewall
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
'''

    openssh_commands = ""
    ssh_key_commands = ""
    if enable_openssh:
        openssh_commands = '''
:: Install OpenSSH Server
powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
:: Set SSH service to automatic startup
powershell -Command "Set-Service -Name sshd -StartupType 'Automatic'"
:: Start SSH service
powershell -Command "Start-Service sshd"
:: Allow SSH through firewall
netsh advfirewall firewall add rule name="OpenSSH SSH Server" dir=in action=allow protocol=TCP localport=22
'''
        if ssh_public_key:
            ssh_key_commands = f'''
:: Add SSH public key for Administrator
mkdir "C:\\ProgramData\\ssh"
echo {ssh_public_key} > "C:\\ProgramData\\ssh\\administrators_authorized_keys"
icacls "C:\\ProgramData\\ssh\\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
'''

    script_content = f'''@echo off
:: Windows SetupComplete.cmd - First boot initialization
echo Running setup complete script... > C:\\setup_complete.log
date /t >> C:\\setup_complete.log
time /t >> C:\\setup_complete.log

{rdp_commands}
{openssh_commands}
{ssh_key_commands}

:: Allow ICMP (ping) through firewall
netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow

:: Disable Windows Defender real-time protection (optional, for performance)
:: powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

echo Setup complete. >> C:\\setup_complete.log
date /t >> C:\\setup_complete.log
time /t >> C:\\setup_complete.log
'''

    script_path = f"/tmp/SetupComplete_{os.getpid()}_{int(time.time())}.cmd"
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_content)
    return script_path


def create_floppy_image(files: List[Tuple[str, str]], output_path: str) -> bool:
    """Create a floppy disk image with the given files.
    files: list of (local_path, floppy_path) tuples
    Returns True on success."""
    try:
        # Create blank floppy image
        result = subprocess.run(
            ["dd", "if=/dev/zero", f"of={output_path}", "bs=1440k", "count=1"],
            capture_output=True, timeout=30
        )
        if result.returncode != 0:
            logger.warning("Failed to create floppy image: %s", result.stderr)
            return False

        # Format as FAT
        result = subprocess.run(
            ["mkfs.fat", output_path],
            capture_output=True, timeout=30
        )
        if result.returncode != 0:
            logger.warning("Failed to format floppy: %s", result.stderr)
            return False

        # Copy files using mtools
        for local_path, floppy_path in files:
            result = subprocess.run(
                ["mcopy", "-i", output_path, local_path, f"::{floppy_path}"],
                capture_output=True, timeout=30
            )
            if result.returncode != 0:
                logger.warning("Failed to copy %s to floppy: %s", local_path, result.stderr)
                return False

        logger.info("Floppy image created: %s", output_path)
        return True
    except Exception as e:
        logger.warning("create_floppy_image error: %s", e)
        return False


def prepare_windows_kvm_disk(
    disk_path: str,
    admin_password: str,
    ssh_public_key: str = "",
    enable_rdp: bool = True,
    enable_openssh: bool = True
) -> bool:
    """Prepare Windows KVM disk image using virt-customize:
    - Set administrator password
    - Enable RDP
    - Install/Enable OpenSSH
    - Inject SSH public key
    Returns True on success."""
    # 输入校验
    if not disk_path or not os.path.exists(disk_path):
        logger.warning("prepare_windows_kvm_disk: invalid disk path: %s", disk_path)
        return False

    if not admin_password:
        logger.warning("prepare_windows_kvm_disk: empty password")
        return False

    tmp_key = ""
    try:
        cmd = ["virt-customize", "-a", disk_path]

        # 安全设置密码（使用 virt-customize 的标准方式）
        cmd.extend(["--root-password", f"password:{admin_password}"])

        if enable_rdp:
            cmd.extend([
                "--run-command",
                'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
            ])
            cmd.extend([
                "--run-command",
                'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes',
            ])

        if enable_openssh:
            cmd.extend([
                "--run-command",
                'powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"',
            ])
            cmd.extend([
                "--run-command",
                'powershell -Command "Set-Service -Name sshd -StartupType Automatic"',
            ])
            cmd.extend([
                "--run-command",
                'netsh advfirewall firewall add rule name="OpenSSH SSH Server" dir=in action=allow protocol=TCP localport=22',
            ])

            if ssh_public_key:
                tmp_key = f"/tmp/win_ssh_key_{os.getpid()}_{int(time.time())}.pub"
                with open(tmp_key, "w") as f:
                    f.write(ssh_public_key.strip() + "\n")

                cmd.extend([
                    "--mkdir", "C:/ProgramData/ssh",
                    "--upload", f"{tmp_key}:C:/ProgramData/ssh/administrators_authorized_keys",
                    "--run-command",
                    'icacls "C:\\ProgramData\\ssh\\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"',
                ])

        cmd.extend([
            "--run-command",
            'netsh advfirewall firewall add rule name="ICMP Allow" protocol=icmpv4:8,any dir=in action=allow',
        ])

        logger.info("Running virt-customize on Windows image...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

        if result.returncode == 0:
            logger.info("Windows disk prepared successfully")
            return True
        else:
            logger.warning("virt-customize failed: %s", result.stderr)
            return False
    except subprocess.TimeoutExpired:
        logger.warning("virt-customize timed out")
        return False
    except Exception as e:
        logger.warning("prepare_windows_kvm_disk error: %s", e)
        return False
    finally:
        if tmp_key and os.path.exists(tmp_key):
            try:
                os.remove(tmp_key)
            except OSError:
                pass


def ensure_docker_in_lxd(name: str) -> None:
    """Ensure Docker is installed and running in LXD container"""
    lxc_exec(
        name,
        "apt-get update -qq && apt-get install -y -qq docker.io && systemctl start docker",
        timeout=120
    )


def install_app_in_lxd(name: str, app_image: str, app_config: Dict[str, Any], user_secrets: Optional[Dict[str, str]] = None) -> Tuple[bool, Dict[str, str], str, str]:
    """Install Docker app in LXD container"""
    ensure_docker_in_lxd(name)

    gen_secrets_config = app_config.get("gen_secrets", {})
    secrets = generate_secrets(gen_secrets_config, user_secrets)

    docker_args = build_docker_run_args(app_config, secrets)
    docker_cmd = ["lxc", "exec", name, "--", "docker", "run", "-d", "--name", app_image] + docker_args + [app_config["docker_image"]]

    result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60)
    return result.returncode == 0, secrets, result.stdout, result.stderr


# =============================================================================
# 工具函数 - 依赖和硬件
# =============================================================================

def ensure_dependencies() -> None:
    """Install required system dependencies"""
    for cmd, pkg in DEPENDENCIES:
        result = subprocess.run(["which", cmd], capture_output=True)
        if result.returncode != 0:
            logger.info("Installing %s...", pkg)
            subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=120)
            subprocess.run(["apt-get", "install", "-y", "-qq", pkg], capture_output=True, timeout=180)

    result = subprocess.run(["which", "virt-builder"], capture_output=True)
    if result.returncode != 0:
        logger.info("Installing libguestfs-tools for Windows support...")
        subprocess.run(
            ["apt-get", "install", "-y", "-qq", "libguestfs-tools", "linux-image-generic"],
            capture_output=True, timeout=300
        )

    subprocess.run(["systemctl", "start", "libvirtd"], capture_output=True)
    subprocess.run(["systemctl", "enable", "libvirtd"], capture_output=True)

    logger.info("Dependencies installed")


def detect_hardware() -> Dict[str, Any]:
    """Detect hardware specifications"""
    hardware: Dict[str, Any] = {}

    try:
        result = subprocess.run(["nproc", "--all"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            hardware["cpu_cores"] = int(result.stdout.strip())
    except (subprocess.SubprocessError, ValueError):
        pass

    try:
        result = subprocess.run(["grep", "MemTotal", "/proc/meminfo"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2 and parts[1].isdigit():
                kb = int(parts[1])
                hardware["memory_gb"] = round(kb / 1024.0 / 1024.0, 2)
    except (subprocess.SubprocessError, ValueError):
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
    except (subprocess.SubprocessError, ValueError):
        pass

    return hardware


def get_local_ip() -> Optional[str]:
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


# =============================================================================
# 工具函数 - noVNC
# =============================================================================

def setup_novnc(name: str, vnc_port: int, web_port: int) -> int:
    """Setup noVNC container for KVM VNC access"""
    try:
        subprocess.run(
            ["docker", "rm", "-f", f"novnc-{name}"],
            capture_output=True, timeout=5
        )

        result = subprocess.run([
            "docker", "run", "-d",
            "--name", f"novnc-{name}",
            "-p", f"{web_port}:6080",
            "novnc/novnc:latest",
            "--vnc", f"127.0.0.1:{vnc_port}"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            logger.info("noVNC started on port %d", web_port)
            return web_port
        else:
            logger.warning("Failed to start novnc: %s", result.stderr)
            release_port(web_port)
            return 0
    except subprocess.SubprocessError as e:
        logger.warning("novnc setup failed: %s", e)
        release_port(web_port)
        return 0


def get_novnc_port(name: str) -> int:
    """Get noVNC port for a machine, start one if not running"""
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name=novnc-{name}", "--format", "{{.Ports}}"],
        capture_output=True, text=True, timeout=5
    )

    if result.returncode == 0 and result.stdout:
        match = re.search(r'0.0.0.0:(\d+)', result.stdout)
        if match:
            return int(match.group(1))

    return 0


# =============================================================================
# AgentHandler - HTTP 请求处理器
# =============================================================================

class AgentHandler(BaseHTTPRequestHandler):
    """HTTP request handler for agent API"""

    def log_message(self, format: str, *args: Any) -> None:
        logger.info("%s - %s", self.address_string(), format % args)

    # ----- 认证和响应辅助方法 -----

    def _check_auth(self) -> bool:
        api_key = self.headers.get("X-API-Key", "")
        return api_key == API_KEY

    def _send_json(self, data: Dict[str, Any], status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _get_virt_type_from_name(self, name: str) -> str:
        if name.startswith("machine-"):
            return "lxd"
        return VIRT_TYPE

    def _read_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return json.loads(self.rfile.read(content_length))
        return {}

    # ----- HTTP 方法入口 -----

    def do_GET(self) -> None:
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        path = urlparse(self.path).path

        routes = {
            "/status": self._handle_status,
            "/images": self._handle_get_images,
            "/app-images": self._handle_get_app_images,
            "/ports": self._handle_get_ports,
            "/processes": self._handle_get_processes,
            "/opengfw/status": self._handle_opengfw_status,
            "/opengfw/install": self._handle_opengfw_install,
            "/opengfw/config": self._handle_opengfw_config,
            "/opengfw/refresh": self._handle_opengfw_refresh,
            "/opengfw/uninstall": self._handle_opengfw_uninstall,
        }

        if path in routes:
            routes[path]()
        elif path.startswith("/traffic/"):
            machine_id = path.split("/")[-1]
            self._handle_get_traffic(machine_id)
        elif path.startswith("/machine/"):
            name = path.split("/")[-1]
            self._handle_get_machine_info(name)
        elif path.startswith("/console/"):
            name = path.split("/")[-1]
            self._handle_get_console(name)
        elif path.startswith("/port-forwards/"):
            name = path.split("/")[-1]
            self._handle_list_port_forwards(name)
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        body = self._read_body()
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
        elif path.startswith("/port-forward/add/"):
            name = path.split("/")[-1]
            self._handle_add_port_forward(name, body)
        else:
            self._send_json({"error": "not found"}, 404)

    def do_DELETE(self) -> None:
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        path = urlparse(self.path).path

        if path.startswith("/port-forward/"):
            parts = path.strip("/").split("/")
            if len(parts) >= 3 and parts[0] == "port-forward":
                name = parts[1]
                try:
                    host_port = int(parts[2])
                    self._handle_delete_port_forward(name, host_port)
                    return
                except (ValueError, IndexError):
                    pass
            self._send_json({"error": "invalid request"}, 400)
            return

        name = path.strip("/")
        if not name:
            self._send_json({"error": "name required"}, 400)
            return

        self._handle_stop(name)

    # ----- GET 处理函数 -----

    def _handle_status(self) -> None:
        self._send_json({"status": "ok", "virt_type": VIRT_TYPE})

    def _handle_get_images(self) -> None:
        self._send_json({"images": list(SYSTEM_IMAGES.keys())})

    def _handle_get_app_images(self) -> None:
        apps = []
        for app_id, config in APP_IMAGES.items():
            apps.append({
                "id": app_id,
                "name": config["name"],
                "docker_image": config["docker_image"],
                "ports": config["ports"],
            })
        self._send_json({"app_images": apps})

    def _handle_get_machine_info(self, name: str) -> None:
        try:
            virt = self._get_virt_type_from_name(name)

            if virt == "lxd":
                self._get_lxd_machine_info(name)
            else:
                self._get_kvm_machine_info(name)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _get_lxd_machine_info(self, name: str) -> None:
        result = subprocess.run(
            ["lxc", "list", name, "--format", "json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            self._send_json({"error": result.stderr}, 500)
            return

        data = json.loads(result.stdout)
        if not data:
            self._send_json({"error": "machine not found"}, 404)
            return

        info = data[0]
        status = info.get("status", "unknown")
        ipv4 = ""
        for addr in info.get("state", {}).get("network", {}).values():
            for a in addr.get("addresses", []):
                if a.get("family") == "inet":
                    ipv4 = a.get("address", "")
                    break

        self._send_json({
            "name": name,
            "status": status,
            "ip": ipv4,
            "ssh_port": 22,
            "virt_type": "lxd",
        })

    def _get_kvm_machine_info(self, name: str) -> None:
        result = subprocess.run(
            ["virsh", "dominfo", name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            self._send_json({"error": "machine not found"}, 404)
            return

        status = "running" if "running" in result.stdout else "stopped"
        vnc_port = self._get_kvm_vnc_port(name)
        novnc_port = get_novnc_port(name)
        image = self._get_kvm_disk_image(name)

        response_data = {
            "name": name,
            "status": status,
            "virt_type": "kvm",
            "vnc_port": vnc_port,
            "novnc_port": novnc_port,
        }

        os_info = self._get_os_type_from_image(image)
        response_data.update(os_info)

        self._send_json(response_data)

    def _get_kvm_vnc_port(self, name: str) -> int:
        result = subprocess.run(
            ["virsh", "vncdisplay", name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            match = re.search(r':(\d+)', result.stdout)
            if match:
                return 5900 + int(match.group(1))
        return 5900

    def _get_kvm_disk_image(self, name: str) -> str:
        result = subprocess.run(
            ["virsh", "domblklist", name, "--details"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.split("\n")
            if len(lines) > 2:
                return os.path.basename(lines[2])
        return ""

    def _get_os_type_from_image(self, image: str) -> Dict[str, Any]:
        for win_image, config in SYSTEM_IMAGES.items():
            if config.get("type") == "windows":
                base_path = config.get("kvm", "")
                if base_path and base_path in image:
                    return {
                        "os_type": "windows",
                        "rdp_port": config.get("rdp_port", 3389),
                        "ssh_port": None,
                        "note": "Windows 虚拟机"
                    }

        return {
            "os_type": "linux",
            "ssh_port": 22,
        }

    def _handle_get_console(self, name: str) -> None:
        try:
            web_port = get_novnc_port(name)
            if web_port == 0:
                web_port = random.randint(6080, 6999)
                subprocess.run([
                    "docker", "run", "-d", "--name", f"novnc-{name}",
                    "-p", f"{web_port}:6080",
                    "-e", f"VNC_HOST={name}",
                    "dorowu/ubuntu-desktop-lxde-vnc"
                ], capture_output=True, timeout=30)

            host_ip = os.environ.get('HOST_IP', 'localhost')
            self._send_json({
                "name": name,
                "web_port": web_port,
                "web_url": f"http://{host_ip}:{web_port}",
            })
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_get_ports(self) -> None:
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

    def _handle_get_processes(self) -> None:
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

    def _get_machine_ip(self, name: str) -> Optional[str]:
        """Get VM/container IP address"""
        try:
            virt = self._get_virt_type_from_name(name)
            if virt == "lxd":
                result = subprocess.run(
                    ["lxc", "list", name, "--format", "csv", "-c", "4"],
                    capture_output=True, text=True, timeout=10
                )
                ip = result.stdout.strip()
                return ip if ip else None
            else:
                # KVM: get IP from DHCP leases or use network
                result = subprocess.run(
                    ["virsh", "domifaddr", name],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split("\n"):
                    if "ipv4" in line:
                        parts = line.split()
                        for p in parts:
                            if "/" in p and "." in p:
                                return p.split("/")[0]
                return None
        except Exception:
            return None

    def _handle_list_port_forwards(self, name: str) -> None:
        """List all port forwarding rules for a machine"""
        try:
            vm_ip = self._get_machine_ip(name)
            if not vm_ip:
                self._send_json({"forwards": [], "error": "machine not found or no IP"})
                return

            # Get all iptables NAT rules for this VM
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=10
            )

            forwards = []
            for line in result.stdout.strip().split("\n")[2:]:
                parts = line.split()
                if len(parts) >= 7 and "DNAT" in parts:
                    proto = parts[3].lower() if parts[3] else "tcp"
                    try:
                        dport = int(parts[-2]) if parts[-2].isdigit() else 0
                        to_parts = parts[-1].split(":")
                        if len(to_parts) >= 2 and to_parts[0] == vm_ip:
                            vm_port = int(to_parts[-1]) if to_parts[-1].isdigit() else 0
                            forwards.append({
                                "host_port": dport,
                                "vm_port": vm_port,
                                "protocol": proto,
                                "vm_ip": to_parts[0],
                            })
                    except (ValueError, IndexError):
                        continue

            self._send_json({"forwards": forwards, "vm_ip": vm_ip})
        except Exception as e:
            self._send_json({"error": str(e), "forwards": []})

    def _handle_add_port_forward(self, name: str, body: Dict[str, Any]) -> None:
        """Add a port forwarding rule"""
        try:
            vm_port = int(body.get("vm_port", 0))
            protocol = body.get("protocol", "tcp").lower()
            host_port = int(body.get("host_port", 0)) if body.get("host_port") else 0

            if vm_port <= 0 or vm_port > 65535:
                self._send_json({"error": "invalid vm_port"}, 400)
                return
            if protocol not in ("tcp", "udp"):
                self._send_json({"error": "invalid protocol, must be tcp or udp"}, 400)
                return

            vm_ip = self._get_machine_ip(name)
            if not vm_ip:
                self._send_json({"error": "machine not found or no IP"}, 404)
                return

            # Allocate host port if not specified
            if host_port == 0:
                host_port = allocate_port()
            else:
                if host_port < 1 or host_port > 65535:
                    self._send_json({"error": "invalid host_port"}, 400)
                    return
                # Check if port is already in use
                result = subprocess.run(
                    ["ss", "-tlnp"],
                    capture_output=True, text=True, timeout=5
                )
                if f":{host_port}" in result.stdout:
                    self._send_json({"error": f"host port {host_port} already in use"}, 400)
                    return
                USED_PORTS.add(host_port)

            setup_port_forwarding(host_port, vm_ip, vm_port, protocol)

            self._send_json({
                "status": "ok",
                "host_port": host_port,
                "vm_port": vm_port,
                "protocol": protocol,
                "vm_ip": vm_ip,
            })
        except ValueError:
            self._send_json({"error": "invalid port number"}, 400)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_delete_port_forward(self, name: str, host_port: int) -> None:
        """Delete a port forwarding rule"""
        try:
            vm_ip = self._get_machine_ip(name)
            if not vm_ip:
                self._send_json({"error": "machine not found or no IP"}, 404)
                return

            # Find and remove both rules (PREROUTING and POSTROUTING)
            for proto in ["tcp", "udp"]:
                remove_port_forwarding(host_port, vm_ip, 0, proto)

            # Also try with vm_port from existing rules
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split("\n")[2:]:
                parts = line.split()
                if len(parts) >= 7 and "DNAT" in parts:
                    try:
                        dport = int(parts[-2]) if parts[-2].isdigit() else 0
                        if dport == host_port:
                            to_parts = parts[-1].split(":")
                            if len(to_parts) >= 2 and to_parts[0] == vm_ip:
                                vm_port = int(to_parts[-1]) if to_parts[-1].isdigit() else 0
                                proto = parts[3].lower() if parts[3] else "tcp"
                                remove_port_forwarding(host_port, vm_ip, vm_port, proto)
                    except (ValueError, IndexError):
                        continue

            release_port(host_port)

            self._send_json({"status": "ok", "host_port": host_port})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_get_traffic(self, machine_id: str) -> None:
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

    # ----- POST 处理函数 -----

    def _handle_create(self, body: Dict[str, Any]) -> None:
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

        root_password = user_root_password if user_root_password else generate_password(16)

        if virt == "lxd":
            self._create_lxd(name, cpu, memory, disk, image, app_image, ssh_public_key, root_password, user_app_secrets)
        elif virt == "kvm":
            self._create_kvm(name, cpu, memory, disk, image, app_image, ssh_public_key, root_password)
        else:
            self._send_json({"error": f"unsupported virt_type: {virt}"})

    def _create_lxd(
        self,
        name: str,
        cpu: int,
        memory: int,
        disk: int,
        image: str,
        app_image: str,
        ssh_public_key: str,
        root_password: str,
        user_app_secrets: Dict[str, str]
    ) -> None:
        lxd_image = SYSTEM_IMAGES.get(image, {}).get("lxd", "ubuntu:22.04")

        cmd = [
            "lxc", "launch", lxd_image, name,
            "-c", f"limits.cpu={cpu}",
            "-c", f"limits.memory={memory}MB",
            "-c", f"limits.disk={disk}GB"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            cmd = [
                "lxc", "launch", lxd_image, name,
                "-c", f"limits.cpu={cpu}",
                "-c", f"limits.memory={memory}MB"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            self._send_json({"status": "error", "error": result.stderr})
            return

        lxc_exec(name, f"echo 'root:{root_password}' | chpasswd", timeout=30)
        inject_ssh_key(name, ssh_public_key, "lxd")

        app_secrets: Dict[str, str] = {}
        if app_image and APP_IMAGES.get(app_image, {}).get("docker_image"):
            app_config = APP_IMAGES.get(app_image, {})
            success, app_secrets, _, _ = install_app_in_lxd(name, app_image, app_config, user_app_secrets)
            if not success:
                logger.warning("Failed to install app %s in container %s", app_image, name)

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

    def _create_kvm(
        self,
        name: str,
        cpu: int,
        memory: int,
        disk: int,
        image: str,
        app_image: str,
        ssh_public_key: str,
        root_password: str
    ) -> None:
        ensure_dependencies()

        image_config = SYSTEM_IMAGES.get(image, {})
        kvm_base = image_config.get("kvm", "/var/lib/libvirt/images/base-ubuntu.qcow2")
        os_type = image_config.get("type", "linux")
        is_windows = os_type == "windows"
        supports_ssh = image_config.get("ssh", True)
        supports_rdp = image_config.get("rdp", False) if is_windows else False

        disk_path = f"/var/lib/libvirt/images/{name}.qcow2"

        if is_windows:
            if not self._prepare_windows_image(image, kvm_base):
                self._send_json({
                    "status": "error",
                    "error": "Failed to prepare Windows image. Please ensure virt-builder or network is available."
                })
                return

            if not os.path.exists(VIRTIO_ISO_PATH):
                logger.info("Downloading VirtIO drivers...")
                subprocess.run([
                    "curl", "-L", "-o", VIRTIO_ISO_PATH,
                    "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.229-2/virtio-win-0.1.229.iso"
                ], capture_output=True, timeout=300)
        elif not os.path.exists(kvm_base):
            if not self._create_linux_base_image(image, kvm_base, image_config):
                return

        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-b", kvm_base, "-F", "qcow2", disk_path, f"{disk}G"],
            capture_output=True, timeout=30
        )

        # 在启动前预处理磁盘
        prep_failed = False
        if is_windows:
            # Windows: 设置密码、启用RDP、安装OpenSSH、注入SSH密钥
            logger.info("Preparing Windows disk image...")
            if not prepare_windows_kvm_disk(
                disk_path,
                root_password,
                ssh_public_key if supports_ssh else "",
                supports_rdp,
                supports_ssh
            ):
                logger.warning("Windows disk preparation failed, VM may not be fully configured")
                prep_failed = True
        elif supports_ssh and ssh_public_key:
            # Linux: 注入 SSH 密钥
            logger.info("Injecting SSH key into Linux KVM disk...")
            if not inject_ssh_key_kvm(disk_path, ssh_public_key, "root"):
                logger.warning("SSH key injection failed")

        ssh_external_port = allocate_port() if supports_ssh else None
        rdp_external_port = allocate_port() if supports_rdp else None
        vnc_external_port = allocate_port()
        novnc_external_port = allocate_port()

        cmd = self._build_virt_install_cmd(name, cpu, memory, disk_path, image, is_windows, vnc_external_port)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode != 0:
            release_port(ssh_external_port)
            release_port(rdp_external_port)
            release_port(vnc_external_port)
            release_port(novnc_external_port)
            # 清理已创建的磁盘镜像
            if os.path.exists(disk_path):
                try:
                    os.remove(disk_path)
                except OSError:
                    pass
            self._send_json({"status": "error", "error": result.stderr})
            return

        time.sleep(10)
        vm_ip = self._get_vm_ip(name)
        setup_novnc(name, vnc_external_port, novnc_external_port)

        if vm_ip:
            if ssh_external_port and supports_ssh:
                setup_port_forwarding(ssh_external_port, vm_ip, 22)
            if rdp_external_port and supports_rdp:
                setup_port_forwarding(rdp_external_port, vm_ip, 3389)

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
                "ssh_port": ssh_external_port,
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

    def _build_virt_install_cmd(
        self,
        name: str,
        cpu: int,
        memory: int,
        disk_path: str,
        image: str,
        is_windows: bool,
        vnc_port: int
    ) -> List[str]:
        vnc_display_port = vnc_port - 5900

        if is_windows:
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
                "--graphics", f"vnc,listen=0.0.0.0,port={vnc_display_port}",
                "--video", "virtio",
                "--network", "bridge=virbr0,model=virtio",
                "--controller", "usb,model=ehci",
            ]
            if os.path.exists(VIRTIO_ISO_PATH):
                cmd.extend(["--disk", f"path={VIRTIO_ISO_PATH},device=cdrom"])
        else:
            os_variant = OS_VARIANT_MAP.get(image, "ubuntu22.04")
            cmd = [
                "virt-install",
                "--name", name,
                "--vcpus", str(cpu),
                "--memory", str(memory),
                "--disk", f"path={disk_path},format=qcow2",
                "--boot", "hd",
                "--os-variant", os_variant,
                "--noautoconsole",
                "--graphics", f"vnc,listen=0.0.0.0,port={vnc_display_port}",
                "--network", "bridge=virbr0",
            ]

        return cmd

    def _create_linux_base_image(self, image: str, kvm_base: str, image_config: Dict[str, Any]) -> bool:
        logger.info("Creating Linux base image from LXD...")
        lxd_image = image_config.get("lxd", image)
        if not lxd_image:
            self._send_json({"status": "error", "error": f"Linux base image not found: {kvm_base}"})
            return False

        subprocess.run(
            ["lxc", "launch", lxd_image, "temp-base", "--ephemeral"],
            capture_output=True, timeout=60
        )
        time.sleep(5)
        lxc_exec("temp-base", "dd if=/dev/sda of=/tmp/rootfs.img", timeout=120)
        subprocess.run(
            ["lxc", "file", "pull", "temp-base/tmp/rootfs.img", kvm_base],
            capture_output=True, timeout=60
        )
        subprocess.run(["lxc", "delete", "--force", "temp-base"], capture_output=True)
        subprocess.run(
            ["qemu-img", "convert", "-O", "qcow2", kvm_base + ".img", kvm_base],
            capture_output=True
        )

        if os.path.exists(kvm_base):
            logger.info("Created base image: %s", kvm_base)
            return True
        else:
            self._send_json({"status": "error", "error": "Failed to create Linux base image"})
            return False

    def _get_vm_ip(self, name: str, timeout: int = 60) -> Optional[str]:
        """Get KVM VM IP address"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            ip = self._try_get_vm_ip_domifaddr(name)
            if ip:
                return ip

            ip = self._try_get_vm_ip_guest_agent(name)
            if ip:
                return ip

            ip = self._try_get_vm_ip_arp(name)
            if ip:
                return ip

            time.sleep(2)

        return None

    def _try_get_vm_ip_domifaddr(self, name: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["virsh", "domifaddr", name],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                match = re.search(r'\d+\.\d+\.\d+\.\d+', result.stdout)
                if match:
                    return match.group(0)
        except subprocess.SubprocessError:
            pass
        return None

    def _try_get_vm_ip_guest_agent(self, name: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["virsh", "qemu-agent-command", name, '{"execute":"guest-network-get-interfaces"}'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for iface in data.get("return", []):
                    for ip_info in iface.get("ip-addresses", []):
                        if ip_info.get("ip-address-type") == "ipv4":
                            return ip_info.get("ip-address")
        except (subprocess.SubprocessError, json.JSONDecodeError):
            pass
        return None

    def _try_get_vm_ip_arp(self, name: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["arp", "-an"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'virbr0' in line:
                    match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if match:
                        return match.group(0)
        except subprocess.SubprocessError:
            pass
        return None

    def _handle_stop(self, name: str) -> None:
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
        subprocess.run(["docker", "rm", "-f", f"novnc-{name}"], capture_output=True)

        self._send_json({
            "status": "stopped" if result.returncode == 0 else "error",
            "output": result.stdout,
            "error": result.stderr
        })

    def _handle_reinstall(self, name: str, body: Dict[str, Any]) -> None:
        image = body.get("image", "ubuntu:22.04")
        app_image = body.get("app_image", "")
        ssh_public_key = body.get("ssh_public_key", PLATFORM_SSH_PUBKEY)

        self._handle_stop(name)
        time.sleep(2)

        try:
            machine_id = name.replace("machine-", "")
            machine_info = platform_request(f"/api/v1/machine/{machine_id}")

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

    def _handle_exec(self, name: str, body: Dict[str, Any]) -> None:
        command = body.get("command", "")
        if not command:
            self._send_json({"error": "command required"}, 400)
            return

        virt = self._get_virt_type_from_name(name)

        if virt == "lxd":
            result = lxc_exec(name, command, timeout=60)
        else:
            result = subprocess.run(
                ["virsh", "qemu-agent-command", name, f"'{command}'"],
                capture_output=True, text=True, timeout=60
            )

        self._send_json({
            "status": "success" if result.returncode == 0 else "error",
            "stdout": result.stdout,
            "stderr": result.stderr,
        })

    def _handle_app_install(self, name: str, body: Dict[str, Any]) -> None:
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
            success, secrets, stdout, stderr = install_app_in_lxd(name, app_image, app_config, user_secrets)
            self._send_json({
                "status": "installed" if success else "error",
                "app_name": app_config["name"],
                "ports": app_config["ports"],
                "secrets": secrets,
                "output": stdout,
                "error": stderr,
            })
        else:
            self._send_json({"error": "KVM app install not supported yet"}, 400)

    def _handle_app_uninstall(self, name: str, body: Dict[str, Any]) -> None:
        app_image = body.get("app_image", "")
        if not app_image:
            self._send_json({"error": "app_image required"}, 400)
            return

        virt = self._get_virt_type_from_name(name)

        if virt == "lxd":
            result = lxc_exec(name, f"docker rm -f {app_image}", timeout=30)
            self._send_json({
                "status": "uninstalled" if result.returncode == 0 else "error",
                "output": result.stdout,
                "error": result.stderr,
            })
        else:
            self._send_json({"error": "KVM app uninstall not supported yet"}, 400)

    # ----- Windows 镜像处理 -----

    def _prepare_windows_image(self, image: str, kvm_base: str) -> bool:
        if os.path.exists(kvm_base):
            logger.info("Windows base image already exists: %s", kvm_base)
            return True

        os.makedirs(os.path.dirname(kvm_base), exist_ok=True)

        download_url = WINDOWS_IMAGE_SOURCES.get(image, "")
        if not download_url:
            logger.info("No download URL for %s, trying virt-builder", image)
            return self._build_windows_with_virtbuilder(image, kvm_base)

        logger.info("Downloading Windows image from %s", download_url)
        logger.info("This may take several minutes...")

        try:
            result = subprocess.run([
                "curl", "-L", "-#",
                "-o", kvm_base,
                download_url
            ], capture_output=True, text=True, timeout=3600)

            if result.returncode == 0 and os.path.exists(kvm_base):
                size = os.path.getsize(kvm_base)
                if size > 100 * 1024 * 1024:
                    logger.info("Downloaded Windows image: %dMB", size // (1024 * 1024))
                    return True
                else:
                    logger.warning("Downloaded file too small: %d bytes", size)
                    os.remove(kvm_base)
            else:
                logger.warning("Download failed: %s", result.stderr)
        except subprocess.SubprocessError as e:
            logger.warning("Download error: %s", e)

        return self._build_windows_with_virtbuilder(image, kvm_base)

    def _build_windows_with_virtbuilder(self, image: str, kvm_base: str) -> bool:
        logger.info("Trying virt-builder for %s", image)

        result = subprocess.run(["which", "virt-builder"], capture_output=True)
        if result.returncode != 0:
            logger.warning("virt-builder not found, install with: apt-get install libguestfs-tools")
            return False

        os_variant = VIRTBUILDER_WINDOWS_MAP.get(image, "win10")

        try:
            cmd = [
                "virt-builder", os_variant,
                "--output", kvm_base,
                "--format", "qcow2",
                "--size", "40G",
                "--root-password", "password:ChangeMe123!",
            ]

            logger.info("Running: %s", " ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            if result.returncode == 0 and os.path.exists(kvm_base):
                size = os.path.getsize(kvm_base) // (1024 * 1024)
                logger.info("Built Windows image with virt-builder: %dMB", size)
                return True
            else:
                logger.warning("virt-builder failed: %s", result.stderr)
        except subprocess.SubprocessError as e:
            logger.warning("virt-builder error: %s", e)

        return False

    # ----- OpenGFW 处理函数 -----

    def _handle_opengfw_status(self) -> None:
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

    def _handle_opengfw_install(self) -> None:
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

    def _handle_opengfw_config(self) -> None:
        try:
            config = platform_request("/api/v1/opengfw/config")

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

    def _generate_opengfw_yaml(self, rules: List[Dict[str, Any]]) -> str:
        actions = []
        for rule in rules:
            proto = rule.get("protocol", "")
            action = rule.get("action", "block")
            sig = rule.get("match_signature", "")
            if sig:
                actions.append(f'  - id: "block_{proto}"\n    match: "{sig}"\n    action: {action}')

        return f'''listen: ":4480"
log:
  level: info
  file: /var/log/opengfw.log
actions:
{chr(10).join(actions)}
'''

    def _apply_nftables_rules(self, rules: List[Dict[str, Any]]) -> None:
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
        except subprocess.SubprocessError as e:
            logger.error("NFTables error: %s", e)

    def _handle_opengfw_refresh(self) -> None:
        self._handle_opengfw_config()

    def _handle_opengfw_uninstall(self) -> None:
        try:
            subprocess.run(["pkill", "-f", "opengfw"], capture_output=True)
            subprocess.run(["rm", "-f", "/usr/local/bin/opengfw"], capture_output=True)
            subprocess.run(["rm", "-rf", "/etc/opengfw"], capture_output=True)
            subprocess.run(["nft", "delete", "table", "ip", "opengfw"], capture_output=True)
            self._send_json({"status": "uninstalled"})
        except Exception as e:
            self._send_json({"status": "error", "error": str(e)})


# =============================================================================
# 后台线程函数
# =============================================================================

def report_stats_loop() -> None:
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
                _report_machine_stats(machine_name)
        except Exception as e:
            logger.error("Stats loop error: %s", e)

        time.sleep(STATS_REPORT_INTERVAL)


def _report_machine_stats(machine_name: str) -> None:
    """Report stats for a single machine"""
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
                memory_used = parse_memory_value(info_line)
            elif "Memory:" in info_line:
                memory_total = parse_memory_value(info_line)

        stats = {
            "machine_name": machine_name,
            "cpu_usage_percent": cpu_usage,
            "memory_used_mb": memory_used,
            "memory_total_mb": memory_total,
        }

        platform_request("/api/v1/agent/stats", method="POST", data=stats)
    except Exception as e:
        logger.error("Stats error for %s: %s", machine_name, e)


def register_with_platform() -> None:
    """Register agent with platform"""
    hardware = detect_hardware()
    payload: Dict[str, Any] = {"virt_type": VIRT_TYPE, "platform_url": PLATFORM_URL}
    payload.update(hardware)

    local_ip = get_local_ip()
    if local_ip:
        payload["ip"] = local_ip

    try:
        result = platform_request("/api/v1/agent/register", method="POST", data=payload, timeout=15)
        logger.info("Registered: %s", result)
    except Exception as e:
        logger.error("Register failed: %s", e)


# =============================================================================
# 主入口
# =============================================================================

def main() -> None:
    if VIRT_TYPE == "kvm":
        logger.info("Checking and installing KVM dependencies...")
        ensure_dependencies()

    register_thread = threading.Thread(target=register_with_platform, daemon=True)
    register_thread.start()

    stats_thread = threading.Thread(target=report_stats_loop, daemon=True)
    stats_thread.start()

    server = HTTPServer(("0.0.0.0", AGENT_PORT), AgentHandler)
    logger.info("Agent running on port %d, virt_type=%s", AGENT_PORT, VIRT_TYPE)
    server.serve_forever()


if __name__ == "__main__":
    main()
