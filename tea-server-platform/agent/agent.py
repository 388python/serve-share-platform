#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import json
import subprocess
import os
import re

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

    def _get_virt_type_from_name(self, name):
        """Determine virt type from container/VM name prefix or name pattern"""
        if name.startswith("machine-"):
            return "lxd"  # Default for platform machines
        return VIRT_TYPE

    def do_GET(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        path = urlparse(self.path).path

        if path == "/status":
            self._send_json({"status": "ok", "virt_type": VIRT_TYPE})
        elif path == "/ports":
            self._handle_get_ports()
        elif path == "/processes":
            self._handle_get_processes()
        elif path.startswith("/traffic/"):
            machine_id = path.split("/")[-1]
            self._handle_get_traffic(machine_id)
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_get_ports(self):
        """Get listening ports - used for VPN detection"""
        try:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5
            )
            ports = []
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    # Parse port from address like *:22 or 0.0.0.0:22
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
        """Get running processes - used for VPN detection"""
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
        """Get traffic stats for a machine - used for bandwidth monitoring"""
        # For LXD containers, get network stats
        container_name = f"machine-{machine_id}"
        try:
            # Get network stats from LXD
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

            # Calculate Mbps (assuming 5-minute interval)
            rx_mbps = (rx_bytes * 8) / (300 * 1_000_000)
            tx_mbps = (tx_bytes * 8) / (300 * 1_000_000)

            self._send_json({
                "bandwidth_mbps": max(rx_mbps, tx_mbps),
                "rx_mbps": rx_mbps,
                "tx_mbps": tx_mbps
            })
        except Exception as e:
            self._send_json({"error": str(e), "bandwidth_mbps": 0})

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
        memory = body.get("memory", 1024)  # MB
        disk = body.get("disk", 10)  # GB
        virt = body.get("virt_type", VIRT_TYPE)

        if virt == "lxd":
            # LXD launch with CPU, memory and disk limits
            cmd = [
                "lxc", "launch", "ubuntu:22.04", name,
                "-c", f"limits.cpu={cpu}",
                "-c", f"limits.memory={memory}MB",
                "-c", f"limits Disk.space={disk}GB"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                # Try without disk limit if unsupported
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
            # KVM virt-install with proper configuration
            # Use cloud-init or simple import
            disk_path = f"/var/lib/libvirt/images/{name}.qcow2"

            # Create disk image
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
        """Stop a running VM/container"""
        if not name:
            self._send_json({"error": "name required"}, 400)
            return

        virt = self._get_virt_type_from_name(name)

        if virt == "lxd":
            # Stop LXD container gracefully, then delete
            subprocess.run(["lxc", "stop", name], capture_output=True, timeout=30)
            cmd = ["lxc", "delete", "--force", name]
        else:
            # KVM - destroy and undefine
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
            # Force delete LXD container
            subprocess.run(["lxc", "stop", name], capture_output=True)
            cmd = ["lxc", "delete", "--force", name]
        else:
            # KVM - destroy and undefine
            subprocess.run(["virsh", "destroy", name], capture_output=True)
            cmd = ["virsh", "undefine", name, "--nvram", "--delete-all-storage"]

        result = subprocess.run(cmd, capture_output=True, text=True)
        self._send_json({
            "status": "deleted" if result.returncode == 0 else "error",
            "output": result.stdout,
            "error": result.stderr
        })

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 19527), AgentHandler)
    print(f"Agent running on port 19527, virt_type={VIRT_TYPE}")
    server.serve_forever()
