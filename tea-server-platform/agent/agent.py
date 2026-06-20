#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import json
import subprocess
import os
import re
import threading
import time

API_KEY = os.environ.get("AGENT_API_KEY", "tea-platform-agent-key")
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

    def _get_machine_stats(self, machine_name):
        """Get CPU, memory, disk stats for a container"""
        try:
            # Get LXD info
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
            
            # Get disk usage
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
            
            # Get process count
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

def report_stats_loop():
    """Background thread to report machine stats to platform"""
    while True:
        try:
            # Get all running machines
            result = subprocess.run(
                ["lxc", "list", "name=machine-", "--format", "csv", "-c", "n"],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                machine_name = line.strip()
                
                # Get stats for this machine
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
                    
                    # Get disk usage
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
                
                # Report to platform
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
        
        time.sleep(60)  # Report every 60 seconds

if __name__ == "__main__":
    # Start stats reporting thread
    stats_thread = threading.Thread(target=report_stats_loop, daemon=True)
    stats_thread.start()
    
    server = HTTPServer(("0.0.0.0", 19527), AgentHandler)
    print(f"Agent running on port 19527, virt_type={VIRT_TYPE}")
    server.serve_forever()
