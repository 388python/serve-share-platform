#!/usr/bin/env python3
from flask import Flask, request, jsonify
import json
import subprocess
import os
import sys
import threading
import time
import requests

API_KEY = os.environ.get("AGENT_API_KEY", "tea-platform-agent-key")
VIRT_TYPE = os.environ.get("VIRT_TYPE", "lxd")

# OpenGFW Configuration
PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:3000")
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "tea-platform-agent-key")

# Bandwidth monitoring thresholds
BANDWIDTH_THRESHOLD_MBPS = 100  # 100 Mbps
BANDWIDTH_MONITOR_INTERVAL = 60  # check every 60 seconds

app = Flask(__name__)


def check_auth():
    api_key = request.headers.get("X-API-Key", "")
    return api_key == API_KEY


# ─── OpenGFW functions ────────────────────────────────────────────────────────

def report_violation(server_id, machine_id, violation_type, detail=""):
    """Report a violation to the platform."""
    try:
        resp = requests.post(
            f"{PLATFORM_URL}/api/v1/agent/violations",
            json={
                "server_id": server_id,
                "machine_id": machine_id,
                "violation_type": violation_type,
                "detail": detail
            },
            headers={"X-API-Key": AGENT_API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            print(f"[OpenGFW] Violation reported: {violation_type} - {detail}")
        else:
            print(f"[OpenGFW] Failed to report violation: {resp.status_code}")
    except Exception as e:
        print(f"[OpenGFW] Error reporting violation: {e}")


def install_openGFW():
    """Install OpenGFW if not present."""
    try:
        # Check if openGFW binary exists
        result = subprocess.run(["which", "openGFW"], capture_output=True, text=True)
        if result.returncode != 0:
            print("[OpenGFW] Installing OpenGFW...")
            # Try to install via common methods
            subprocess.run(["bash", "-c", "curl -sSL https://raw.githubusercontent.com/apernet/OpenGFW/main/install.sh | bash"],
                           check=False, timeout=120)
            print("[OpenGFW] Install attempted")
    except Exception as e:
        print(f"[OpenGFW] Install error: {e}")


def check_traffic_abuse():
    """Monitor network traffic for abuse patterns."""
    while True:
        time.sleep(BANDWIDTH_MONITOR_INTERVAL)
        try:
            # Check interface traffic using /proc/net/dev or ifstat
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            for line in lines[2:]:  # skip headers
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].rstrip(':')
                    if iface == "lo":
                        continue
                    recv_bytes = int(parts[1])
                    # Rough estimation: if receiving > threshold
                    recv_mbps = (recv_bytes * 8) / (BANDWIDTH_MONITOR_INTERVAL * 1_000_000)
                    if recv_mbps > BANDWIDTH_THRESHOLD_MBPS:
                        report_violation(0, 0, "bandwidth_abuse",
                                         f"Interface {iface}: {recv_mbps:.1f} Mbps")
        except Exception as e:
            print(f"[OpenGFW] Traffic check error: {e}")


def check_vpn_processes():
    """Check for known VPN/proxy processes."""
    vpn_keywords = [
        "openvpn", "wireguard", "wg", "shadowsocks", "ss-server", "ss-local",
        "v2ray", "xray", "trojan", "naive", "hysteria", "sing-box",
        "clash", "brook", "gost", "iperf3", "speedtest"
    ]
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.split('\n'):
            for keyword in vpn_keywords:
                if keyword in line.lower() and "grep" not in line.lower() and "check_vpn" not in line.lower():
                    # Found a VPN process
                    report_violation(0, 0, "vpn_proxy",
                                     f"Detected process: {keyword}")
                    # Try to kill the process
                    parts = line.split()
                    if len(parts) > 1:
                        try:
                            pid = parts[1]
                            subprocess.run(["kill", "-9", pid], check=False)
                            print(f"[OpenGFW] Killed VPN process PID {pid}: {keyword}")
                        except:
                            pass
    except Exception as e:
        print(f"[OpenGFW] VPN check error: {e}")


def start_openGFW_monitor():
    """Start OpenGFW monitoring in background."""
    def monitor_loop():
        install_openGFW()
        print("[OpenGFW] Monitor started")
        while True:
            check_vpn_processes()
            time.sleep(30)

    # Start bandwidth monitor in separate thread
    bw_thread = threading.Thread(target=check_traffic_abuse, daemon=True)
    bw_thread.start()

    # Start VPN process monitor
    vpn_thread = threading.Thread(target=monitor_loop, daemon=True)
    vpn_thread.start()

    print("[OpenGFW] All monitors started")


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/status', methods=['GET'])
def status():
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
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
    return jsonify(status_info)


@app.route('/create', methods=['POST'])
def create():
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json() or {}
    name = body.get("name", f"vm-{body.get('cpu','1')}-{body.get('memory','1024')}")
    cpu = body.get("cpu", 1)
    memory = body.get("memory", 1024)  # MB
    disk = body.get("disk", 10)  # GB
    virt = body.get("virt_type", VIRT_TYPE)

    if virt == "lxd":
        cmd = f"lxc launch ubuntu:22.04 {name} -c limits.cpu={cpu} -c limits.memory={memory}MB"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return jsonify({"status": "created" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})
    elif virt == "kvm":
        cmd = f"virt-install --name {name} --vcpus {cpu} --memory {memory} --disk size={disk} --import --os-variant ubuntu22.04 --noautoconsole"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return jsonify({"status": "created" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})
    else:
        return jsonify({"error": f"unsupported virt_type: {virt}"}), 400


@app.route('/start/<name>', methods=['POST'])
def start_vm(name):
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    if VIRT_TYPE == "lxd":
        cmd = f"lxc start {name}"
    else:
        cmd = f"virsh start {name}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    return jsonify({"status": "started" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})


@app.route('/stop/<name>', methods=['POST'])
def stop_vm(name):
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    if VIRT_TYPE == "lxd":
        cmd = f"lxc stop {name}"
    else:
        cmd = f"virsh shutdown {name}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    return jsonify({"status": "stopped" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})


@app.route('/<name>', methods=['DELETE'])
def delete_vm(name):
    if not check_auth():
        return jsonify({"error": "unauthorized"}), 401
    if VIRT_TYPE == "lxd":
        cmd = f"lxc delete --force {name}"
    else:
        cmd = f"virsh destroy {name} 2>/dev/null; virsh undefine {name} --remove-all-storage"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    return jsonify({"status": "deleted" if result.returncode == 0 else "error", "output": result.stdout, "error": result.stderr})


# ─── OpenGFW API endpoints ────────────────────────────────────────────────────

@app.route('/openGFW/status', methods=['GET'])
def openGFW_status():
    """Get OpenGFW monitoring status."""
    return jsonify({
        "status": "running",
        "bandwidth_threshold_mbps": BANDWIDTH_THRESHOLD_MBPS,
        "monitor_interval": BANDWIDTH_MONITOR_INTERVAL
    })


@app.route('/openGFW/restart', methods=['POST'])
def openGFW_restart():
    """Restart OpenGFW monitor."""
    start_openGFW_monitor()
    return jsonify({"status": "restarted"})


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Start OpenGFW monitor
    start_openGFW_monitor()
    print(f"Agent running on port 19527, virt_type={VIRT_TYPE}")
    app.run(host="0.0.0.0", port=19527)