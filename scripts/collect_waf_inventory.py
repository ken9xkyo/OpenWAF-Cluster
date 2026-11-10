#!/usr/bin/env python3
"""Read-only WAF inventory. No configuration changes, reloads or secret dumps."""
import argparse
import csv
import datetime
import io
import json
from pathlib import Path
import socket
import subprocess


def run(argv):
    try:
        p = subprocess.run(argv, text=True, capture_output=True, timeout=15)
        return {"exit_code": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}


def config_summary(path, allowed):
    p = Path(path)
    if not p.exists():
        return []
    output = []
    in_peer = False
    for raw in p.read_text().splitlines():
        line = raw.strip()
        words = line.split()
        if not words or line.startswith('#'):
            continue
        if words[0] == 'unicast_peer':
            in_peer = True
            output.append(line)
        elif in_peer:
            output.append(line)
            if '}' in line:
                in_peer = False
        elif words[0] in allowed:
            output.append(line)
        elif 'keepalived' in path and words[0][0].isdigit():
            output.append(line)
    return output


def collect():
    commands = {
        "hostname": ["hostname"], "os": ["cat", "/etc/os-release"],
        "kernel": ["uname", "-r"], "virtualization": ["systemd-detect-virt"],
        "cpu_count": ["nproc"], "memory": ["free", "-h"],
        "disk": ["df", "-hT"], "interfaces": ["ip", "-br", "address"],
        "routes": ["ip", "-4", "route"], "listeners": ["ss", "-lnt"],
        "haproxy_version": ["haproxy", "-v"], "nginx_version": ["nginx", "-v"],
        "docker_version": ["docker", "--version"], "caddy_version": ["caddy", "version"],
        "containers": ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
        "packages": ["dpkg-query", "-W", "-f=${Package}\t${Version}\n", "haproxy", "keepalived", "nginx", "bunkerweb", "docker-ce", "docker.io", "openssh-server"],
        "service_states": ["systemctl", "is-active", "bunkerweb", "haproxy", "keepalived", "caddy", "nginx", "docker", "postgresql"],
        "haproxy_validation": ["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"],
    }
    result = {"collected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "commands": {name: run(argv) for name, argv in commands.items()}}
    result["haproxy_config_summary"] = config_summary('/etc/haproxy/haproxy.cfg', {
        'mode', 'frontend', 'backend', 'listen', 'bind', 'default_backend',
        'use_backend', 'server', 'option', 'http-check', 'tcp-check'})
    result["keepalived_config_summary"] = config_summary('/etc/keepalived/keepalived.conf', {
        'vrrp_instance', 'state', 'interface', 'virtual_router_id', 'priority',
        'advert_int', 'nopreempt', 'unicast_src_ip', 'virtual_ipaddress',
        'track_script', 'vrrp_script', 'script', 'interval', 'fall', 'rise', 'weight'})
    try:
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(5)
            s.connect('/var/run/haproxy.sock')
            s.sendall(b'show stat\n')
            s.shutdown(socket.SHUT_WR)
            parts = []
            while True:
                part = s.recv(65536)
                if not part:
                    break
                parts.append(part)
        rows = csv.DictReader(io.StringIO(b''.join(parts).decode().lstrip('# ')))
        keys = ['pxname', 'svname', 'status', 'check_status', 'check_code', 'lastchg', 'scur', 'stot']
        result['haproxy_backend_status'] = [{k: r.get(k) for k in keys} for r in rows
                                            if r.get('pxname') in {'waf_http', 'waf_https'}]
    except OSError as e:
        result['haproxy_backend_status_error'] = str(e)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh', help='SSH destination, e.g. root@192.168.11.202')
    parser.add_argument('--host-key-alias', help='Previously verified known_hosts name')
    parser.add_argument('--output', help='Local JSON output file; defaults to stdout')
    args = parser.parse_args()
    if args.ssh:
        argv = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=yes']
        if args.host_key_alias:
            argv += ['-o', 'HostKeyAlias=' + args.host_key_alias]
        argv += [args.ssh, 'python3 -']
        # The remote process only reads inventory and prints JSON.
        p = subprocess.run(argv, input=Path(__file__).read_text(), text=True,
                           capture_output=True, timeout=180, check=True)
        result = json.loads(p.stdout)
    else:
        result = collect()
    payload = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload)
        print(path)
    else:
        print(payload, end='')


if __name__ == '__main__':
    main()
