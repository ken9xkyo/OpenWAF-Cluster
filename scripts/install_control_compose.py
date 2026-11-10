#!/usr/bin/env python3
"""Migrate an already provisioned node to Compose, retaining PKI, DB and state."""
import argparse
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess

ROOT = Path(__file__).resolve().parents[1]
NODES = {'waf-cluster-1': '192.168.11.100', 'waf-cluster-2': '192.168.11.202'}
SERVICES = ['waf-control', 'waf-agent-api', 'waf-agent']
ENV = Path('/etc/waf-control/compose.env')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-build', action='store_true', help='Use an image already built/loaded on this node')
    args = parser.parse_args()
    node = socket.gethostname()
    if os.geteuid() != 0 or node not in NODES:
        parser.error('Run as root on a provisioned waf-cluster node')
    run('docker', 'compose', 'version')
    for path in ['/etc/waf-control/control.env', '/etc/waf-control/pki/ca.crt',
                 '/etc/waf-control/pki/server.crt', '/etc/waf-control/pki/server.key',
                 '/etc/waf-control/release-signing.key', '/etc/waf-agent/agent.json',
                 '/etc/waf-agent/pki/agent.crt', '/etc/waf-agent/pki/agent.key',
                 '/etc/caddy/tls', '/var/lib/waf-agent', '/var/lib/caddy',
                 '/var/lib/waf-control', '/var/log/caddy', '/var/log/coraza']:
        if not Path(path).exists():
            parser.error('Missing provisioned path: ' + path)
    control, caddy = pwd.getpwnam('waf-control'), pwd.getpwnam('caddy')
    ENV.touch(mode=0o600, exist_ok=True)
    ENV.chmod(0o600)
    ENV.write_text(f'CONTROL_UID={control.pw_uid}\nCONTROL_GID={control.pw_gid}\n'
                   f'CADDY_UID={caddy.pw_uid}\nCADDY_GID={caddy.pw_gid}\nNODE_IP={NODES[node]}\n')
    compose = ['docker', 'compose', '--env-file', str(ENV), '-f', str(ROOT / 'compose.yaml')]
    run(*compose, 'config', '--quiet')
    if not args.skip_build:
        (ROOT / 'docker').mkdir(exist_ok=True)
        shutil.copyfile('/usr/local/bin/caddy', ROOT / 'docker/caddy')
        (ROOT / 'docker/caddy').chmod(0o755)
        run(*compose, 'build', 'control')
    # Refuse migration if the container validator differs from the data plane.
    host_hash = run('sha256sum', '/usr/local/bin/caddy', capture_output=True, text=True).stdout.split()[0]
    image_hash = run('docker', 'run', '--rm', '--network', 'none', 'openwaf-control:local',
                     'sha256sum', '/usr/local/bin/caddy', capture_output=True, text=True).stdout.split()[0]
    if host_hash != image_hash:
        raise RuntimeError('Image Caddy differs from this node; rebuild before migration')
    installed = [s for s in SERVICES if run('systemctl', 'show', s, '--property=LoadState',
                                           '--value', capture_output=True, text=True).stdout.strip() != 'not-found']
    active = [s for s in installed if subprocess.run(['systemctl', 'is-active', '--quiet', s]).returncode == 0]
    enabled = [s for s in installed if subprocess.run(['systemctl', 'is-enabled', '--quiet', s]).returncode == 0]
    try:
        if installed:
            run('systemctl', 'disable', '--now', *installed)
        run(*compose, 'up', '-d', '--no-build', '--wait', '--wait-timeout', '150')
        run('systemctl', 'enable', 'docker')
    except Exception:
        # Restore host services only during the first migration, never start duplicates.
        if active:
            run(*compose, 'down')
            if enabled:
                run('systemctl', 'enable', *enabled)
            run('systemctl', 'start', *active)
        raise
    print('Control now runs in Docker Compose on ' + node)


if __name__ == '__main__':
    main()
