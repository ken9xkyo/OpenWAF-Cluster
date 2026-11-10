#!/usr/bin/env python3
"""Controlled WAF/LB failure checks for the authorized two-node POC.

Restores stopped services and returns the VIP to node 1 in finally blocks.
"""
import csv
import datetime as dt
import io
import json
from pathlib import Path
import socket
import subprocess
import time
import httpx

SSH = ['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes',
       '-o','HostKeyAlias=118.107.78.18','root@192.168.11.202']
report = {}


def remote(command):
    return subprocess.run(SSH+[command],check=True,capture_output=True,text=True,timeout=25).stdout


def runtime(command):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5);s.connect('/var/run/haproxy.sock');s.sendall((command+'\n').encode());s.shutdown(socket.SHUT_WR)
        parts=[]
        while True:
            chunk=s.recv(65536)
            if not chunk:break
            parts.append(chunk)
    return b''.join(parts).decode()


def status(name):
    rows=csv.DictReader(io.StringIO(runtime('show stat').lstrip('# ')))
    return next(r['status'] for r in rows if r.get('pxname')=='waf_https' and r.get('svname')==name)


def wait(predicate,label,timeout=40):
    start=time.monotonic()
    while time.monotonic()-start<timeout:
        try:
            if predicate():
                elapsed=round(time.monotonic()-start,2)
                print(label,elapsed,'seconds',flush=True)
                return elapsed
        except (OSError,httpx.HTTPError,subprocess.SubprocessError):
            pass
        time.sleep(.5)
    raise RuntimeError('Timed out: '+label)


def request():
    with httpx.Client(trust_env=False,timeout=5) as c:
        r=c.get('https://test-waf.vtccloud.vn/',headers={'Connection':'close'})
        assert r.status_code==200,r.status_code
        return r.headers['x-waf-node']


def local_has_vip():
    value=subprocess.check_output(['ip','-j','-4','address','show','dev','ens3'],text=True)
    return any(a['local']=='118.107.78.209' for link in json.loads(value) for a in link['addr_info'])


assert local_has_vip(),'Expected initial VIP on node 1'
assert status('waf01')=='UP' and status('waf02')=='UP'
try:
    runtime('disable server waf_https/waf01')
    assert all(request()=='waf-cluster-2' for _ in range(3))
    report['drain_waf01'] = 'all requests served by waf-cluster-2 with valid TLS and HTTP 200'
finally:
    runtime('enable server waf_https/waf01')
wait(lambda:status('waf01')=='UP','WAF01 available after drain')

try:
    remote('systemctl stop caddy')
    seconds=wait(lambda:status('waf02')=='DOWN','HAProxy detects stopped WAF02')
    assert all(request()=='waf-cluster-1' for _ in range(3))
    report['waf02_process_failure']={'health_detection_seconds':seconds,'remaining_node_http':200}
finally:
    remote('systemctl start caddy')
wait(lambda:status('waf02')=='UP','WAF02 recovered')

try:
    subprocess.run(['systemctl','stop','haproxy'],check=True)
    moved=wait(lambda:not local_has_vip(),'VIP removed from failed LB01')
    remote_vip=remote('ip -j -4 address show dev ens3')
    assert any(a['local']=='118.107.78.209' for link in json.loads(remote_vip) for a in link['addr_info'])
    recovered=wait(lambda:request() in {'waf-cluster-1','waf-cluster-2'},'HTTPS works through LB02 VIP')
    report['lb01_failure_vip_to_lb02']={'vip_removal_seconds':moved,'additional_https_probe_seconds':recovered,'http':200}
finally:
    subprocess.run(['systemctl','start','haproxy'],check=True)
    wait(lambda:status('waf01')=='UP' and status('waf02')=='UP','LB01 pools recovered')
    # nopreempt intentionally keeps VIP on node 2 after node 1 recovers.
    # Stop only node 2 VRRP briefly to restore the original VIP owner.
    try:
        remote('systemctl stop keepalived')
        wait(local_has_vip,'VIP returned to node 1')
        wait(lambda:request() in {'waf-cluster-1','waf-cluster-2'},'HTTPS restored via original VIP owner')
    finally:
        remote('systemctl start keepalived')
assert local_has_vip()
remote_vip=remote('ip -j -4 address show dev ens3')
assert not any(a['local']=='118.107.78.209' for link in json.loads(remote_vip) for a in link['addr_info'])
report.update(completed_at_utc=dt.datetime.now(dt.timezone.utc).isoformat(),final_vip_owner='waf-cluster-1')
path=Path(__file__).resolve().parents[1]/'reports/2026-11-10/ha-verification.json'
path.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2),flush=True)
