#!/usr/bin/env python3
from pathlib import Path
import socket
import subprocess

node = socket.gethostname()
assert node in {'waf-cluster-1', 'waf-cluster-2'}
config = '''global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon
    maxconn 4096
    stats socket /var/run/haproxy.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
defaults
    log global
    mode tcp
    option tcplog
    option dontlognull
    timeout connect 5s
    timeout client 300s
    timeout server 300s
    timeout check 5s
listen admin_stats
    bind 127.0.0.1:8085
    mode http
    stats enable
    stats uri /stats
frontend http_in
    bind 0.0.0.0:80
    default_backend waf_http
frontend https_in
    bind 0.0.0.0:443
    default_backend waf_https
backend waf_http
    mode tcp
    balance roundrobin
    option httpchk
    http-check send meth GET uri /_lb/healthz ver HTTP/1.1 hdr Host lb-health.internal
    http-check expect status 200
    http-check expect string ok
    server waf01 192.168.11.100:8080 check inter 3s fall 3 rise 2 send-proxy-v2 check-send-proxy
    server waf02 192.168.11.202:8080 backup check inter 3s fall 3 rise 2 send-proxy-v2 check-send-proxy
backend waf_https
    mode tcp
    balance roundrobin
    option httpchk
    http-check send meth GET uri /_waf_health ver HTTP/1.1 hdr Host test-waf.vtccloud.vn
    http-check expect status 200
    http-check expect string ok
    server waf01 192.168.11.100:8443 check inter 3s fall 3 rise 2 send-proxy-v2 check-send-proxy check-ssl verify required verifyhost test-waf.vtccloud.vn ca-file /etc/ssl/certs/ca-certificates.crt check-sni test-waf.vtccloud.vn
    server waf02 192.168.11.202:8443 check inter 3s fall 3 rise 2 send-proxy-v2 check-send-proxy check-ssl verify required verifyhost test-waf.vtccloud.vn ca-file /etc/ssl/certs/ca-certificates.crt check-sni test-waf.vtccloud.vn
'''
target = Path('/etc/haproxy/haproxy.cfg')
candidate = target.with_suffix('.candidate')
candidate.write_text(config)
candidate.chmod(0o640)
subprocess.run(['haproxy', '-c', '-f', str(candidate)], check=True)
candidate.replace(target)
subprocess.run(['systemctl', 'reload', 'haproxy'], check=True)
print('HAProxy configured for TCP/PROXY v2; HTTP ACME traffic prefers node 1.')
