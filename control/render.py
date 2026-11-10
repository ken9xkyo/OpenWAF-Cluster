"""Deterministic, typed-input Caddy configuration for the two-node POC."""
import ipaddress
import re

NODES = {'waf-cluster-1': '192.168.11.100', 'waf-cluster-2': '192.168.11.202'}


def hostname(value):
    value = value.lower().rstrip('.')
    if len(value) > 253 or not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', value):
        raise ValueError('Tên miền không hợp lệ')
    return value


def validate_site(site, allowed_networks):
    site = dict(site)
    site['hostname'] = hostname(site['hostname'])
    ip = ipaddress.ip_address(site['backend_ip'])
    if not any(ip in ipaddress.ip_network(cidr) for cidr in allowed_networks):
        raise ValueError('Backend chưa thuộc dải địa chỉ được quản trị cho phép')
    site['backend_ip'] = str(ip)
    if ip.version != 4 or not 1 <= int(site['backend_port']) <= 65535:
        raise ValueError('Backend IPv4/port không hợp lệ')
    if site.get('mode') not in {'DetectionOnly', 'On'}:
        raise ValueError('Chọn DetectionOnly hoặc On')
    if int(site.get('paranoia', 1)) not in {1, 2, 3, 4}:
        raise ValueError('Paranoia level phải từ 1 đến 4')
    excluded = site.get('excluded_rules', [])
    if len(excluded) > 50 or any(not isinstance(x, int) or not 100000 <= x <= 999999 for x in excluded):
        raise ValueError('Danh sách rule exception không hợp lệ')
    if excluded and not site.get('exception_reason', '').strip():
        raise ValueError('Cần nhập lý do cho rule exception')
    return site


def render(node, sites, revision):
    ip = NODES[node]
    lines = ['{', '    admin 127.0.0.1:2019', '    http_port 8080', '    https_port 8443',
             '    auto_https disable_redirects', '    order coraza_waf first',
             f'    default_bind {ip}', '    servers {', '        protocols h1 h2',
             '        listener_wrappers {', '            proxy_protocol {',
             '                timeout 3s', '                allow 192.168.11.100/32 192.168.11.202/32',
             '                fallback_policy reject', '            }', '            tls',
             '        }', '    }', '}']
    lines += ['http://:8080 {', f'    bind {ip}',
              '    @health {', '        path /_lb/healthz',
              '        remote_ip 192.168.11.100/32 192.168.11.202/32', '    }',
              '    handle @health {', '        respond "ok" 200', '    }']
    for site in sites:
        if site.get('enabled', True):
            domain = hostname(site['hostname'])
            lines += [f'    @redirect_{site["id"]} host {domain}',
                      f'    handle @redirect_{site["id"]} {{', f'        redir https://{domain}{{uri}} 308', '    }']
    lines += ['    handle {', '        respond "Unknown host" 421', '    }', '}']
    for site in sites:
        if not site.get('enabled', True):
            continue
        domain = hostname(site['hostname'])
        lines += [f'https://{domain} {{', f'    bind {ip}']
        if node == 'waf-cluster-1':
            lines += ['    tls {', '        issuer acme {',
                      '            dir https://acme-v02.api.letsencrypt.org/directory',
                      '            disable_tlsalpn_challenge', '        }', '    }']
        else:
            lines += [f'    tls /etc/caddy/tls/{domain}.crt /etc/caddy/tls/{domain}.key']
        lines += ['    log {', '        output file /var/log/caddy/access.json {',
                  '            roll_size 10MiB', '            roll_keep 5', '        }',
                  '        format filter {', '            wrap json', '            fields {',
                  '                request>headers delete', '                request>uri delete',
                  '            }', '        }', '    }',
                  '    @health {', '        path /_waf_health',
                  '        remote_ip 192.168.11.100/32 192.168.11.202/32', '    }',
                  '    handle @health {', '        respond "ok" 200', '    }', '    handle {',
                  '        route {', '            coraza_waf {', '                load_owasp_crs',
                  '                directives `', '                    Include @coraza.conf-recommended',
                  '                    Include @crs-setup.conf.example',
                  f'                    SecRuleEngine {site["mode"]}',
                  '                    SecAuditEngine RelevantOnly',
                  '                    SecAuditLogFormat JSON', '                    SecAuditLogParts AHZ',
                  f'                    SecAuditLog /var/log/coraza/site-{site["id"]}.json',
                  f'                    SecAction "id:100010,phase:1,pass,nolog,setvar:tx.paranoia_level={site.get("paranoia", 1)}"',
                  '                    Include @owasp_crs/*.conf']
        if site.get('excluded_rules'):
            lines += ['                    SecRuleRemoveById ' + ' '.join(str(x) for x in sorted(site['excluded_rules']))]
        lines += ['                `', '            }',
                  f'            header X-WAF-Node {node}', f'            header X-WAF-Revision {revision}',
                  f'            reverse_proxy {site["backend_ip"]}:{site["backend_port"]} {{',
                  '                header_up -Forwarded', '                header_up X-Forwarded-For {remote_host}',
                  '                header_up X-Real-IP {remote_host}', '                header_up X-Forwarded-Proto {scheme}',
                  '                header_up X-Forwarded-Host {host}',
                  '                header_up X-Transaction-ID {http.transaction_id}',
                  '                fail_duration 30s', '                max_fails 3',
                  '                transport http {', '                    dial_timeout 5s', '                }',
                  '            }', '        }', '    }', '}']
    return '\n'.join(lines) + '\n'
