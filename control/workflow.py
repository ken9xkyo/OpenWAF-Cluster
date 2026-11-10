"""Read-only deployment status derived from snapshots and agent evidence."""
import hashlib
import json

from control.render import NODES

SITE_FIELDS = ('id', 'hostname', 'backend_ip', 'backend_port', 'mode', 'paranoia',
               'enabled', 'excluded_rules', 'exception_reason', 'crs_settings')
LABELS = {'hostname': 'Domain', 'backend_ip': 'Backend IP', 'backend_port': 'Port',
          'mode': 'Chế độ WAF', 'paranoia': 'Paranoia level', 'enabled': 'Bật website',
          'excluded_rules': 'Rule ngoại lệ', 'exception_reason': 'Lý do ngoại lệ',
          'crs_settings': 'Tham số CRS nâng cao'}


def normalized(site):
    result = {key: site.get(key) for key in SITE_FIELDS}
    result['crs_settings'] = site.get('crs_settings') or {}
    result['excluded_rules'] = sorted(site.get('excluded_rules') or [])
    return result


def snapshot_digest(sites):
    value = sorted((normalized(s) for s in sites), key=lambda s: s['id'])
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def node_verified(node, revision):
    config = revision['configs'].get(node['id'])
    return bool(config and node.get('online') and node.get('health') == 'healthy'
                and node.get('actual_revision') == revision['id']
                and node.get('actual_digest') == hashlib.sha256(config.encode()).hexdigest())


def node_ready(node, revision):
    return node.get('desired_revision') == revision['id'] and node_verified(node, revision)


def deployment_status(sites, nodes, revisions, deployments):
    """Revisions include node references even when outside the visible history."""
    digest = snapshot_digest(sites)
    revisions = sorted(revisions, key=lambda r: r['id'], reverse=True)
    target = next((r for r in revisions if snapshot_digest(r['snapshot']) == digest), None)
    by_revision = {r['id']: r for r in revisions}
    by_node = {n['id']: n for n in nodes}
    active = next((d for d in deployments if d['state'] in ('canary', 'rollout')), None)
    node_states = []
    for node_id in NODES:
        node = by_node.get(node_id, {'id': node_id})
        revision = by_revision.get(node.get('actual_revision'))
        verified = bool(revision and node_verified(node, revision))
        matches = bool(revision and snapshot_digest(revision['snapshot']) == digest)
        node_states.append({'id': node_id, 'actual_revision': node.get('actual_revision'),
                            'desired_revision': node.get('desired_revision'),
                            'online': bool(node.get('online')), 'health': node.get('health', 'unknown'),
                            'detail': node.get('detail', ''), 'last_seen': node.get('last_seen'),
                            'verified': verified, 'matches_draft': matches,
                            'applied': verified and matches})
    rows = []
    for site in sites:
        statuses = []
        for node in node_states:
            revision = by_revision.get(node['actual_revision'])
            previous = next((s for s in revision['snapshot'] if s['id'] == site['id']), None) if revision else None
            changed = [LABELS[k] for k in LABELS if normalized(site)[k] != normalized(previous)[k]] if previous else ['Website mới']
            statuses.append({'id': node['id'], 'matches': not changed,
                             'applied': not changed and node['verified'], 'changed_fields': changed})
        rows.append({'id': site['id'], 'hostname': site['hostname'], 'nodes': statuses,
                     'applied': all(n['applied'] for n in statuses)})
    synced = bool(sites) and all(n['applied'] for n in node_states)
    deployment = next((d for d in deployments if target and d['revision_id'] == target['id']), None)
    stage = 'draft'
    if synced:
        stage = 'complete'
    elif target:
        stage = 'approved' if target.get('approved_at') else 'checked' if target.get('validated') else 'draft'
        if deployment and deployment['state'] in ('canary', 'rollout', 'aborted'):
            stage = deployment['state']
        elif deployment and deployment['state'] == 'complete':
            stage = 'attention'
    return {'draft_digest': digest, 'revision_id': target['id'] if target else None,
            'stage': stage, 'applied': synced, 'nodes': node_states, 'sites': rows,
            'active_deployment': active, 'deployment': deployment,
            'pending_sites': sum(not s['applied'] for s in rows)}
