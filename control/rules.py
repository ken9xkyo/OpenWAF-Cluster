"""Versioned metadata for the exact CRS bundled in the deployed Caddy binary."""
from functools import lru_cache
import json
from pathlib import Path

MAX_RULE_EXCLUSIONS = 2000
GROUP_LABELS = {
    '901': 'Khởi tạo', '905': 'Ngoại lệ chung', '911': 'HTTP method',
    '913': 'Scanner', '920': 'Tuân thủ giao thức', '921': 'Tấn công giao thức',
    '922': 'Multipart', '930': 'LFI', '931': 'RFI', '932': 'RCE', '933': 'PHP',
    '934': 'Tấn công ứng dụng khác', '941': 'XSS', '942': 'SQLi', '943': 'Session fixation',
    '944': 'Java', '949': 'Đánh giá chặn request', '999': 'Ngoại lệ sau kiểm tra',
    '950': 'Rò rỉ dữ liệu', '951': 'Rò rỉ SQL', '952': 'Rò rỉ Java', '953': 'Rò rỉ PHP',
    '954': 'Rò rỉ IIS', '955': 'Web shell', '956': 'Rò rỉ Ruby',
    '959': 'Đánh giá chặn response', '980': 'Tổng hợp điểm và sự kiện',
}


@lru_cache(maxsize=1)
def rule_catalog():
    data = json.loads((Path(__file__).parent / 'data/crs-rules.json').read_text())
    for rule in data['rules']:
        code = rule['group'].split('-')[1]
        rule['group_label'] = code + ' · ' + GROUP_LABELS.get(code, rule['group'])
    return data


@lru_cache(maxsize=1)
def rules_by_id():
    return {rule['id']: rule for rule in rule_catalog()['rules']}


def validate_rule_exclusions(excluded, reason):
    if not isinstance(excluded, list) or len(excluded) > MAX_RULE_EXCLUSIONS or any(
            type(value) is not int or not 100000 <= value <= 999999 for value in excluded):
        raise ValueError('Danh sách rule exception không hợp lệ')
    rules = rules_by_id()
    for rid in excluded:
        if rid in rules and not rules[rid]['selectable']:
            raise ValueError(f'Rule {rid} là rule hệ thống CRS, chỉ được xem')
    if excluded and not reason.strip():
        raise ValueError('Cần nhập lý do cho rule exception')
    return sorted(set(excluded))
