#!/usr/bin/env python3
"""Build a versioned read-only catalog from the CRS embedded in the Caddy build.

Usage: python scripts/build_rule_catalog.py /path/to/coreruleset/rules
Source statements and complete chains are preserved for inspection only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil


def tokens(statement):
    """Tokenize SecLang arguments, preserving escapes inside quoted strings."""
    result, index = [], 0
    while index < len(statement):
        if statement[index].isspace():
            index += 1
            continue
        quote = statement[index] if statement[index] in '\"\'' else None
        if quote:
            index += 1
        value = ''
        while index < len(statement):
            char = statement[index]
            if char == '\\' and index + 1 < len(statement):
                value += statement[index:index + 2]
                index += 2
            elif quote and char == quote:
                index += 1
                break
            elif not quote and char.isspace():
                break
            else:
                value += char
                index += 1
        result.append(value)
    return result


def action_values(actions, key):
    pattern = r'(?:^|,)\s*' + re.escape(key) + r':(?:\'((?:\\.|[^\'\\])*)\'|([^,]*))'
    return [(a or b).strip() for a, b in re.findall(pattern, actions)]


def statements(text):
    pending, start = [], 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending and (not line.strip() or line.lstrip().startswith('#')):
            continue
        if not pending:
            start = number
        pending.append(line)
        if not line.rstrip().endswith('\\'):
            source = '\n'.join(pending)
            yield start, source, re.sub(r'\\\s*\n\s*', '', source).strip()
            pending = []
    if pending:
        raise ValueError('Unterminated SecLang statement')


def build(root):
    rules, seen, digest, versions = [], set(), hashlib.sha256(), set()
    for path in sorted((root / '@owasp_crs').glob('*.conf')):
        content = path.read_text()
        digest.update(path.name.encode() + b'\0' + content.encode())
        chain_parent = None
        for line, source, statement in statements(content):
            args = tokens(statement)
            if args[0] not in {'SecRule', 'SecAction'}:
                if chain_parent is not None:
                    raise ValueError(f'Incomplete chain in {path.name}:{line}')
                continue
            expected = 4 if args[0] == 'SecRule' else 2
            if args[0] == 'SecRule' and len(args) == 3 and chain_parent is not None:
                args.append('')
            if len(args) != expected:
                raise ValueError(f'Invalid statement in {path.name}:{line}')
            actions = args[-1]
            ids = action_values(actions, 'id')
            chained = bool(re.search(r'(?:^|,)\s*chain\s*(?:,|$)', actions))
            if not ids:
                if chain_parent is None:
                    raise ValueError(f'Orphan chain in {path.name}:{line}')
                chain_parent['source'] += '\n' + source
                chain_parent['chain_length'] += 1
                if not chained:
                    chain_parent = None
                continue
            if chain_parent is not None:
                raise ValueError(f'Incomplete chain in {path.name}:{line}')
            rid = int(ids[0])
            if rid in seen:
                raise ValueError(f'Duplicate rule ID {rid}')
            seen.add(rid)
            tags = action_values(actions, 'tag')
            pl = next((int(tag.rsplit('/', 1)[1]) for tag in tags if re.fullmatch('paranoia-level/[1-4]', tag)), None)
            message = next(iter(action_values(actions, 'msg')), '')
            version = next(iter(action_values(actions, 'ver')), '')
            if version:
                versions.add(version)
            item = dict(id=rid, description=message or 'CRS internal control rule',
                        group=path.stem, pl=pl, phase=int(next(iter(action_values(actions, 'phase')), '0')),
                        severity=next(iter(action_values(actions, 'severity')), ''), tags=tags,
                        selectable=args[0] == 'SecRule' and pl is not None and bool(message),
                        file=path.name, line=line, source=source, chain_length=1)
            rules.append(item)
            if chained:
                chain_parent = item
        if chain_parent is not None:
            raise ValueError(f'Incomplete final chain in {path.name}')
    if len(versions) != 1 or not rules:
        raise ValueError(f'Expected exactly one CRS version, got {versions}')
    return dict(version=versions.pop(), source_sha256=digest.hexdigest(),
                rules=sorted(rules, key=lambda rule: rule['id']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rules_root', type=Path)
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1] / 'control/data/crs-rules.json')
    args = parser.parse_args()
    catalog = build(args.rules_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + '\n')
    shutil.copyfile(args.rules_root / 'LICENSE', args.output.parent / 'CRS-LICENSE.txt')
    print(f'{catalog["version"]}: {len(catalog["rules"])} rules; {sum(r["selectable"] for r in catalog["rules"])} selectable')
