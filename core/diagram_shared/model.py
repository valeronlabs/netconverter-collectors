"""Derived presentation graph, never a replacement for NCIR or a verdict engine.

Hosts select the immutable snapshot and apply their authorization/privacy view
before calling this module. Only explicit fields/relationships are projected.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import ipaddress
import json

SCHEMA = 'nc.diagram.v1'
VERSION = '1.0.0'
KINDS = ('topology', 'comparison', 'traffic', 'nat', 'policy')
BASES = ('configured', 'observed', 'inferred', 'unknown', 'modeled')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def display(value):
    if value is None:
        return ''
    if isinstance(value, (list, tuple)):
        return ', '.join(display(v) for v in value)
    if isinstance(value, dict):
        return canonical(value).decode()
    # Make forbidden XML codepoints visible instead of breaking an export.
    return ''.join(c if c in '\n\t' or 32 <= ord(c) <= 0xD7FF or 0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF
                   else '\\u%04x' % ord(c) for c in str(value))


def items(value):
    if isinstance(value, dict):
        return [(str(k), v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0])) if isinstance(v, dict)]
    if isinstance(value, list):
        return [(str(i), v) for i, v in enumerate(value) if isinstance(v, dict)]
    return []


def strings(value):
    if value is None or value == '':
        return []
    return [display(v) for v in value] if isinstance(value, (list, tuple)) else [display(value)]


def normalized(source):
    """Read the two existing serialization shapes; do not parse vendor syntax."""
    if not isinstance(source, Mapping):
        return {}
    core = source.get('core', source)
    if not isinstance(core, Mapping) or not core:
        return {}
    data = dict(core)
    modules = source.get('modules') or {}
    if not isinstance(modules, dict):
        modules = {}
    for module in ('routing', 'policy'):
        content = modules.get(module) or {}
        for key, value in (content.items() if isinstance(content, Mapping) else []):
            data.setdefault(key, value)
    if 'static_routes' in data:
        data.setdefault('routes', data['static_routes'])
    vpn = modules.get('vpn') or {}
    if isinstance(vpn, Mapping) and 'tunnels' in vpn:
        data.setdefault('vpn_tunnels', vpn['tunnels'])
    for field in ('coverage', 'diagram_limitations'):
        if field in source:
            data[field] = source[field]
    data['metadata'] = dict(source.get('metadata') or {})
    data['metadata'].setdefault('technology', source.get('kind', 'firewall'))
    # Preserve resolvable locators in either existing serialization shape.
    for family in ('interfaces', 'zones', 'routes', 'security_rules', 'nat_rules', 'vpn_tunnels'):
        prefix = ('core', family) if 'core' in source and family in core else (family,)
        if family == 'routes' and family not in core:
            prefix = ('core', 'static_routes') if 'static_routes' in core and 'core' in source else ('static_routes',)
            if 'static_routes' not in core:
                prefix = ('modules', 'routing', 'static_routes')
        if family == 'vpn_tunnels' and family not in core:
            prefix = ('modules', 'vpn', 'tunnels')
        for module in ('routing', 'policy'):
            content = modules.get(module)
            if family not in core and isinstance(content, Mapping) and family in content:
                prefix = ('modules', module, family)
        records = data.get(family)
        if isinstance(records, dict):
            data[family] = {key: {**row, 'evidence_refs': row.get('evidence_refs') or [pointer(*prefix, key)]}
                            for key, row in items(records)}
        elif isinstance(records, list):
            data[family] = [{**row, 'evidence_refs': row.get('evidence_refs') or [pointer(*prefix, key)]}
                            for key, row in items(records)]
    return data


def namespace(row):
    return tuple(str(row.get(key) or '') for key in
                 ('vrf', 'vsys', 'vdom', 'device_group', 'domain', 'layer', 'install_target'))


def pointer(*parts):
    return '/' + '/'.join(str(p).replace('~', '~0').replace('/', '~1') for p in parts)


def build_diagram(source, *, kind='topology', side='source', target=None,
                  provenance=None, flow_results=None, max_nodes=120):
    """Build a bounded graph from a host-selected source/target snapshot.

    `provenance` is host-owned (job/revision/scope/hash/view), never an external
    tool argument. Record evidence_refs on normalized native rows to preserve
    their original locators. Absence and bounds are explicit in coverage.
    """
    if kind not in KINDS or side not in ('source', 'target'):
        raise ValueError('Unsupported diagram kind or side')
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or not 4 <= max_nodes <= 1000:
        raise ValueError('max_nodes must be an integer from 4 to 1000')
    # Detach from mutable caller state and reject non-JSON inputs early.
    prov = json.loads(canonical(provenance or {}))
    chosen = target if side == 'target' and kind != 'comparison' else source
    data = normalized(chosen)
    nodes, edges, groups, reasons = {}, {}, {}, []
    unavailable = False

    def refs(row, path):
        return strings(row.get('evidence_refs')) or [path]

    def node(key, label, icon, row, path, *, detail='', level=1, group='', basis='configured', change=None):
        identifier = 'n-' + digest([side, prov.get('scope'), key])[:20]
        record = {'id': identifier, 'label': display(label), 'detail': display(detail),
                  'icon': 'nc-' + icon, 'evidence_refs': refs(row, path),
                  'basis': basis if basis in BASES else 'unknown', 'level': level, 'group': display(group)}
        if change:
            record['change'] = change
        nodes[identifier] = record
        if group:
            groups[str(group)] = {'id': str(group), 'label': display(group)}
        return identifier

    def edge(a, b, label, row, path, basis='configured'):
        identifier = 'e-' + digest([a, b, label, path])[:20]
        edges[identifier] = {'id': identifier, 'source': a, 'target': b,
                             'label': display(label), 'evidence_refs': refs(row, path),
                             'basis': basis if basis in BASES else 'unknown'}

    def missing(message):
        if message not in reasons:
            reasons.append(message)

    if kind != 'traffic' and not data:
        unavailable = True
        missing('Selected immutable ' + side + ' data is unavailable.')

    if kind == 'comparison':
        if not normalized(source) or not normalized(target):
            unavailable = True
            missing('Source and target evidence are both required for a comparison.')
        else:
            left, right = normalized(source), normalized(target)
            for family, icon in [('interfaces', 'interface'), ('zones', 'security-zone'),
                                 ('routes', 'route'), ('security_rules', 'policy'), ('nat_rules', 'nat')]:
                if family not in left or family not in right:
                    missing(f'{family} comparison unavailable: collection missing from source or target readback; no additions/removals inferred.')
                    continue
                # Position, native namespace and name form identity. A rename is
                # not presumed equivalent; show removal/addition for review.
                def index(records):
                    return {(str(row.get('name') or key), str(row.get('vrf') or row.get('vsys') or ''), key): (key, row)
                            for key, row in items(records)}
                a, b = index(left.get(family)), index(right.get(family))
                for identity in sorted(set(a) | set(b)):
                    ar, br = a.get(identity), b.get(identity)
                    change = 'added' if ar is None else 'removed' if br is None else 'unchanged' if ar[1] == br[1] else 'changed'
                    if change == 'unchanged':
                        continue
                    previous = None
                    for number, pair in enumerate((ar, br)):
                        if pair is None:
                            continue
                        key, row = pair
                        origin = 'source' if number == 0 else 'target'
                        row = {**row, 'evidence_refs': [origin + ':' + ref for ref in refs(row, pointer(family, key))]}
                        label = ('Source / ' if number == 0 else 'Target / ') + identity[0]
                        path = pointer('source' if number == 0 else 'target', family, key)
                        current = node([family, identity, number], label, icon, row, path,
                                       detail=change + ' · ' + family, level=number + 1, group=family, change=change)
                        if previous:
                            edge(previous, current, 'changed fields; not equivalence proof', row, path)
                        previous = current
            missing('Comparison is a structural difference view; renamed entities are not assumed equivalent.')
            if not nodes:
                missing('No differences in the represented interface/zone/route/policy/NAT collections. Other features are not compared.')

    elif kind == 'topology' and data:
        meta = data.get('metadata', {})
        role = str(meta.get('technology', 'firewall')).lower()
        role = role if role in ('firewall', 'router', 'switch', 'host', 'server') else 'gateway'
        dev = node('device', meta.get('device_hostname') or 'Selected device', role, meta, '/metadata' if chosen.get('metadata') else '/', level=0)
        iface_nodes, zone_nodes = {}, {}

        def remember(table, row, names, identifier):
            for name in set(names):
                scoped = (namespace(row), str(name))
                table[scoped] = identifier if scoped not in table else None

        def resolve(table, row, name):
            return table.get((namespace(row), str(name)))
        for key, row in items(data.get('zones')):
            name = str(row.get('name') or key)
            zid = node(['zone', key], name, 'security-zone', row, pointer('zones', key), level=1)
            remember(zone_nodes, row, [name, key], zid)
        for key, row in items(data.get('interfaces')):
            name = str(row.get('name') or key)
            path = pointer('interfaces', key)
            detail = ' · '.join(display(row[k]) for k in ('cidr', 'ip_address', 'netmask', 'vrf') if row.get(k))
            iid = node(['interface', key], name, 'interface', row, path, detail=detail, level=2,
                       group=str(row.get('vrf') or row.get('vsys') or ''))
            remember(iface_nodes, row, [key, name], iid)
            edge(dev, iid, 'configured interface', row, path)
            address = row.get('cidr') or row.get('ip_address')
            if address:
                try:
                    value = str(address)
                    if '/' not in value and row.get('netmask'):
                        value += '/' + str(row['netmask'])
                    # A bare address does not establish a subnet prefix.
                    if '/' in value:
                        subnet = str(ipaddress.ip_interface(value).network)
                        sid = node(['subnet', key, subnet], subnet, 'subnet', row, path,
                                   detail='Prefix derived from configured interface address', level=3,
                                   group=str(row.get('vrf') or row.get('vsys') or ''))
                        edge(iid, sid, 'configured prefix; reachability unverified', row, path)
                except ValueError:
                    missing('An interface address has no interpretable prefix; no subnet was invented.')
            zone = resolve(zone_nodes, row, row.get('zone'))
            if zone:
                edge(zone, iid, 'zone membership', row, path)
            elif row.get('zone'):
                missing('Zone membership is absent or ambiguous in this namespace; no cross-scope link was invented.')
        for key, row in items(data.get('zones')):
            z = resolve(zone_nodes, row, row.get('name') or key)
            if not z:
                missing('Duplicate zone identities in one namespace are unresolved.')
                continue
            for name in strings(row.get('interfaces')):
                resolved = resolve(iface_nodes, row, name)
                if resolved:
                    # Same relationship may be represented on both entities.
                    if not any(e['source'] == z and e['target'] == resolved for e in edges.values()):
                        edge(z, resolved, 'zone membership', row, pointer('zones', key, 'interfaces'))
                else:
                    missing('A zone references an interface absent from the selected snapshot.')
        for key, row in items(data.get('routes')):
            path = pointer('routes', key)
            destination = row.get('destination') or row.get('network') or row.get('prefix')
            rid = node(['route', key], destination or row.get('name') or 'Route', 'route', row, path,
                       detail=' · '.join(display(row[k]) for k in ('next_hop', 'gateway', 'vrf') if row.get(k)), level=3)
            interface = row.get('interface') or row.get('egress_interface') or row.get('next_hop_interface')
            resolved = resolve(iface_nodes, row, interface)
            if resolved:
                edge(resolved, rid, 'configured route; reachability unverified', row, path)
            else:
                missing('Route egress is absent or unresolved; no interface link was invented.')
        for key, row in items(data.get('vpn_tunnels')):
            path = pointer('vpn_tunnels', key)
            vid = node(['vpn', key], row.get('name') or 'VPN tunnel', 'vpn', row, path,
                       detail=display(row.get('peer_address') or row.get('peer') or 'Peer not captured'), level=3)
            interface = row.get('interface') or row.get('tunnel_interface')
            resolved = resolve(iface_nodes, row, interface)
            if resolved:
                edge(resolved, vid, 'configured tunnel; runtime unverified', row, path)
            else:
                missing('VPN interface binding is unavailable; tunnel is shown without an inferred link.')
        if not iface_nodes:
            missing('No interface records available in the selected snapshot.')
        missing('Configured relationships do not prove live connectivity. Neighbor and operational evidence were not assessed.')

    elif kind in ('nat', 'policy') and data:
        family = 'nat_rules' if kind == 'nat' else 'security_rules'
        for key, row in items(data.get(family)):
            path = pointer(family, key)
            state = 'disabled' if row.get('enabled') is False else 'configured; runtime unverified'
            detail = ' · '.join(filter(None, [display(row.get('direction') if kind == 'nat' else row.get('action')), state,
                                              'service: ' + display(row.get('original_service') or row.get('services')) if row.get('original_service') or row.get('services') else '']))
            rule = node([family, key], row.get('name') or f'{kind} {key}', kind, row, path, detail=detail, level=1, group=path)
            if kind == 'nat':
                pairs = [('original_source', 'translated_source'), ('original_destination', 'translated_destination'),
                         ('original_service', 'translated_service')]
                for left, right in pairs:
                    for field, level in ((left, 0), (right, 2)):
                        if row.get(field) is None:
                            continue
                        endpoint = node([family, key, field], display(row[field]), 'host', row, pointer(family, key, field),
                                        detail=field.replace('_', ' '), level=level, group=path)
                        edge(endpoint, rule, 'match ' + field.replace('original_', ''), row, path) if level == 0 else edge(rule, endpoint, 'translate ' + field.replace('translated_', ''), row, path)
                missing('NAT relationships show configured transforms, not packet reachability or rule selection.')
            else:
                for field, level, icon in [('source_zones', 0, 'security-zone'), ('dest_zones', 2, 'security-zone'),
                                           ('source_networks', 0, 'host'), ('dest_networks', 2, 'host')]:
                    for index, value in enumerate(strings(row.get(field))):
                        endpoint = node([family, key, field, index], value, icon, row, pointer(family, key, field, index),
                                        detail=field.replace('_', ' '), level=level, group=path)
                        edge(endpoint, rule, 'configured match', row, path) if level == 0 else edge(rule, endpoint, 'configured match', row, path)
                missing('Policy relationships are match criteria, not a flow verdict; order, exclusions and additional conditions remain in the rule evidence.')
        if not nodes:
            missing('No ' + family.replace('_', ' ') + ' available in the selected snapshot.')

    elif kind == 'traffic':
        records = flow_results if isinstance(flow_results, list) else [flow_results] if isinstance(flow_results, dict) else []
        for key, row in items(records):
            if not row.get('verdict'):
                missing('A supplied flow record has no evaluator verdict; it was not drawn as an evaluated path.')
                continue
            basis = 'observed' if row.get('basis') == 'observed' and row.get('evidence_refs') else 'modeled'
            group = 'Flow ' + str(int(key) + 1)
            path = pointer('flow_results', key)
            a = node([key, 'source'], row.get('source_ip') or 'Source not recorded', 'host', row, path, level=0, group=group, basis=basis)
            b = node([key, 'verdict'], 'Flow ' + display(row.get('protocol') or ''), 'flow', row, path,
                     detail=display(row['verdict']) + ' · ' + display(row.get('verdict_reason') or 'See flow evidence'), level=1, group=group, basis=basis)
            c = node([key, 'destination'], row.get('destination_ip') or 'Destination not recorded', 'host', row, path,
                     detail=' · '.join(display(row[k]) for k in ('destination_port', 'source_translated', 'destination_translated') if row.get(k) is not None), level=2, group=group, basis=basis)
            edge(a, b, basis + ' flow input', row, path, basis)
            edge(b, c, display(row['verdict']), row, path, basis)
        if not nodes:
            unavailable = True
            missing('No flow was evaluated or recorded. Request a supported simulation with an explicit packet, or inspect policy relationships.')
        missing('Modeled behavior and observed traffic are different evidence layers; neither changes the job verdict.')

    if data and data.get('coverage'):
        missing('Source coverage limits apply; consult the source receipt.')
    for scope_data in ([data, normalized(target)] if kind == 'comparison' else [data]):
        for limitation in strings(scope_data.get('diagram_limitations')):
            missing(limitation)
    all_nodes = list(nodes.values())
    selected = all_nodes[:max_nodes]
    ids = {n['id'] for n in selected}
    all_edges = list(edges.values())
    selected_edges = [e for e in all_edges if e['source'] in ids and e['target'] in ids]
    omitted = len(all_nodes) - len(selected)
    if omitted:
        missing(f'Bounded view omits {omitted} nodes. Narrow the selected scope or request a higher max_nodes limit; original records remain unchanged.')
    prov.setdefault('source_sha256', digest(source) if isinstance(source, Mapping) else None)
    if isinstance(target, Mapping):
        prov.setdefault('target_sha256', digest(target))
    coverage = {'status': 'unavailable' if unavailable else 'partial',
                'reasons': reasons, 'total_nodes': len(all_nodes), 'total_edges': len(all_edges),
                'omitted_nodes': omitted, 'omitted_edges': len(all_edges) - len(selected_edges),
                'basis': 'selected evidence only; no live discovery'}
    # Conservative: diagram coverage never promotes the source's intake status.
    if not unavailable and not omitted and nodes:
        coverage['status'] = 'available'
    result = {'schema': SCHEMA, 'library_version': VERSION, 'icon_version': VERSION,
              'kind': kind, 'side': side, 'title': kind.title() + ' / ' + side,
              'provenance': prov, 'nodes': selected, 'edges': selected_edges,
              'groups': list(groups.values()), 'coverage': coverage,
              'notice': 'Derived documentation. Editing a drawing does not modify configuration, NCIR or verification evidence.'}
    result['id'] = 'diagram-' + digest(result)[:32]
    return result
