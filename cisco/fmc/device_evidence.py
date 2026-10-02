"""Selected-device supplementary evidence using the canonical FMC client.

Manager API results are retained as JSON evidence, not deployment observations
or a replacement for a complete policy/object capture. No device writes occur.
"""
from __future__ import annotations

import json
import base64
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.capture_evidence import receipt, store_receipt

MAX_RESPONSE = 32 * 1024 * 1024
MAX_CAPTURE = 64 * 1024 * 1024
SECTIONS = {
    'identity': '',
    'manager_physical_interfaces': '/physicalinterfaces',
    'manager_logical_interfaces': '/logicalinterfaces',
    'manager_bridge_interfaces': '/bridgegroupinterfaces',
    'manager_ipv4_static_routes': '/routing/ipv4staticroutes',
    'manager_ipv6_static_routes': '/routing/ipv6staticroutes',
}


class CaptureCancelled(BaseException):
    """Escape legacy client retry loops without converting cancellation to success."""


def validate_scope(scope):
    for field in ('domain_id', 'device_id'):
        if not isinstance(scope.get(field), str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', scope[field]):
            raise ValueError('Select exact FMC domain and device identities')
    return '/devices/devicerecords/' + scope['device_id']


def native_identity(payload, scope):
    """A native device ID and domain link must agree; wrapper claims are not proof."""
    from urllib.parse import urlsplit
    try:
        data = json.loads(payload)
        if isinstance(data, dict) and data.get('schema') == 'nc.fmc-api-responses.v1':
            responses = data.get('responses')
            if not isinstance(responses, list) or len(responses) != 1:
                return 'unverified'
            response = responses[0]
            expected = '/api/fmc_config/v1/domain/' + scope['domain_id'] + validate_scope(scope)
            if response.get('path') != expected or response.get('status') != 200:
                return 'unverified'
            native = json.loads(base64.b64decode(response['body_base64'], validate=True))
            if native != data.get('data'):
                return 'conflicting'
            data = native
        if not isinstance(data, dict) or not isinstance(data.get('id'), str):
            return 'unverified'
        if data['id'] != scope['device_id']:
            return 'conflicting'
        domain = ((data.get('metadata') or {}).get('domain') or {}).get('id')
        link = (data.get('links') or {}).get('self')
        if domain is not None:
            return 'matching' if domain == scope['domain_id'] else 'conflicting'
        if isinstance(link, str):
            expected = '/api/fmc_config/v1/domain/' + scope['domain_id'] + validate_scope(scope)
            return 'matching' if urlsplit(link).path.rstrip('/') == expected else 'conflicting'
    except (ValueError, TypeError, AttributeError, KeyError):
        pass
    return 'unverified'


def bounded_session(cancelled):
    import requests
    class Session(requests.Session):
        def __init__(self):
            super().__init__()
            self.captured_bytes = 0
            self.responses = []
            self.verify = True

        def request(self, method, url, **kwargs):
            if cancelled():
                raise CaptureCancelled()
            # Only canonical token endpoints may POST. All evidence is GET.
            from urllib.parse import urlsplit
            path = urlsplit(url).path
            if method.upper() != 'GET' and not (method.upper() == 'POST' and path in {
                    '/api/fmc_platform/v1/auth/generatetoken',
                    '/api/fmc_platform/v1/auth/refreshtoken'}):
                raise ValueError('Read-only FMC evidence request refused')
            kwargs.update(verify=True, allow_redirects=False, stream=True, timeout=(10, 30))
            response = super().request(method, url, **kwargs)
            try:
                chunks = []
                size = 0
                for chunk in response.iter_content(1024 * 1024):
                    if cancelled():
                        raise CaptureCancelled()
                    size += len(chunk)
                    self.captured_bytes += len(chunk)
                    if size > MAX_RESPONSE or self.captured_bytes > MAX_CAPTURE:
                        raise ValueError('FMC evidence response limit exceeded')
                    chunks.append(chunk)
                response._content = b''.join(chunks)
                response._content_consumed = True
                # Auth/token responses never enter evidence. Keep exact GET
                # response bytes separately from the canonical parsed section.
                if method.upper() == 'GET' and path.startswith('/api/fmc_config/v1/domain/'):
                    self.responses.append({'path':path, 'parameters':kwargs.get('params') or {},
                        'status':response.status_code,
                        'body_base64':base64.b64encode(response._content).decode('ascii')})
                return response
            finally:
                response.close()
    return Session()


def collect(host, username, password, scope, directory, *, version, source_revision,
            cancelled=lambda: False, on_progress=lambda row: None, retry_records=None,
            client_factory=None):
    if not re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]+)?', host):
        raise ValueError('Use an FMC hostname without a URL path or credentials')
    base = validate_scope(scope)
    if not isinstance(source_revision, str) or not re.fullmatch(r'[0-9a-f]{64}', source_revision):
        raise ValueError('An exact source revision is required')
    previous = {}
    for row in retry_records or []:
        if not isinstance(row, dict) or row.get('vendor') != 'cisco_fmc' or row.get('scope') != scope \
                or row.get('source_revision') != source_revision or row.get('kind') not in SECTIONS \
                or row['kind'] in previous:
            raise ValueError('Retry receipts differ from the selected FMC scope')
        previous[row['kind']] = row
    if client_factory is None:
        from .fmc_collect_data import FMCClient
        client_factory = FMCClient
    client = client_factory(host, username, password, domain_uuid=scope['domain_id'], verify=True)
    client.session.close()
    client.session = bounded_session(cancelled)
    records = dict(previous)
    stopped = False
    try:
        client.authenticate()
        for kind, suffix in SECTIONS.items():
            if cancelled():
                stopped = True
                break
            if kind != 'identity' and previous.get(kind, {}).get('status') == 'captured':
                continue
            raw = None
            status = 'collection_failed'
            failure = None
            complete = False
            try:
                client.session.responses = []
                if kind == 'identity':
                    data = client.get_json(base)
                    if not isinstance(data, dict) or '_error' in data:
                        raise ValueError('Device identity endpoint unavailable')
                    raw = json.dumps(data, sort_keys=True, allow_nan=False).encode()
                    identity = native_identity(raw, scope)
                    status = 'captured' if identity == 'matching' else 'conflicting' if identity == 'conflicting' else 'not_interpreted'
                    failure = None if identity == 'matching' else 'native_identity_unverified'
                else:
                    items = client.get_all(base + suffix)
                    evidence = client.endpoint_evidence.get(base + suffix, {})
                    # Preserve successful partial pages; they are not complete.
                    raw = json.dumps({'items':items, 'collection_evidence':evidence},
                                     sort_keys=True, allow_nan=False).encode()
                    complete = evidence.get('status') == 'complete'
                    status = 'captured' if complete else 'collection_failed'
                    failure = None if complete else 'endpoint_incomplete'
                if client.session.responses:
                    raw = json.dumps({'schema':'nc.fmc-api-responses.v1',
                        'responses':client.session.responses, 'data':json.loads(raw)},
                        sort_keys=True, allow_nan=False).encode()
                if len(raw) > MAX_CAPTURE:
                    raw = None
                    raise ValueError('Captured section exceeds its size limit')
            except CaptureCancelled:
                stopped = True
                failure = 'cancelled'
            except Exception:
                status = 'collection_failed'
                complete = False
                failure = 'endpoint_failed'
            record = receipt(vendor='cisco_fmc', scope=scope, kind=kind, collector_version=version,
                payload=raw, status=status, source_revision=source_revision,
                complete=complete, failure_code=failure)
            store_receipt(directory, record, raw)
            records[kind] = record
            on_progress(record)
            if stopped or (kind == 'identity' and status != 'captured'):
                break
    except CaptureCancelled:
        stopped = True
    finally:
        client.session.close()
    return {'records':list(records.values()), 'cancelled':stopped,
            'complete':not stopped and all(records.get(kind, {}).get('status') == 'captured' for kind in SECTIONS)}
