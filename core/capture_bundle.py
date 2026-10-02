"""Portable evidence receipts and responses; distinct from migration packages.

No archive member is extracted to the filesystem. Native identity and semantic
association remain the responsibility of the receiving canonical adapter.
"""
from hashlib import sha256
from io import BytesIO
import json
import re
import stat
import zipfile

from .capture_evidence import validate_receipt

SCHEMA = 'nc.capture-bundle.v1'
MAX_BYTES = 256 * 1024 * 1024
MAX_RESPONSE = 128 * 1024 * 1024
MAX_RECEIPT = 64 * 1024
MAX_RECORDS = 256


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def read_bundle(raw):
    """Validate the complete bounded archive before returning any evidence."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Evidence archive exceeds its size limit')
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > 1 + 2 * MAX_RECORDS:
                raise ValueError('Evidence archive member limit exceeded')
            names = set()
            total = 0
            for entry in infos:
                name = entry.filename
                if name in names or not (name == 'manifest.json' or
                        re.fullmatch(r'evidence/[0-9a-f]{64}\.(json|native)', name)):
                    raise ValueError('Invalid or duplicate evidence archive path')
                if entry.flag_bits & 1 or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG):
                    raise ValueError('Encrypted members and links are unsupported')
                limit = MAX_RESPONSE if name.endswith('.native') else MAX_RECEIPT
                total += entry.file_size
                if entry.file_size > limit or total > MAX_BYTES:
                    raise ValueError('Expanded evidence archive exceeds its size limit')
                names.add(name)
            if 'manifest.json' not in names:
                raise ValueError('Evidence bundle manifest is missing')
            manifest = _json(archive.read('manifest.json'))
            if not isinstance(manifest, dict) or set(manifest) != {'schema','receipts'} or manifest['schema'] != SCHEMA:
                raise ValueError('Unsupported evidence bundle schema')
            ids = manifest['receipts']
            if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_RECORDS or not all(
                    isinstance(item, str) and re.fullmatch(r'[0-9a-f]{64}', item) for item in ids):
                raise ValueError('Invalid evidence receipt list')
            if len(set(ids)) != len(ids):
                raise ValueError('Repeated evidence receipt identity')
            expected = {'manifest.json'}
            rows = []
            for identifier in ids:
                receipt_path = 'evidence/' + identifier + '.json'
                expected.add(receipt_path)
                record = _json(archive.read(receipt_path))
                if not isinstance(record, dict) or record.get('id') != identifier:
                    raise ValueError('Receipt identity differs from its archive path')
                payload = None
                if record.get('sha256') is not None:
                    native_path = 'evidence/' + identifier + '.native'
                    expected.add(native_path)
                    payload = archive.read(native_path)
                validate_receipt(record, payload)
                rows.append((record, payload))
            if expected != names:
                raise ValueError('Evidence archive contains unaccounted members')
            return {'schema':SCHEMA, 'sha256':sha256(raw).hexdigest(), 'records':rows}
    except (zipfile.BadZipFile, KeyError, UnicodeError, TypeError, RuntimeError, NotImplementedError) as exc:
        raise ValueError('Invalid evidence archive or receipt') from exc


def build_bundle(rows):
    """Package existing validated receipts without rewriting their provenance."""
    # Bound generators before consuming them and validate expanded sizes before
    # allocating an archive. A highly compressible oversized response still
    # exceeds the evidence limit.
    prepared = []
    identifiers = []
    total = 0
    for record, payload in rows:
        if len(prepared) >= MAX_RECORDS:
            raise ValueError('Evidence record limit exceeded')
        if payload is not None and (not isinstance(payload, bytes) or len(payload) > MAX_RESPONSE):
            raise ValueError('Response size limit exceeded')
        serialized = json.dumps(record, sort_keys=True).encode()
        if len(serialized) > MAX_RECEIPT:
            raise ValueError('Receipt size limit exceeded')
        total += len(serialized) + (len(payload) if payload is not None else 0)
        if total > MAX_BYTES:
            raise ValueError('Expanded evidence archive exceeds its size limit')
        validate_receipt(record, payload)
        identifier = record['id']
        if identifier in identifiers:
            raise ValueError('Repeated evidence receipt identity')
        identifiers.append(identifier)
        prepared.append((identifier, serialized, payload))
    if not prepared:
        raise ValueError('Evidence record limit exceeded')
    manifest = json.dumps({'schema':SCHEMA,'receipts':identifiers}).encode()
    if total + len(manifest) > MAX_BYTES or len(manifest) > MAX_RECEIPT:
        raise ValueError('Expanded evidence archive exceeds its size limit')
    stream = BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for identifier, serialized, payload in prepared:
            archive.writestr('evidence/' + identifier + '.json', serialized)
            if payload is not None:
                archive.writestr('evidence/' + identifier + '.native', payload)
        archive.writestr('manifest.json', manifest)
    result = stream.getvalue()
    read_bundle(result)
    return result


def bundle_directory(directory):
    """Package one receipt directory only; never infer sibling device scope."""
    from pathlib import Path
    root = Path(directory)
    if root.is_symlink() or any(p.is_symlink() for p in root.parents):
        raise ValueError('Evidence directory cannot contain symbolic links')
    rows = []
    total = 0
    for path in sorted(root.iterdir()):
        if not re.fullmatch(r'[0-9a-f]{64}\.json', path.name):
            continue
        if path.is_symlink() or len(rows) == MAX_RECORDS:
            raise ValueError('Invalid evidence directory or record limit exceeded')
        with path.open('rb') as stream:
            raw = stream.read(MAX_RECEIPT + 1)
        if len(raw) > MAX_RECEIPT:
            raise ValueError('Receipt size limit exceeded')
        record = _json(raw)
        if not isinstance(record, dict) or record.get('id') != path.stem:
            raise ValueError('Receipt filename differs from its identity')
        payload = None
        if record.get('sha256') is not None:
            native = root / (path.stem + '.native')
            if native.is_symlink():
                raise ValueError('Native response cannot be a symbolic link')
            with native.open('rb') as stream:
                payload = stream.read(MAX_RESPONSE + 1)
            if len(payload) > MAX_RESPONSE:
                raise ValueError('Response size limit exceeded')
        total += len(raw) + (len(payload) if payload is not None else 0)
        if total > MAX_BYTES:
            raise ValueError('Expanded evidence archive exceeds its size limit')
        rows.append((record, payload))
    return build_bundle(rows)


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description='Package one retained evidence-receipt directory for explicit offline import.')
    parser.add_argument('directory')
    parser.add_argument('output', help='New ZIP path; existing files are never overwritten')
    args = parser.parse_args()
    try:
        raw = bundle_directory(args.directory)
        target = Path(args.output)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(0o600)
        print('Evidence bundle created. ZIP packaging does not encrypt its contents.')
    except (ValueError, OSError) as exc:
        parser.exit(1, 'Evidence bundle could not be created; check receipts, paths and available storage.\n')
