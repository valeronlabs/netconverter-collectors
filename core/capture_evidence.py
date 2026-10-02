"""Common evidence receipts for read-only collectors, independent of vendor syntax.

One receipt describes one request and exact native scope. Failed requests retain
their state; successful empty responses do not automatically mean not configured.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from copy import deepcopy

SCHEMA = "nc.capture-evidence.v1"
STATUSES = {"captured", "verified_absent", "missing", "collection_failed",
            "not_interpreted", "conflicting", "stale_or_incompatible"}


def receipt(*, vendor, scope, kind, collector_version, payload=None,
            status="captured", observed_at=None, source_revision=None,
            complete=False, absence_verified=False, failure_code=None):
    if status not in STATUSES:
        raise ValueError("Unknown evidence status")
    if not isinstance(scope, dict) or not scope or not all(isinstance(k, str) for k in scope):
        raise ValueError("Evidence requires explicit native scope")
    if not vendor or not kind or not collector_version:
        raise ValueError("Evidence requires vendor, kind and collector version")
    if status == "verified_absent" and not (complete and absence_verified):
        raise ValueError("Absent evidence requires a complete, explicitly verified query")
    if status in {"captured", "verified_absent"} and not isinstance(payload, bytes):
        raise ValueError("Successful evidence requires the retained response bytes")
    if payload is not None and not isinstance(payload, bytes):
        raise ValueError("Payload must contain bytes")
    if source_revision is not None and (not isinstance(source_revision, str)
            or len(source_revision) != 64 or any(c not in "0123456789abcdef" for c in source_revision)):
        raise ValueError("Source revision must be an exact SHA-256")
    timestamp = observed_at or datetime.now(timezone.utc).isoformat()
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Evidence timestamp requires a timezone")
    digest = sha256(payload).hexdigest() if payload is not None else None
    identity = json.dumps([vendor, scope, kind, timestamp, digest], sort_keys=True)
    return {"schema": SCHEMA, "id": sha256(identity.encode()).hexdigest(),
        "vendor": vendor, "scope": deepcopy(scope), "kind": kind, "status": status,
        "collector_version": collector_version, "observed_at": timestamp,
        "source_revision": source_revision, "sha256": digest,
        "size_bytes": len(payload) if payload is not None else None,
        "complete": bool(complete), "absence_verified": bool(absence_verified),
        # Never include raw exception strings, API URLs, credentials or payloads.
        "failure_code": failure_code}


def validate_receipt(record, payload=None):
    """Verify retained bytes and receipt structure, not the device's truthfulness.

    Imported metadata establishes provenance claims only. A vendor adapter must
    separately confirm native device identity before associating the response.
    """
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        raise ValueError("Unsupported capture evidence schema")
    for name in ("complete", "absence_verified"):
        if not isinstance(record.get(name), bool):
            raise ValueError("Evidence completeness flags must be boolean")
    if not isinstance(record.get("observed_at"), str) or not record["observed_at"]:
        raise ValueError("Imported evidence requires its original observation time")
    expected = receipt(vendor=record.get("vendor"), scope=record.get("scope"),
        kind=record.get("kind"), collector_version=record.get("collector_version"),
        payload=payload, status=record.get("status"), observed_at=record["observed_at"],
        source_revision=record.get("source_revision"), complete=record["complete"],
        absence_verified=record["absence_verified"], failure_code=record.get("failure_code"))
    if record != expected:
        raise ValueError("Evidence receipt identity or content hash does not match")
    return expected


def assess_attachment(record, payload, *, vendor, scope, source_revision,
                      native_identity_verified=False):
    """Account for imported evidence without confusing collection with semantics.

    Exact scope equality is intentional: physical members, manager groups and
    virtual contexts are not interchangeable. Only a vendor's canonical adapter
    may establish native_identity_verified; an imported JSON flag cannot do so.
    """
    verified = validate_receipt(record, payload)
    state = verified['status']
    reason = 'Retained response bytes and receipt integrity verified.'
    if verified['vendor'] != vendor or verified['scope'] != scope:
        state = 'conflicting'
        reason = 'Evidence identifies a different device or configuration scope.'
    elif not source_revision or verified['source_revision'] != source_revision:
        state = 'stale_or_incompatible'
        reason = 'Evidence is not bound to the selected source revision; review capture times separately.'
    elif state in {'captured', 'verified_absent'} and not native_identity_verified:
        state = 'not_interpreted'
        reason = 'Bytes are retained, but canonical native device identity has not been verified.'
    return {'id': verified['id'], 'kind': verified['kind'], 'state': state,
            'receipt_status': verified['status'], 'sha256': verified['sha256'],
            'observed_at': verified['observed_at'], 'source_revision': verified['source_revision'],
            'collector_version': verified['collector_version'], 'reason': reason,
            'resolves_missing_capture': state in {'captured', 'verified_absent'}
                and native_identity_verified,
            'resolves_translation_limitations': False}


def store_receipt(directory, record, payload=None):
    """Content-addressed files preserve previous attempts and avoid scope collisions."""
    root = Path(directory)
    validate_receipt(record, payload)
    if root.is_symlink() or any(p.is_symlink() for p in root.parents):
        raise ValueError("Evidence directory cannot contain symbolic links")
    identifier = record.get("id", "")
    if len(identifier) != 64 or any(c not in "0123456789abcdef" for c in identifier):
        raise ValueError("Invalid receipt identity")
    if payload is not None and (sha256(payload).hexdigest() != record.get("sha256")
                                or len(payload) != record.get("size_bytes")):
        raise ValueError("Evidence bytes differ from their receipt")
    root.mkdir(parents=True, exist_ok=True)
    if payload is not None:
        path = root / (identifier + ".native")
        if path.is_symlink():
            raise ValueError("Evidence content cannot be a symbolic link")
        if not path.exists():
            with path.open("xb") as stream: stream.write(payload)
            path.chmod(0o600)
        elif path.read_bytes() != payload:
            raise ValueError("Existing evidence content differs")
    serialized = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
    target = root / (identifier + ".json")
    if target.is_symlink():
        raise ValueError("Evidence receipt cannot be a symbolic link")
    if target.exists():
        if target.read_bytes() != serialized: raise ValueError("Existing receipt differs")
    else:
        with target.open("xb") as stream: stream.write(serialized)
        target.chmod(0o600)
    return target
