"""Explicit, read-only selected-device evidence through Panorama XML API.

Responses remain separate: local running configuration is never described as a
complete merged policy. Unsupported commands are recorded, not silently skipped.
"""
from __future__ import annotations
from pathlib import Path
import re
import sys
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.capture_evidence import receipt, store_receipt

MAX_RESPONSE = 128 * 1024 * 1024
COMMANDS = {
    "identity": "<show><system><info/></system></show>",
    "local_configuration": "<show><config><running/></config></show>",
    "pushed_policy": "<show><config><pushed-shared-policy/></config></show>",
    "pushed_templates": "<show><config><pushed-template/></config></show>",
    "interfaces": "<show><interface>all</interface></show>",
    "routing": "<show><routing><route/></routing></show>",
    "ha": "<show><high-availability><all/></high-availability></show>",
}
PROFILES = {"configuration": ("identity", "local_configuration", "pushed_policy", "pushed_templates"),
            "operational": ("identity", "interfaces", "routing", "ha")}


def collect(host, api_key, serial, directory, *, profile="configuration", version,
            source_revision, session=None, cancelled=lambda: False, on_progress=lambda row: None,
            retry_records=None):
    import requests
    if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]+)?", host):
        raise ValueError("Use a Panorama hostname or address, without URL credentials or a path")
    if not re.fullmatch(r"[0-9]{9,15}", serial):
        raise ValueError("Select an exact firewall serial")
    if profile not in PROFILES: raise ValueError("Unknown read-only capture profile")
    if not re.fullmatch(r"[0-9a-f]{64}", source_revision):
        raise ValueError("A manager source revision is required")
    steps = list(PROFILES[profile])
    if retry_records is not None:
        if not isinstance(retry_records, list) or not retry_records:
            raise ValueError("Retry requires previous collection receipts")
        previous = {}
        for row in retry_records:
            if not isinstance(row, dict) or row.get('vendor') != 'palo_alto' \
                    or row.get('scope') != {'serial': serial} or row.get('source_revision') != source_revision \
                    or row.get('kind') not in steps or row['kind'] in previous:
                raise ValueError("Retry receipts belong to a different device, revision or capture profile")
            previous[row['kind']] = row
        # Re-prove device identity for every attempt; retain successful files
        # from previous attempts and request only failed or unattempted steps.
        steps = ['identity'] + [kind for kind in steps if kind != 'identity'
            and previous.get(kind, {}).get('status') != 'captured']
    client = session or requests.Session()
    records = []; identity_verified = False
    for kind in steps:
        if cancelled(): break
        if kind != "identity" and not identity_verified: break
        payload = None; status = "collection_failed"; failure = None
        try:
            # API key is a header, never a logged URL. TLS verification cannot
            # be disabled on this supplementary collection path.
            with client.post("https://"+host+"/api/", headers={"X-PAN-KEY":api_key},
                    data={"type":"op", "target":serial, "cmd":COMMANDS[kind]},
                    verify=True, timeout=(10,60), allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    failure = "http_"+str(response.status_code)
                else:
                    chunks=[]; size=0
                    for chunk in response.iter_content(1024*1024):
                        if cancelled(): raise InterruptedError()
                        size+=len(chunk)
                        if size > MAX_RESPONSE: raise ValueError("response_limit")
                        chunks.append(chunk)
                    raw=b"".join(chunks)
                    xml = raw.decode("utf-8-sig")
                    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
                        raise ValueError("unsafe_xml")
                    root=ET.fromstring(xml)
                    if root.tag != "response" or root.get("status") != "success" or root.find("result") is None:
                        failure="api_response_not_success"
                    elif kind == "identity" and root.findtext("./result/system/serial") != serial:
                        failure="device_identity_mismatch";status="conflicting"
                    else:
                        payload=raw;status="captured"
                        if kind == "identity":identity_verified=True
        except InterruptedError:
            failure="cancelled"
        except (requests.RequestException, ValueError, ET.ParseError):
            failure="request_or_response_failed"
        row=receipt(vendor="palo_alto",scope={"serial":serial},kind=kind,
            collector_version=version,payload=payload,status=status,
            source_revision=source_revision,complete=False,failure_code=failure)
        store_receipt(directory,row,payload);records.append(row);on_progress(row)
    if session is None: client.close()
    return {"records":records,"cancelled":bool(cancelled()),
            "requested_steps": steps,
            "complete":len(records)==len(steps) and all(r["status"]=="captured" for r in records),
            "note":"Request success does not establish complete effective device configuration."}
