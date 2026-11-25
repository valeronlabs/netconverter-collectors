"""Interpret retained Panorama rule-usage responses without inventing counters.

The response itself identifies device group and policy family, but not pre/post
rulebase, selected serial, or observation time. Filename conventions prove none
of those. Callers retain the original bytes and associate other receipts separately.
"""
from hashlib import sha256
from defusedxml import ElementTree as ET


def inspect_usage(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > 32 * 1024 * 1024:
        raise ValueError("Usage response exceeds the supported size")
    root = ET.fromstring(raw, forbid_dtd=True)
    if root.tag != "response" or root.get("status") != "success":
        raise ValueError("A successful Panorama API response is required")
    results = root.findall("result/rule-hit-count")
    if len(results) != 1:
        raise ValueError("Expected one captured rule-usage result")
    records = []
    scopes = []
    for group in results[0].findall("device-group/entry"):
        group_name = group.get("name")
        if not group_name:
            raise ValueError("Usage response is missing its device-group identity")
        for family in group.findall("rule-base/entry"):
            family_name = family.get("name")
            if not family_name:
                raise ValueError("Usage response is missing its policy-family identity")
            scope = {"device_group": group_name, "policy_family": family_name}
            scopes.append(scope)
            for position, rule in enumerate(family.findall("rules/entry")):
                name = rule.get("name")
                if not name:
                    raise ValueError("Usage result is missing a rule identity")
                state = (rule.findtext("rule-state") or "").strip().lower()
                records.append({"scope": scope.copy(), "name": name, "position": position,
                    "state": state if state in {"used", "unused", "partial"} else "not_interpreted",
                    "all_connected": {"yes": True, "no": False}.get(rule.findtext("all-connected")),
                    "rule_created_at": rule.findtext("rule-creation-timestamp"),
                    "rule_modified_at": rule.findtext("rule-modification-timestamp")})
    return {"schema": "nc.panorama-rule-usage.v1", "sha256": sha256(raw).hexdigest(),
            "scopes": scopes, "records": records, "observation_time": None,
            "serial": None, "rulebase_position": None, "packet_counters": False,
            "cleanup_authorization": False, "complete_capture": False,
            "limitations": ["Used/Unused/Partial are usage states, not packet counters.",
                "Device-group observations are not selected-firewall observations.",
                "Pre/post rulebase and collection time need separate request evidence.",
                "Rule creation/modification timestamps are not the collection time."]}
