#!/usr/bin/env python3
"""
NetConverter.AI — FMC Import Script  (version 2.3.0)

Imports a NetConverter FMC JSON file into a Cisco Secure Firewall Management Center
via the FMC REST API. Run this on any machine that can reach your FMC.

Requirements: Python 3.8+, requests (pip install requests)

Usage:
    python3 fmc_import.py --host 10.1.1.100 --user admin --json converted_output.json --dry-run
    python3 fmc_import.py --host 10.1.1.100 --user admin --json converted_output.json
    python3 fmc_import.py --host fmc.company.com --user netadmin --json output.json --reuse-policy

Behaviour you can rely on:
  * Nothing is ever broadened silently. A rule, NAT rule or group whose references
    cannot all be resolved to FMC object IDs is NOT created; it is reported as a
    failure with the reason.
  * Every failure is printed with its HTTP status and FMC's error text, and the
    script exits non-zero if anything failed.
  * Every access policy and NAT policy in the file is created fresh. If a policy
    with the same name already exists, a uniquely named one is created instead;
    pass --reuse-policy to write into the existing policy on purpose (decided per
    policy).
  * A file with several access / NAT policies (one per device group) puts each
    rule into the policy its "_policy_name" names; a rule without one goes into
    the first policy. A rule naming a policy the file does not define is not
    created. With a single policy every rule goes into it, as before.
  * Objects that already exist with the same name are reused only when their
    content matches field for field (a field FMC does not return for its object,
    e.g. an ICMP object with no type, counts as a difference). A same-named object
    with a different definition is never reused: the file's object is created
    under a new name (<name>_nc<hash>), everything in the file that references it
    uses the new name, and the rename is reported.
  * Re-running with --reuse-policy adds only what is missing: access rules and
    NAT rules already in the policy with the same definition are skipped, a
    same-named access rule with a different definition is reported, and new
    access rules are inserted at their position in the file (not after the
    policy's last rule).
  * --dry-run makes no changes but still reads FMC to report conflicts and
    references that would not resolve.

Changelog
---------
2.3.0 (2026-10-04)  Single-policy naming overrides, requested/actual policy identities,
                    per-policy counts and optional JSON import receipts. No assignment/deployment.
2.2.1 (2026-10-04)  A session FMC invalidated mid-import (another login with the same
                    account; FMC keeps one REST session per user) is re-established
                    with the credentials already given, up to 3 times. Before, the
                    refresh was refused and every later rule failed with HTTP 401.
2.2.0 (2026-10-03)  Closes two gaps against the FMC JSON the converter emits:
                    - objects.networkfeeds (type NetworkFeed) are created, looked
                      up and reused like every other object type (strict content
                      compare, <name>_nc<hash> on conflict); rules referencing a
                      feed resolve. Before, every feed and every rule using one
                      failed. The REST collection is object/sinetworkfeeds (type
                      SINetworkFeed, per the FMC 7.6.5 OpenAPI spec); an
                      FMC that answers 404 there gets the feed reported with a
                      pointer to create it in the FMC UI.
                    - Several access / NAT policies (one per device group) are all
                      created (or reused with --reuse-policy, per policy) and each
                      rule goes into the policy named by its _policy_name; before,
                      every rule went into the first policy. File order and
                      insertBefore are kept per policy; counts are reported per
                      policy. A single-policy file imports exactly as in 2.1.0.
                    - A rule whose file policy, intrusion policy or variable set
                      does not exist on FMC now says so (create it first) instead
                      of "it would match more than intended".
2.1.0 (2026-09-26)  Fixes from a re-validation against FMC 7.6.5:
                    - Object comparison is strict: a field in the file that FMC
                      does not return (icmpType, port, value, ...) is a difference.
                      A pre-existing typeless ICMP object named like the file's
                      echo object was reused and widened the rule to every ICMP type.
                    - A conflicting same-named object is never reused; the file's
                      object is created as <name>_nc<hash> and referenced by that
                      name (reported as RENAMED).
                    - --reuse-policy re-runs: manual and Auto NAT rules already in
                      the policy are not duplicated; "Duplicate Auto NAT rule" is
                      no longer reported as a name collision; access rules are
                      inserted at their file position (insertBefore), not after
                      the policy's deny rules; identical existing rules are skipped.
2.0.0 (2026-09-25)  Fixes from a run against FMC 7.6.5:
                    - Range / FQDN (and every other emitted object type) resolve in
                      access rules, NAT rules and groups, by the reference's real
                      type; an unresolvable reference fails the rule loudly
                      instead of creating it as ANY.
                    - Manual NAT port fields and the PAT pool resolve to IDs
                      (a top-level "patPool" is sent as patOptions.patPoolAddress);
                      Auto NAT ports are sent as integers.
                    - Manual NAT rules are posted into their section with
                      ?section=before_auto / after_auto (lowercase).
                    - Access rules keep logBegin / logEnd / sendEventsToFMC /
                      description and every other field in the file.
                    - Each failure prints HTTP status + FMC error text; exit code 1
                      when anything failed.
                    - Policy lookup pages through all results; existing policies
                      are not written into without --reuse-policy.
                    - Object lookups list each object type once (paged) instead of
                      the nameOrValue filter, which FMC rejects on securityzones.
                    - Re-runs compare the content of same-named objects and report
                      rule-name collisions.
                    - HTTP 429 back-off and one token refresh on 401.
1.x                 Original importer.
"""

import argparse
import hashlib
import copy
from pathlib import Path
import ipaddress
import json
import sys
import time
import os
import tempfile
from datetime import datetime, timezone
from getpass import getpass
from typing import Any, Callable, Dict, List, Optional, Tuple

__version__ = "2.3.0"

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:  # checked in main(); lets the module import for --help and tests
    requests = None

_sleep = time.sleep

PAGE_LIMIT = 1000          # FMC's maximum page size
MAX_ATTEMPTS = 5           # per request, for HTTP 429 back-off
MAX_RELOGINS = 3           # fresh logins after FMC invalidated the session (another login, 3 refreshes used)
DRY_RUN_ID = "(dry-run)"

# Reference type -> FMC collection(s) to look it up in. A generic "Network"
# reference may name any network-family object; its real type is taken from FMC.
_NETWORK_FAMILY = ["object/networks", "object/hosts", "object/ranges", "object/fqdns",
                   "object/networkgroups"]
# Collection for the converter's "networkfeeds" objects. FMC 7.6.5's own OpenAPI
# spec (API Explorer fmc.json, read 2026-10-03) has no object/networkfeeds: the
# collection is object/sinetworkfeeds and the type SINetworkFeed (Security
# Intelligence network feed). An FMC that answers 404 here gets the feed reported
# with how to create it in the FMC UI.
NETWORK_FEED_PATH = "object/sinetworkfeeds"
NETWORK_FEED_TYPE = "SINetworkFeed"
LOOKUP_PATHS: Dict[str, List[str]] = {
    "Host": ["object/hosts"],
    "Network": _NETWORK_FAMILY,
    "Range": ["object/ranges"],
    "FQDN": ["object/fqdns"],
    "NetworkFeed": [NETWORK_FEED_PATH],
    NETWORK_FEED_TYPE: [NETWORK_FEED_PATH],
    "NetworkGroup": ["object/networkgroups"],
    "ProtocolPortObject": ["object/protocolportobjects"],
    "PortObjectGroup": ["object/portobjectgroups"],
    "ICMPV4Object": ["object/icmpv4objects"],
    "ICMPV6Object": ["object/icmpv6objects"],
    "SecurityZone": ["object/securityzones", "object/interfacegroups"],
    "InterfaceGroup": ["object/interfacegroups"],
    "Url": ["object/urls"],
    "UrlGroup": ["object/urlgroups"],
    "URLCategory": ["object/urlcategories"],
    "Application": ["object/applications"],
    "VariableSet": ["object/variablesets"],
    "IntrusionPolicy": ["policy/intrusionpolicies"],
    "FilePolicy": ["policy/filepolicies"],
    "IKEv1Policy": ["object/ikev1policies"],
    "IKEv2Policy": ["object/ikev2policies"],
    "IKEv1IPsecProposal": ["object/ikev1ipsecproposals"],
    "IKEv2IPsecProposal": ["object/ikev2ipsecproposals"],
}
PATH_TYPE = {paths[0]: t for t, paths in LOOKUP_PATHS.items() if len(paths) == 1}
PATH_TYPE.update({"object/networks": "Network", "object/securityzones": "SecurityZone"})

# Names are unique across these collections on FMC (case-insensitive).
FAMILIES = {
    "network": set(_NETWORK_FAMILY),
    "port": {"object/protocolportobjects", "object/portobjectgroups",
             "object/icmpv4objects", "object/icmpv6objects"},
    "zone": {"object/securityzones", "object/interfacegroups"},
}

# File key -> FMC collection, in dependency order (members before groups).
OBJECT_PUSH_ORDER = [
    ("hosts", "object/hosts"),
    ("networks", "object/networks"),
    ("ranges", "object/ranges"),
    ("fqdns", "object/fqdns"),
    ("networkfeeds", NETWORK_FEED_PATH),
    ("protocolportobjects", "object/protocolportobjects"),
    ("icmpv4objects", "object/icmpv4objects"),
    ("icmpv6objects", "object/icmpv6objects"),
    ("urls", "object/urls"),
    ("securityzones", "object/securityzones"),
    ("networkgroups", "object/networkgroups"),
    ("portobjectgroups", "object/portobjectgroups"),
    ("urlgroups", "object/urlgroups"),
    ("ikev1policies", "object/ikev1policies"),
    ("ikev2policies", "object/ikev2policies"),
    ("ikev1ipsecproposals", "object/ikev1ipsecproposals"),
    ("ikev2ipsecproposals", "object/ikev2ipsecproposals"),
]
GROUP_KEYS = {"networkgroups", "portobjectgroups", "urlgroups"}

# FMC name-length limits (lab FMC 7.6.5, 2026-09-26: 65-char object names and
# 49-char security-zone names are rejected with HTTP 400).
MAX_NAME = {"zone": 48}
MAX_OBJECT_NAME = 64
# Fields whose absence on one side changes what the object matches: an ICMP
# object with no icmpType matches every type, a port object with no port every port.
_SEMANTIC_KEYS = ("value", "port", "protocol", "icmpType", "code", "dnsResolution", "url")

# Keys FMC does not accept in a POST body (read-only / NetConverter-internal).
_READ_ONLY_KEYS = {"id", "links", "metadata"}
# Fields compared when an object with the same name already exists.
_NOT_COMPARED = {"name", "type", "id", "links", "metadata", "description", "overridable",
                 "objects", "literals"}

# Access-rule fields that attach an FMC policy rather than narrow the match. An
# unresolved one does not widen the rule: the policy is missing on FMC.
_PREREQUISITE_FIELDS = {"filePolicy": "file policy", "ipsPolicy": "intrusion policy",
                        "variableSet": "variable set"}


def family_of(path: str) -> str:
    for fam, paths in FAMILIES.items():
        if path in paths:
            return fam
    return path


def fmc_error_text(resp: Any) -> str:
    """FMC's error description(s), or the raw body."""
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        err = body.get("error") or {}
        msgs = [m.get("description") for m in (err.get("messages") or [])
                if isinstance(m, dict) and m.get("description")]
        if msgs:
            return "; ".join(msgs)
    text = (getattr(resp, "text", "") or "").strip()
    return text[:500] or "(empty response body)"


class FMCError(Exception):
    def __init__(self, status: Optional[int], message: str):
        super().__init__(f"HTTP {status}: {message}" if status else message)
        self.status = status
        self.message = message


# --------------------------------------------------------------------------- HTTP

def _normalize_feed_types(objects: Dict, policies: Dict) -> None:
    """The converter names a feed 'NetworkFeed'; FMC's type is SINetworkFeed.
    Rename it once, in the objects and in every reference, so lookup, strict
    content comparison and the posted rule all use FMC's type."""
    for obj in objects.get("networkfeeds") or []:
        if isinstance(obj, dict) and obj.get("type") == "NetworkFeed":
            obj["type"] = NETWORK_FEED_TYPE

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("type") == "NetworkFeed":
                value["type"] = NETWORK_FEED_TYPE
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
    walk(policies)


class FMCClient:
    """Minimal FMC REST client: auth headers, 429 back-off, token refresh, paging."""

    def __init__(self, host: str, token: str, domain: str, verify_ssl: bool = False,
                 http: Any = None, refresh_token: Optional[str] = None, timeout: int = 120,
                 reauth: Optional[Callable[[], Tuple[str, Optional[str], str]]] = None):
        self.host = host
        self.token = token
        self.domain = domain
        self.verify_ssl = verify_ssl
        self.http = http if http is not None else requests
        self.refresh_token = refresh_token
        self.timeout = timeout
        self._refreshes = 0
        # FMC keeps one REST session per user: a second login with the same account
        # (FMC UI, another script) kills this token and its refresh token alike.
        self._reauth = reauth
        self._relogins = 0

    def _url(self, path: str) -> str:
        if path.startswith("/api/"):
            return f"https://{self.host}{path}"
        return f"https://{self.host}/api/fmc_config/v1/domain/{self.domain}/{path}"

    def _refresh(self) -> bool:
        if not self.refresh_token or self._refreshes >= 3:
            return False
        resp = self.http.request(
            "POST", self._url("/api/fmc_platform/v1/auth/refreshtoken"),
            headers={"X-auth-access-token": self.token, "X-auth-refresh-token": self.refresh_token},
            verify=self.verify_ssl, timeout=self.timeout)
        if resp.status_code not in (200, 201, 204):
            return False
        self.token = resp.headers.get("X-auth-access-token") or self.token
        self.refresh_token = resp.headers.get("X-auth-refresh-token") or self.refresh_token
        self._refreshes += 1
        print("  (FMC token refreshed)")
        return True

    def _relogin(self) -> bool:
        if not self._reauth or self._relogins >= MAX_RELOGINS:
            return False
        try:
            self.token, self.refresh_token, self.domain = self._reauth()
        except FMCError:
            return False
        self._relogins += 1
        self._refreshes = 0
        print("  (FMC session was invalidated, e.g. by another login with this account; logged in again)")
        return True

    def request(self, method: str, path: str, params: Optional[Dict] = None,
                payload: Optional[Dict] = None) -> Any:
        resp = None
        for attempt in range(MAX_ATTEMPTS):
            headers = {"X-auth-access-token": self.token, "Content-Type": "application/json"}
            resp = self.http.request(method, self._url(path), headers=headers, params=params,
                                     json=payload, verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code == 429:
                try:
                    wait = float(resp.headers.get("Retry-After", ""))
                except ValueError:
                    wait = min(2.0 * (2 ** attempt), 30.0)
                _sleep(wait)
                continue
            if resp.status_code == 401 and (self._refresh() or self._relogin()):
                continue
            return resp
        return resp

    def list_all(self, path: str, expanded: bool = True) -> List[Dict]:
        """Every item of a collection, following FMC paging."""
        items: List[Dict] = []
        offset = 0
        while True:
            params = {"limit": PAGE_LIMIT, "offset": offset}
            if expanded:
                params["expanded"] = "true"
            resp = self.request("GET", path, params=params)
            if resp.status_code == 404 and offset == 0:
                return items
            if resp.status_code != 200:
                raise FMCError(resp.status_code, fmc_error_text(resp))
            body = resp.json() or {}
            page = body.get("items") or []
            items.extend(page)
            paging = body.get("paging") or {}
            offset += len(page)
            if not page:
                break
            count = paging.get("count")
            if count is not None:
                if offset >= int(count):
                    break
            elif not paging.get("next"):
                break
        return items


def _login(http: Any, host: str, username: str, password: str,
           verify_ssl: bool) -> Tuple[str, Optional[str], str]:
    """One generatetoken call: (access token, refresh token, domain uuid)."""
    import base64
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    resp = http.request("POST", f"https://{host}/api/fmc_platform/v1/auth/generatetoken",
                        headers={"Authorization": f"Basic {creds}"}, verify=verify_ssl, timeout=60)
    if resp.status_code not in (200, 201, 204):
        raise FMCError(resp.status_code, f"authentication failed: {fmc_error_text(resp)}")
    token = resp.headers.get("X-auth-access-token")
    domain = resp.headers.get("DOMAIN_UUID")
    if not token or not domain:
        raise FMCError(resp.status_code, "authentication response carried no token / DOMAIN_UUID")
    return token, resp.headers.get("X-auth-refresh-token"), domain


def connect(host: str, username: str, password: str, verify_ssl: bool = False,
            http: Any = None) -> Tuple[FMCClient, Optional[str]]:
    """Authenticate; return a client and the FMC server version."""
    http = http if http is not None else requests
    token, refresh_token, domain = _login(http, host, username, password, verify_ssl)
    client = FMCClient(host, token, domain, verify_ssl, http=http, refresh_token=refresh_token,
                       reauth=lambda: _login(http, host, username, password, verify_ssl))
    version = None
    try:
        vr = client.request("GET", "/api/fmc_platform/v1/info/serverversion")
        if vr.status_code == 200:
            items = (vr.json() or {}).get("items") or [{}]
            version = items[0].get("serverVersion")
    except (ValueError, OSError):
        pass
    return client, version


# --------------------------------------------------------------------------- report

class Report:
    """Collects outcomes; every failure is printed the moment it happens."""

    def __init__(self):
        self.failures: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.renames: List[Dict[str, str]] = []
        self.counts: Dict[str, Dict[str, int]] = {}
        # The policy rules are going into, set only when the file has several
        # policies: counts are then also kept per policy and failures name it.
        self.scope: Optional[str] = None
        self.policies: List[Dict[str, Any]] = []
        self.skipped: List[Dict[str, Any]] = []

    def record_skip(self, phase: str, name: str, reason: str) -> None:
        entry = {"phase": phase, "name": name, "reason": reason}
        if self.scope:
            entry["policy"] = self.scope
        self.skipped.append(entry)

    @staticmethod
    def label(phase: str, policy: Optional[str]) -> str:
        return f"{phase} -> '{policy}'" if policy else phase

    def count(self, phase: str, key: str) -> None:
        for bucket_name in ([phase, self.label(phase, self.scope)] if self.scope else [phase]):
            bucket = self.counts.setdefault(bucket_name, {})
            bucket[key] = bucket.get(key, 0) + 1

    def fail(self, phase: str, name: str, reason: str, status: Optional[int] = None) -> None:
        entry: Dict[str, Any] = {"phase": phase, "name": name, "reason": reason, "status": status}
        if self.scope:
            entry["policy"] = self.scope
        self.failures.append(entry)
        self.count(phase, "failed")
        http = f"HTTP {status} " if status else ""
        print(f"    FAIL [{self.label(phase, self.scope)}] {name}: {http}{reason}")

    def rename(self, name: str, new_name: str, reason: str) -> None:
        self.renames.append({"name": name, "new_name": new_name, "reason": reason})
        print(f"    RENAMED {name} -> {new_name}: {reason}")

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        print(f"    WARN {message}")

    def exit_code(self) -> int:
        return 1 if self.failures else 0

    def print_summary(self) -> None:
        print(f"\n{'=' * 60}")
        for phase, bucket in self.counts.items():
            parts = ", ".join(f"{k}={v}" for k, v in sorted(bucket.items()))
            print(f"  {phase:<14} {parts}")
        if self.renames:
            print(f"\n  {len(self.renames)} object(s) are on FMC under a new name because FMC "
                  "already has a different object with the file's name (everything in the "
                  "file that references them uses the new name):")
            for r in self.renames:
                print(f"    - {r['name']} -> {r['new_name']} ({r['reason']})")
        if self.warnings:
            print(f"\n  {len(self.warnings)} warning(s) — see WARN lines above.")
        if self.failures:
            print(f"\n  {len(self.failures)} FAILURE(S):")
            for f in self.failures:
                http = f"HTTP {f['status']} " if f["status"] else ""
                print(f"    - [{self.label(f['phase'], f.get('policy'))}] {f['name']}: "
                      f"{http}{f['reason']}")
            print("\n  Import INCOMPLETE. Nothing listed above was created. After fixing the cause,")
            print("  re-run with --reuse-policy to add what is missing to the policies this run")
            print("  created: identical objects, access rules and NAT rules are skipped, new")
            print("  access rules are inserted at their file position. Without --reuse-policy a")
            print("  re-run creates new, separately named policies.")
        else:
            print("\n  Import complete with no failures.")
        print(f"{'=' * 60}")


# --------------------------------------------------------------------------- helpers

def _norm_scalar(value: Any) -> str:
    return str(value).strip().lower()


def _norm_address(path: str, value: Any) -> str:
    s = str(value).strip()
    try:
        if path == "object/hosts":
            return str(ipaddress.ip_address(s))
        if path == "object/networks":
            return str(ipaddress.ip_network(s, strict=False))
        if path == "object/ranges" and "-" in s:
            a, b = s.split("-", 1)
            return f"{ipaddress.ip_address(a.strip())}-{ipaddress.ip_address(b.strip())}"
    except ValueError:
        pass
    return s.lower().rstrip(".")


def _content_difference(path: str, ours: Dict, theirs: Dict) -> Optional[str]:
    """None only when an existing FMC object matches the file's definition exactly.

    Strict: a field the file defines that FMC does not return for its object is
    a difference (FMC omits icmpType on an any-type ICMP object and port on a
    protocol-only port object -- treating the omission as "identical" reused a
    typeless icmp_echo and widened the rule to every ICMP type). A semantic field
    FMC has that the file does not is a difference too.
    """
    if theirs.get("type") and ours.get("type") and \
            _norm_scalar(theirs["type"]) != _norm_scalar(ours["type"]):
        return f"it is a {theirs['type']} on FMC, the file defines a {ours['type']}"
    for key in _SEMANTIC_KEYS:
        if key in ours and key not in theirs:
            return f"{key} is {ours[key]!r} in the file but FMC's object has no {key}"
        if key in theirs and key not in ours and theirs[key] not in (None, ""):
            return f"FMC's object has {key} {theirs[key]!r}, the file's object has none"
    if "value" in ours and \
            _norm_address(path, ours["value"]) != _norm_address(path, theirs["value"]):
        return f"value on FMC is {theirs['value']}, the file has {ours['value']}"
    if "objects" in ours or "literals" in ours or "objects" in theirs or "literals" in theirs:
        ours_m = sorted(_norm_scalar(o.get("name", o.get("id"))) for o in ours.get("objects") or [])
        theirs_m = sorted(_norm_scalar(o.get("name", o.get("id"))) for o in theirs.get("objects") or [])
        ours_l = sorted(_norm_scalar(l.get("value", l.get("port", l))) for l in ours.get("literals") or [])
        theirs_l = sorted(_norm_scalar(l.get("value", l.get("port", l)))
                          for l in theirs.get("literals") or [])
        if ours_m != theirs_m or ours_l != theirs_l:
            return (f"members on FMC are {theirs_m + theirs_l}, "
                    f"the file has {ours_m + ours_l}")
    for key, val in ours.items():
        if key.startswith("_") or key in _NOT_COMPARED or key == "value":
            continue
        if key not in theirs:
            return f"{key} is {val!r} in the file but FMC's object has no {key}"
        mine, fmc = val, theirs[key]
        if isinstance(mine, dict) or isinstance(fmc, dict):
            if _canon(mine) != _canon(fmc):
                return f"{key} on FMC is {fmc}, the file has {mine}"
            continue
        if isinstance(mine, list) and isinstance(fmc, list):
            if all(not isinstance(x, (dict, list)) for x in mine + fmc):
                if sorted(map(_norm_scalar, mine)) != sorted(map(_norm_scalar, fmc)):
                    return f"{key} on FMC is {fmc}, the file has {mine}"
            elif _canon(mine) != _canon(fmc):
                return f"{key} on FMC is {fmc}, the file has {mine}"
            continue
        if _norm_scalar(mine) != _norm_scalar(fmc):
            return f"{key} on FMC is {fmc}, the file has {mine}"
    return None


def _canon(value: Any) -> Any:
    """Order- and case-insensitive canonical form (ids/links/metadata dropped)."""
    if isinstance(value, dict):
        return tuple(sorted((k, _canon(v)) for k, v in value.items()
                            if k not in _READ_ONLY_KEYS and not k.startswith("_")))
    if isinstance(value, list):
        return tuple(sorted((_canon(v) for v in value), key=repr))
    if isinstance(value, str):
        return value.strip().lower()
    return value


def _content_hash(obj: Dict) -> str:
    body = {k: v for k, v in obj.items()
            if k not in ("name", "description", "id", "links", "metadata") and not k.startswith("_")}
    return hashlib.sha1(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:6]


def _suffixed_name(name: str, tag: str, limit: int) -> str:
    suffix = f"_nc{tag}"
    return name[:max(1, limit - len(suffix))] + suffix


def _ref_names(container: Any) -> List[str]:
    """Sorted lower-case names/values referenced by a rule field."""
    out: List[str] = []
    if isinstance(container, dict):
        if "objects" in container or "literals" in container:
            for o in container.get("objects") or []:
                out.append(_norm_scalar(o.get("name") or o.get("id")))
            for lit in container.get("literals") or []:
                out.append(_norm_scalar(lit.get("value", lit.get("port", lit))
                                        if isinstance(lit, dict) else lit))
            return sorted(out)
        if container.get("name") or container.get("id"):
            return [_norm_scalar(container.get("name") or container.get("id"))]
    return sorted(out)


_ACCESS_RULE_SIG_FIELDS = ("sourceZones", "destinationZones", "sourceNetworks", "destinationNetworks",
                           "sourcePorts", "destinationPorts", "applications", "urls",
                           "sourceSecurityGroupTags", "vlanTags", "users")
_NAT_SIG_REFS = ("originalSource", "translatedSource", "originalDestination", "translatedDestination",
                 "originalNetwork", "translatedNetwork", "originalSourcePort", "translatedSourcePort",
                 "originalDestinationPort", "translatedDestinationPort", "sourceInterface",
                 "destinationInterface")
_NAT_SIG_FLAGS = ("natType", "interfaceInTranslatedSource", "interfaceInOriginalDestination",
                  "interfaceInTranslatedNetwork", "unidirectional", "originalPort", "translatedPort",
                  "serviceProtocol", "dns", "noProxyArp", "routeLookup", "netToNet")


def _access_rule_signature(rule: Dict) -> Tuple:
    return (_norm_scalar(rule.get("action", "ALLOW")),
            tuple((f, tuple(_ref_names(rule.get(f)))) for f in _ACCESS_RULE_SIG_FIELDS))


def _nat_signature(rule: Dict) -> Tuple:
    pat = (rule.get("patOptions") or {}).get("patPoolAddress")
    return (tuple((f, tuple(_ref_names(rule.get(f)))) for f in _NAT_SIG_REFS)
            + (("patPool", tuple(_ref_names(pat))),)
            + tuple((f, _norm_scalar(rule.get(f)) if rule.get(f) not in (None, False) else "")
                    for f in _NAT_SIG_FLAGS))


def _is_named_ref(value: Dict) -> bool:
    """A by-name object reference that still needs an FMC id."""
    return (isinstance(value.get("name"), str) and "type" in value and not value.get("id")
            and not any(k in value for k in ("value", "url", "port", "objects", "literals")))


def _strip_internal(obj: Dict, extra: Tuple[str, ...] = ()) -> Dict:
    return {k: v for k, v in obj.items()
            if not k.startswith("_") and k not in _READ_ONLY_KEYS and k not in extra}


def _port_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _access_rule_error_text(errors: List[str]) -> str:
    """Why an access rule was not created. A missing file / intrusion policy or
    variable set is a prerequisite to create on FMC, not a broadened match."""
    prereq = [e for e in errors if e.split(":", 1)[0].split(".", 1)[0] in _PREREQUISITE_FIELDS]
    match = [e for e in errors if e not in prereq]
    parts = []
    if match:
        parts.append("not created (it would match more than intended): " + "; ".join(match))
    if prereq:
        kinds = []
        for e in prereq:
            kind = _PREREQUISITE_FIELDS[e.split(":", 1)[0].split(".", 1)[0]]
            if kind not in kinds:
                kinds.append(kind)
        parts.append(f"not created: the referenced {' and '.join(kinds)} does not exist on FMC; "
                     "create it in FMC first, then re-run with --reuse-policy: " + "; ".join(prereq))
    return " | ".join(parts)


# --------------------------------------------------------------------------- importer

class Importer:
    def __init__(self, client: FMCClient, data: Dict, dry_run: bool = False,
                 reuse_policy: bool = False, stamp: Optional[str] = None):
        self.client = client
        data = copy.deepcopy(data)
        self.objects = data.get("objects") or {}
        self.policies = data.get("policies") or {}
        _normalize_feed_types(self.objects, self.policies)
        self.dry_run = dry_run
        self.reuse_policy = reuse_policy
        self.stamp = stamp or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.report = Report()
        self._index: Dict[str, Dict[str, Dict]] = {}
        # (family, lower name) -> why references to that name must not resolve
        self.blocked: Dict[Tuple[str, str], str] = {}
        # (family, lower file name) -> name the object was created under on FMC
        self.renamed: Dict[Tuple[str, str], str] = {}

    # --- object index (one paged listing per collection) -------------------
    def _collection(self, path: str) -> Dict[str, Dict]:
        if path not in self._index:
            items = self.client.list_all(path)
            self._index[path] = {str(i.get("name", "")).lower(): i for i in items if i.get("name")}
        return self._index[path]

    def _find(self, path: str, name: str) -> Optional[Dict]:
        return self._collection(path).get(name.lower())

    def _remember(self, path: str, item: Dict) -> None:
        self._collection(path)[str(item.get("name", "")).lower()] = item

    def resolve(self, ref: Dict) -> Tuple[Optional[Dict], Optional[str]]:
        if ref.get("id"):
            return ref, None
        name, rtype = ref.get("name"), ref.get("type")
        paths = LOOKUP_PATHS.get(rtype)
        if not paths:
            return None, f"reference '{name}' has type {rtype!r}, which this importer cannot resolve"
        blocked = self.blocked.get((family_of(paths[0]), str(name).lower()))
        if blocked:
            return None, f"{rtype} '{name}' {blocked}"
        name = self.renamed.get((family_of(paths[0]), str(name).lower()), name)
        for path in paths:
            try:
                item = self._find(path, name)
            except FMCError as exc:
                return None, f"cannot list {path} to resolve {rtype} '{name}': {exc}"
            if item is not None:
                return {"type": item.get("type") or PATH_TYPE.get(path, rtype),
                        "id": item["id"], "name": item.get("name", name)}, None
        return None, f"{rtype} '{name}' not found on FMC (not created by this file, not pre-existing)"

    def _resolve_tree(self, value: Any, where: str, errors: List[str]) -> Any:
        if isinstance(value, list):
            return [self._resolve_tree(v, where, errors) for v in value]
        if isinstance(value, dict):
            if _is_named_ref(value):
                resolved, err = self.resolve(value)
                if err:
                    errors.append(f"{where}: {err}")
                    return value
                return resolved
            return {k: self._resolve_tree(v, f"{where}.{k}" if where else k, errors)
                    for k, v in value.items()}
        return value

    def _resolve_fields(self, payload: Dict, errors: List[str]) -> Dict:
        """Resolve references inside each field (never the payload itself)."""
        return {k: self._resolve_tree(v, k, errors) for k, v in payload.items()}

    def _post(self, phase: str, name: str, path: str, payload: Dict,
              params: Optional[Dict] = None) -> Optional[Dict]:
        if path == NETWORK_FEED_PATH and payload.get("type") != NETWORK_FEED_TYPE:
            payload = {**payload, "type": NETWORK_FEED_TYPE}
        resp = self.client.request("POST", path, params=params, payload=payload)
        if resp.status_code in (200, 201):
            try:
                return resp.json() or {}
            except ValueError:
                return {}
        text = fmc_error_text(resp)
        low = text.lower()
        if resp.status_code == 400 and "duplicate auto nat" in low:
            text = (f"an Auto NAT rule for this original object already exists in the NAT "
                    f"policy (FMC allows one per object) — {text}")
        elif resp.status_code == 400 and "already exists" in low:
            text = f"name collision — {text}"
        elif resp.status_code == 404 and path == NETWORK_FEED_PATH:
            text = (f"this FMC has no REST collection {path}; create the feed manually in the "
                    "FMC UI (Objects > Object Management > Security Intelligence > Network "
                    "Lists and Feeds); rules that reference it are not created by this tool "
                    f"— {text}")
        self.report.fail(phase, name, text, resp.status_code)
        return None

    # --- run ---------------------------------------------------------------
    def run(self) -> Report:
        steps = [("objects", self.push_objects)]
        if self.policies.get("accessrules"):
            steps.append(("access rules", self.push_access_rules))
        if self.policies.get("natrules"):
            steps.append(("NAT rules", self.push_nat_rules))
        if self.policies.get("ftds2svpns"):
            steps.append(("S2S VPNs", self.push_s2s_vpns))
        for label, step in steps:
            print(f"\n{'[DRY RUN] ' if self.dry_run else ''}{label}...")
            try:
                step()
            except FMCError as exc:
                self.report.fail(label, "(phase aborted)", exc.message, exc.status)
        return self.report

    # --- objects -----------------------------------------------------------
    def push_objects(self) -> None:
        known = {k for k, _ in OBJECT_PUSH_ORDER}
        for key, items in self.objects.items():
            if key not in known and isinstance(items, list) and items:
                for obj in items:
                    self.report.fail("objects", obj.get("name", "?"),
                                     f"object type '{key}' is not imported by this tool; "
                                     "create it in FMC manually")
        for key, path in OBJECT_PUSH_ORDER:
            items = [o for o in (self.objects.get(key) or []) if isinstance(o, dict)]
            if not items:
                continue
            if key in GROUP_KEYS:
                items = self._dependency_order(items)
            print(f"  {key}: {len(items)}")
            for obj in items:
                self._push_object(key, path, obj)

    def _dependency_order(self, groups: List[Dict]) -> List[Dict]:
        by_name = {str(g.get("name", "")).lower(): g for g in groups}
        ordered: List[Dict] = []
        state: Dict[str, int] = {}

        def visit(name: str) -> None:
            if state.get(name) == 2:
                return
            if state.get(name) == 1:  # cycle: leave it to the member check to report
                return
            state[name] = 1
            for m in by_name[name].get("objects") or []:
                child = str(m.get("name", "")).lower()
                if child in by_name:
                    visit(child)
            state[name] = 2
            ordered.append(by_name[name])

        for n in by_name:
            visit(n)
        return ordered

    def _push_object(self, key: str, path: str, obj: Dict) -> None:
        name = str(obj.get("name", "?"))
        family = family_of(path)
        payload = _strip_internal(obj)
        # Members renamed earlier in this run are referenced by their new name.
        if key in GROUP_KEYS and isinstance(payload.get("objects"), list):
            payload["objects"] = [
                {**m, "name": self.renamed.get((family, str(m.get("name", "")).lower()), m.get("name"))}
                if isinstance(m, dict) and m.get("name") else m
                for m in payload["objects"]]

        existing_diff = self._existing_difference(path, family, name, obj, payload)
        if existing_diff is None:
            print(f"    REUSE {name} (identical definition already on FMC)")
            self.report.count("objects", "reused")
            self.report.record_skip("objects", name, "identical definition already exists on FMC")
            return
        if existing_diff == "the file defines this name twice":
            self.blocked[(family, name.lower())] = "is defined twice in the file; not created"
            self.report.fail("objects", name, "the file defines this name twice")
            return
        target_name = name
        if existing_diff:
            # Never reuse a different object: create the file's object under a
            # unique name and point every reference in the file at it.
            limit = MAX_NAME.get(family, MAX_OBJECT_NAME)
            tag = _content_hash(payload)
            target_name = _suffixed_name(name, tag, limit)
            n = 2
            while True:
                again = self._existing_difference(path, family, target_name, obj,
                                                  {**payload, "name": target_name})
                if again is None:
                    self.renamed[(family, name.lower())] = target_name
                    self.report.rename(name, target_name, f"FMC already has '{name}': {existing_diff}; "
                                       f"reusing the identical '{target_name}'")
                    self.report.count("objects", "reused")
                    self.report.record_skip("objects", target_name, "identical renamed definition already exists on FMC")
                    return
                if again is False:
                    break
                target_name = _suffixed_name(name, f"{tag}{n}", limit)
                n += 1
            self.renamed[(family, name.lower())] = target_name
            self.report.rename(name, target_name, f"FMC already has '{name}': {existing_diff}")
            payload["name"] = target_name

        if key in GROUP_KEYS:
            errors: List[str] = []
            if "objects" in payload:
                payload["objects"] = self._resolve_tree(payload["objects"], "member", errors)
            if errors:
                self.blocked[(family, name.lower())] = "was not created (unresolved members)"
                self.report.fail("objects", name, "group not created (would be partial): "
                                 + "; ".join(errors))
                return
        else:
            errors = []
            payload = self._resolve_fields(payload, errors)
            if errors:
                self.blocked[(family, name.lower())] = "was not created (unresolved references)"
                self.report.fail("objects", name, "; ".join(errors))
                return

        if self.dry_run:
            print(f"    [DRY RUN] would create {target_name}")
            self._remember(path, {**payload, "id": DRY_RUN_ID,
                                  "type": payload.get("type") or PATH_TYPE.get(path)})
            self.report.count("objects", "would create")
            return
        created = self._post("objects", target_name, path, payload)
        if created is None:
            self.blocked[(family, name.lower())] = "failed to create (see its FAIL line)"
            return
        created.setdefault("name", target_name)
        created.setdefault("type", payload.get("type") or PATH_TYPE.get(path))
        self._remember(path, {**payload, **created})
        self.report.count("objects", "created")

    def _existing_difference(self, path: str, family: str, name: str, obj: Dict,
                             payload: Dict) -> Any:
        """False: no object with this name on FMC. None: an identical one exists.
        Otherwise the text of the difference with the same-named FMC object."""
        fam_paths = [path] + sorted(p for p in FAMILIES.get(family, ()) if p != path)
        for fam_path in fam_paths:
            existing = self._find(fam_path, name)
            if existing is None:
                continue
            if existing.get("id") == DRY_RUN_ID:
                return "the file defines this name twice"
            if fam_path != path:
                return (f"it is a {existing.get('type', PATH_TYPE.get(fam_path))} on FMC, "
                        f"the file defines a {obj.get('type', PATH_TYPE.get(path))}")
            return _content_difference(path, payload, existing)
        return False

    # --- policies ------------------------------------------------------------
    def _choose_policy(self, phase: str, path: str, wanted: str,
                       payload: Dict) -> Optional[Tuple[str, str, bool]]:
        existing = {str(p.get("name", "")).lower(): p
                    for p in self.client.list_all(path, expanded=False)}
        name = wanted
        reused = wanted.lower() in existing and self.reuse_policy
        if reused:
            pol = existing[wanted.lower()]
            policy_id, name = pol["id"], pol["name"]
        else:
            if wanted.lower() in existing:
                name = f"{wanted}-{self.stamp}"
                n = 2
                while name.lower() in existing:
                    name = f"{wanted}-{self.stamp}-{n}"
                    n += 1
                self.report.warn(f"{phase} policy '{wanted}' left untouched; using '{name}'")
            if self.dry_run:
                policy_id = DRY_RUN_ID
            else:
                created = self._post(phase, f"policy '{name}'", path, {**payload, "name": name})
                if created is None or not created.get("id"):
                    return None
                policy_id = created["id"]
        self.report.policies.append({"kind": phase, "requested_name": wanted,
            "actual_name": name, "id": None if policy_id == DRY_RUN_ID else policy_id,
            "action": "reused" if reused else ("would_create" if self.dry_run else "created")})
        print(f"  {'[DRY RUN] ' if self.dry_run else ''}{phase}: requested '{wanted}', actual '{name}', id {policy_id}")
        return policy_id, name, reused

    def _file_policies(self, key: str) -> List[Dict]:
        """The file's policies of one kind; [{}] (defaults) when it has none."""
        pols = self.policies.get(key) or [{}]
        if len(pols) == 1:  # 2.1.0 behaviour, unchanged
            return [pols[0] if isinstance(pols[0], dict) else {}]
        return [p for p in pols if isinstance(p, dict)] or [{}]

    def _route(self, phase: str, pols: List[Dict], rules: List[Tuple[int, Dict]],
               label: Any) -> List[List[Tuple[int, Dict]]]:
        """Split (file index, rule) pairs by the policy their _policy_name names.

        One policy: every rule goes into it (as in 2.1.0). Several: a rule with
        no _policy_name goes into the first; one naming a policy the file does
        not define is reported and not created (never put into another policy).
        """
        if len(pols) == 1:
            return [rules]
        exact: Dict[str, int] = {}
        folded: Dict[str, int] = {}
        for i, p in enumerate(pols):
            exact.setdefault(str(p.get("name") or ""), i)
            folded.setdefault(str(p.get("name") or "").lower(), i)
        buckets: List[List[Tuple[int, Dict]]] = [[] for _ in pols]
        for idx, rule in rules:
            wanted = rule.get("_policy_name")
            if wanted in (None, ""):
                buckets[0].append((idx, rule))
                continue
            i = exact.get(str(wanted), folded.get(str(wanted).lower()))
            if i is None:
                known = ", ".join(f"'{p.get('name')}'" for p in pols)
                self.report.fail(phase, label(idx, rule), f"not created: its _policy_name '{wanted}' "
                                 f"is not one of the file's policies ({known})")
                continue
            buckets[i].append((idx, rule))
        return buckets

    def _duplicate_policy(self, phase: str, pols: List[Dict], i: int) -> bool:
        name = str(pols[i].get("name") or "").lower()
        if name and any(str(p.get("name") or "").lower() == name for p in pols[:i]):
            self.report.fail(phase, f"policy '{pols[i].get('name')}'",
                             "the file defines this policy twice; its rules go into the first one")
            return True
        return False

    def push_access_rules(self) -> None:
        phase = "access rules"
        pols = self._file_policies("accesspolicies")
        rules = [r for r in self.policies.get("accessrules") or [] if isinstance(r, dict)]
        buckets = self._route(phase, pols, list(enumerate(rules)),
                              lambda _i, r: str(r.get("name") or "unnamed"))
        for i, (ap, bucket) in enumerate(zip(pols, buckets)):
            if len(pols) > 1 and self._duplicate_policy(phase, pols, i):
                continue
            try:
                self._push_access_policy(phase, ap, [r for _, r in bucket], several=len(pols) > 1)
            finally:
                self.report.scope = None

    def _push_access_policy(self, phase: str, ap: Dict, rules: List[Dict], several: bool) -> None:
        default_action = ap.get("defaultAction") if isinstance(ap.get("defaultAction"), dict) else {
            "type": "AccessPolicyDefaultAction", "logBegin": False, "logEnd": False,
            "sendEventsToFMC": False, "action": "BLOCK"}
        errors: List[str] = []
        default_action = self._resolve_fields(_strip_internal(default_action), errors)
        if errors:
            self.report.fail(phase, f"access policy '{ap.get('name')}'" if several else "access policy",
                             "; ".join(errors))
            return
        payload = {"type": "AccessPolicy", "defaultAction": default_action}
        if ap.get("description"):
            payload["description"] = ap["description"]
        chosen = self._choose_policy(phase, "policy/accesspolicies",
                                     ap.get("name") or "Migrated-Policy", payload)
        if chosen is None:
            for r in rules:
                self.report.fail(phase, str(r.get("name", "unnamed")), "not created: no access policy")
            return
        policy_id, policy_name, reused = chosen
        self.report.scope = policy_name
        rules_path = f"policy/accesspolicies/{policy_id}/accessrules"
        # Existing rules of a reused policy, in policy order (FMC ruleIndex = position + 1).
        existing: List[Dict] = []
        if reused:
            existing = [r for r in self.client.list_all(rules_path, expanded=True) if isinstance(r, dict)]
        order = [str(r.get("name", "")).lower() for r in existing]
        by_name = {str(r.get("name", "")).lower(): r for r in existing}

        file_names = [str(r.get("name") or "unnamed").lower() for r in rules]
        print(f"  {len(rules)} access rules -> '{policy_name}'")
        seen_in_file = set()
        for pos, rule in enumerate(rules):
            name = str(rule.get("name") or "unnamed")
            if name.lower() in seen_in_file:
                self.report.fail(phase, name, f"rule name collision: the file defines '{name}' "
                                 "twice; the second one was not created")
                continue
            seen_in_file.add(name.lower())

            payload = _strip_internal(rule, extra=("category",))
            payload["name"] = name
            payload.setdefault("type", "AccessRule")
            payload.setdefault("action", "ALLOW")
            errors = []
            payload = self._resolve_fields(payload, errors)
            if errors:
                self.report.fail(phase, name, _access_rule_error_text(errors))
                continue

            if name.lower() in by_name:
                if _access_rule_signature(by_name[name.lower()]) == _access_rule_signature(payload):
                    print(f"    SKIP {name} (identical rule already in '{policy_name}')")
                    self.report.count(phase, "already present")
                    self.report.record_skip(phase, name, "identical access rule already exists in the policy")
                else:
                    self.report.fail(phase, name, f"rule name collision: a different rule named "
                                     f"'{name}' already exists in policy '{policy_name}'; not created")
                continue

            params: Dict[str, Any] = {}
            category = rule.get("category")
            if isinstance(category, str) and category.lower() in ("mandatory", "default"):
                params["section"] = category.lower()
            elif category:
                self.report.warn(f"rule '{name}': category '{category}' is not sent; "
                                 "place the rule in that category in the FMC UI")
            # Keep file order in a reused policy: insert before the next rule of
            # the file that is already there (a plain POST appends after the
            # policy's last rule -- typically its deny-all).
            insert_before = None
            for later in file_names[pos + 1:]:
                if later in order:
                    insert_before = order.index(later) + 1
                    break
            if insert_before is not None:
                params["insertBefore"] = insert_before
            if self.dry_run:
                self.report.count(phase, "would create")
                continue
            if self._post(phase, name, rules_path, payload, params=params or None) is not None:
                self.report.count(phase, "created")
                if insert_before is not None:
                    order.insert(insert_before - 1, name.lower())
                else:
                    order.append(name.lower())

    def push_nat_rules(self) -> None:
        phase = "NAT rules"
        pols = self._file_policies("natpolicies")
        rules = [r for r in self.policies.get("natrules") or [] if isinstance(r, dict)]
        buckets = self._route(phase, pols, list(enumerate(rules, 1)),
                              lambda i, r: str(r.get("name") or f"NAT rule #{i}"))
        for i, (np_, bucket) in enumerate(zip(pols, buckets)):
            if len(pols) > 1 and self._duplicate_policy(phase, pols, i):
                continue
            try:
                self._push_nat_policy(phase, np_, bucket, several=len(pols) > 1)
            finally:
                self.report.scope = None

    def _push_nat_policy(self, phase: str, np_: Dict, rules: List[Tuple[int, Dict]],
                         several: bool) -> None:
        payload = {"type": "FTDNatPolicy"}
        if np_.get("description"):
            payload["description"] = np_["description"]
        chosen = self._choose_policy(phase, "policy/ftdnatpolicies",
                                     np_.get("name") or "Migrated-NAT", payload)
        if chosen is None:
            for i, r in rules:
                self.report.fail(phase, str(r.get("name") or f"NAT rule #{i}"), "not created: no NAT policy")
            return
        policy_id, policy_name, reused = chosen
        self.report.scope = policy_name
        # A reused policy may already hold these rules (an earlier run). FMC
        # accepts an identical manual NAT rule twice, so check before posting.
        self._existing_nat: Dict[str, List[Tuple]] = {"manual": [], "auto": []}
        if reused and policy_id != DRY_RUN_ID:
            for kind in ("manual", "auto"):
                items = self.client.list_all(f"policy/ftdnatpolicies/{policy_id}/{kind}natrules")
                self._existing_nat[kind] = [_nat_signature(r) for r in items if isinstance(r, dict)]
        print(f"  {len(rules)} NAT rules -> '{policy_name}'")
        for i, rule in rules:
            self._push_nat_rule(phase, policy_id, i, rule)

    def _auto_nat_port(self, value: Any) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """(port, protocol, error) for an Auto NAT port given as an int or a port-object ref."""
        port = _port_int(value)
        if port is not None:
            return port, None, None
        if isinstance(value, dict) and value.get("name"):
            try:
                obj = self._find("object/protocolportobjects", value["name"])
            except FMCError as exc:
                return None, None, str(exc)
            if obj is None:
                return None, None, f"port object '{value['name']}' not found"
            port = _port_int(obj.get("port"))
            if port is None:
                return None, None, (f"port object '{value['name']}' is '{obj.get('port')}'; "
                                    "Auto NAT needs a single port")
            return port, (str(obj.get("protocol") or "").upper() or None), None
        return None, None, f"unsupported Auto NAT port value {value!r}"

    def _push_nat_rule(self, phase: str, policy_id: str, index: int, rule: Dict) -> None:
        label = str(rule.get("name") or f"NAT rule #{index}")
        section = str(rule.get("section") or "BEFORE_AUTO").upper()
        is_auto = section == "AUTO" or rule.get("type") == "FTDAutoNatRule"
        clean = {k: v for k, v in _strip_internal(rule, extra=("section", "name")).items()
                 if v is not None}
        errors: List[str] = []

        if "patPool" in clean:  # FMC field is patOptions.patPoolAddress
            pat = dict(clean.get("patOptions") or {})
            pat.setdefault("patPoolAddress", clean.pop("patPool"))
            clean.pop("patPool", None)
            clean["patOptions"] = pat

        if is_auto:
            clean.setdefault("type", "FTDAutoNatRule")
            if clean.pop("enabled", True) is False:
                self.report.warn(f"{label}: disabled Auto NAT rule not created "
                                 "(FMC Auto NAT rules cannot be disabled)")
                self.report.record_skip(phase, label, "disabled Auto NAT rule cannot be created on FMC")
                self.report.count(phase, "skipped")
                return
            for fld in ("originalPort", "translatedPort"):
                if fld in clean:
                    port, proto, err = self._auto_nat_port(clean[fld])
                    if err:
                        errors.append(f"{fld}: {err}")
                        continue
                    clean[fld] = port
                    if proto and not clean.get("serviceProtocol"):
                        clean["serviceProtocol"] = proto
            path = f"policy/ftdnatpolicies/{policy_id}/autonatrules"
            params = None
        else:
            clean.setdefault("type", "FTDManualNatRule")
            if section not in ("BEFORE_AUTO", "AFTER_AUTO"):
                self.report.fail(phase, label, f"unknown NAT section '{section}'; not created")
                return
            path = f"policy/ftdnatpolicies/{policy_id}/manualnatrules"
            params = {"section": section.lower()}  # FMC 7.6 rejects the uppercase form

        clean = self._resolve_fields(clean, errors)
        if errors:
            self.report.fail(phase, label, "not created (it would translate more than intended): "
                             + "; ".join(errors))
            return
        existing = getattr(self, "_existing_nat", {}).get("auto" if is_auto else "manual", [])
        if _nat_signature(clean) in existing:
            print(f"    SKIP {label} (identical {'Auto' if is_auto else 'manual'} NAT rule already in the policy)")
            self.report.count(phase, "already present")
            self.report.record_skip(phase, label, "identical NAT rule already exists in the policy")
            return
        if self.dry_run:
            self.report.count(phase, "would create")
            return
        if self._post(phase, label, path, clean, params=params) is not None:
            self.report.count(phase, "created")

    # --- S2S VPN -------------------------------------------------------------
    def push_s2s_vpns(self) -> None:
        phase = "S2S VPNs"
        for topo in self.policies.get("ftds2svpns") or []:
            if not isinstance(topo, dict):
                continue
            name = str(topo.get("name") or "unnamed")
            clean = _strip_internal(topo)
            endpoints = clean.get("endpoints") or []
            if any(not ep.get("extranet") and str(ep.get("deviceName", "")).startswith("<")
                   for ep in endpoints if isinstance(ep, dict)):
                self.report.warn(f"{name}: local endpoint is a placeholder — choose the target FTD "
                                 "device in the FMC UI and add this topology there (IKE policy and "
                                 "IPsec proposal objects were imported)")
                self.report.count(phase, "manual step")
                continue
            errors: List[str] = []
            for key in ("ikeSettings", "ipsecSettings"):
                if key in clean:
                    clean[key] = self._resolve_tree(clean[key], key, errors)
            if errors:
                self.report.fail(phase, name, "; ".join(errors))
                continue
            if self.dry_run:
                self.report.count(phase, "would create")
                continue
            if self._post(phase, name, "policy/ftds2svpns", clean) is not None:
                self.report.count(phase, "created")


# --------------------------------------------------------------------------- CLI

def apply_policy_names(data: Dict, access_name: Optional[str] = None,
                       nat_name: Optional[str] = None) -> Dict:
    """Validate all overrides before authentication; never mutate the artifact."""
    result = copy.deepcopy(data)
    policies = result.get("policies") or {}
    for key, rules_key, value in (("accesspolicies", "accessrules", access_name),
                                   ("natpolicies", "natrules", nat_name)):
        if value is None:
            continue
        if not value.strip() or len(value) > 64 or any(ord(c) < 32 for c in value):
            raise ValueError(f"{key}: name must be 1-64 printable characters")
        entries = policies.get(key) or []
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
            raise ValueError(f"{key}: naming override requires exactly one policy")
        old = entries[0].get("name")
        for rule in policies.get(rules_key) or []:
            if rule.get("_policy_name") not in (None, "", old):
                raise ValueError(f"{rules_key}: reference does not name the single file policy")
            rule["_policy_name"] = value.strip()
        entries[0]["name"] = value.strip()
    return result


def import_receipt(report: Report, artifact_hash: str, version: Optional[str],
                   domain: Optional[str], dry_run: bool) -> Dict:
    return {"schema": "nc.fmc-import-receipt.v1", "artifact_sha256": artifact_hash,
        "importer_version": __version__, "fmc_version": version, "domain_id": domain,
        "status": "incomplete" if report.failures else ("dry_run" if dry_run else "imported"),
        "assigned": False, "deployed": False, "policies": report.policies,
        "counts": report.counts, "object_renames": report.renames,
        "skipped_items": report.skipped,
        "warnings": report.warnings, "failures": report.failures}


def redact_receipt(value: Any, secrets: List[str]) -> Any:
    """FMC error text can echo input: remove supplied credentials and API tokens."""
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, list):
        return [redact_receipt(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: redact_receipt(item, secrets) for key, item in value.items()}
    return value


def write_receipt(path: str, receipt: Dict) -> None:
    """Atomically publish the receipt; keep partial JSON out of the destination."""
    target = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                         prefix=".fmc-receipt-", delete=False) as handle:
            temporary = handle.name
            json.dump(receipt, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, target)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="NetConverter.AI — Import FMC JSON to Cisco Secure Firewall Management Center",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python3 fmc_import.py --host 10.1.1.100 --user admin --json output.json --dry-run",
    )
    parser.add_argument("--host", required=True, help="FMC hostname or IP")
    parser.add_argument("--user", required=True, help="FMC username")
    parser.add_argument("--password", help="FMC password (prompted if not provided)")
    parser.add_argument("--json", required=True, help="Path to NetConverter FMC JSON file")
    parser.add_argument("--dry-run", action="store_true",
                        help="Read FMC and report what would happen, without making changes")
    parser.add_argument("--reuse-policy", action="store_true",
                        help="Write into an existing access/NAT policy with the same name "
                             "(default: create a uniquely named policy)")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificate (default: skip)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--access-policy-name", help="Override the single access policy name")
    parser.add_argument("--nat-policy-name", help="Override the single NAT policy name")
    parser.add_argument("--report-json", help="Write an import receipt (never credentials)")
    args = parser.parse_args(argv)

    if requests is None:
        print("ERROR: 'requests' package required. Install with: pip install requests")
        return 1

    try:
        artifact = Path(args.json).read_bytes()
        data = json.loads(artifact)
    except (OSError, ValueError) as e:
        print(f"ERROR: Cannot read {args.json}: {e}")
        return 1
    if not isinstance(data, dict):
        print(f"ERROR: {args.json} is not a NetConverter FMC JSON document")
        return 1

    try:
        data = apply_policy_names(data, args.access_policy_name, args.nat_policy_name)
        if args.report_json and Path(args.report_json).resolve() == Path(args.json).resolve():
            raise ValueError("receipt must not overwrite the input JSON")
        if args.report_json:
            target = Path(args.report_json)
            if target.exists() and not target.is_file():
                raise ValueError("receipt destination must be a file")
            with tempfile.TemporaryFile(dir=target.parent):
                pass
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}")
        return 1
    password = args.password or getpass(f"Password for {args.user}@{args.host}: ")
    objects = data.get("objects") or {}
    policies = data.get("policies") or {}
    total_objects = sum(len(v) for v in objects.values() if isinstance(v, list))
    total_rules = sum(len(v) for v in policies.values() if isinstance(v, list))
    print(f"\nNetConverter.AI FMC Import v{__version__}")
    print("=" * 60)
    print(f"FMC Host:    {args.host}")
    print(f"JSON File:   {args.json}")
    print(f"Objects:     {total_objects}")
    print(f"Policies:    {total_rules}")
    if args.dry_run:
        print("Mode:        DRY RUN (no changes)")
    if args.reuse_policy:
        print("Policies:    --reuse-policy (existing same-named policies will be written into)")
    print("=" * 60)

    print(f"\nAuthenticating to {args.host}...")
    try:
        client, version = connect(args.host, args.user, password, args.verify_ssl, http=requests)
    except FMCError as exc:
        print(f"AUTH FAILED: {exc}")
        if args.report_json:
            failed = Report()
            failed.fail("authentication", "FMC", "authentication did not complete", exc.status)
            try:
                write_receipt(args.report_json, import_receipt(failed,
                    hashlib.sha256(artifact).hexdigest(), None, None, args.dry_run))
            except OSError:
                print("ERROR: authentication failure receipt could not be written")
        return 1
    except OSError as exc:
        print(f"ERROR: cannot reach {args.host}: {exc}")
        if args.report_json:
            failed = Report()
            failed.fail("connection", "FMC", "connection did not complete")
            try:
                write_receipt(args.report_json, import_receipt(failed,
                    hashlib.sha256(artifact).hexdigest(), None, None, args.dry_run))
            except OSError:
                print("ERROR: connection failure receipt could not be written")
        return 1
    print(f"  Authenticated. FMC {version or 'unknown'}, Domain: {client.domain}")

    report = Importer(client, data, dry_run=args.dry_run, reuse_policy=args.reuse_policy).run()
    report.print_summary()
    if args.report_json:
        try:
            receipt = import_receipt(report, hashlib.sha256(artifact).hexdigest(), version,
                                     client.domain, args.dry_run)
            for field in ('warnings', 'failures', 'object_renames', 'skipped_items'):
                receipt[field] = redact_receipt(receipt[field], [password, getattr(client, "token", ""), getattr(client, "refresh_token", "")])
            write_receipt(args.report_json, receipt)
        except OSError as exc:
            print(f"ERROR: import ran but receipt could not be written: {exc}")
            return 1
    if not args.dry_run and not report.failures:
        print("Log into FMC to verify, then deploy to the managed devices.")
    return report.exit_code()


if __name__ == "__main__":
    sys.exit(main())
