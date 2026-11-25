#!/usr/bin/env python3
"""Guard: nothing publish_public.py would ship may carry machine paths or real addresses.

The public collectors repo is one-way and public; a leak there cannot be recalled.
This test scans exactly the files ``scripts/publish_public.py`` would copy
(including untracked files sitting in a managed folder, because the publish
script ships those too) and fails on:

* absolute home-directory paths (macOS, Linux and Windows user folders),
* cloud-storage and customer-folder markers (the sync-client folder names and
  the customer-configs folder name listed in ``PATH_MARKERS``),
* public IPv4/IPv6 addresses outside the documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32). Private,
  loopback, link-local, multicast, reserved and mask-like values are allowed,
  and so is shared address space 100.64.0.0/10 (RFC 6598): like RFC 1918 it is
  not routable on the internet, so it cannot point at an organisation,
* 12-digit numbers in the device-serial format (synthetic serials start with
  seven zeros),
* host names on registrable domains other than the allowlisted vendor and
  reference domains; fixtures use ``example.*``, ``.test`` or ``.invalid``.

This file ships and is scanned like every other published file, so its own
bad examples are assembled from fragments at run time.

The denylist is generic on purpose: naming a real customer, serial or host here
would publish it. Fixtures must use synthetic values instead.

Run: python3 -m pytest -q scripts/test_public_tree_hygiene.py
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_public as pub  # noqa: E402

REPO_ROOT = pub.REPO_ROOT

DOC_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_SHARED_SPACE = ipaddress.ip_network("100.64.0.0/10")

PATH_MARKERS = (
    ("home-directory path", re.compile(r"/Users/[A-Za-z0-9._-]+")),
    ("home-directory path", re.compile(r"/home/[A-Za-z0-9._-]+/")),
    ("home-directory path", re.compile(r"[A-Za-z]:[\\/]+Users[\\/]", re.I)),
    ("cloud-storage marker", re.compile(
        r"One" r"Drive|Cloud" r"Storage|Mobile" r" Documents|Drop" r"box/|Google" r" Drive/", re.I)),
    ("customer-folder marker", re.compile(r"netconverter-" r"clients", re.I)),
)

# Underscores may touch an address (``fw_<addr>.xml``) and a sentence may end on one;
# a dot followed by a digit means a longer dotted number (an OID or a version).
_IPV4 = re.compile(r"(?<![0-9A-Za-z.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z]|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])([23][0-9a-fA-F]{3}:[0-9a-fA-F:]{2,})(?![\w:])")
# A dotted quad right after one of these words is a release number, not an address.
_VERSION_CONTEXT = re.compile(r"(?:version|release|build|NetConverter\.local|\bv)\s*$", re.I)
# Palo Alto serials are 12 digits; synthetic fixtures use seven leading zeros.
# Hex neighbours mean the digits sit inside a hash.
_SERIAL = re.compile(r"(?<![0-9A-Fa-f])(0\d{11})(?![0-9A-Fa-f])")
_SYNTHETIC_SERIAL = "0000000"
_FQDN = re.compile(r"(?<![\w.-])((?:[a-z0-9-]+\.)+(?:com|net|org|io|ai|co|gov|edu|dev|us|uk|de))(?![\w(-])")
# Vendor, standards and reference domains the collectors name on purpose.
ALLOWED_DOMAINS = frozenset({
    "netconverter.ai", "aws-netconverter.ai", "github.com", "w3.org", "draw.io",
    "nist.gov", "cisa.gov", "first.org", "python.org", "bitstream.com",
    "fontconfig.org", "pan.dev", "dropbox.com",
})


def published_files() -> list[tuple[str, Path]]:
    """(published path, source path) for every file the publish would write."""
    folders = pub.managed_folders()
    out = [
        (str(rel), REPO_ROOT / pub.ROOT_SOURCES.get(rel, rel))
        for rel in pub.iter_source_files(folders)
    ]
    # Rendered from these sources rather than copied verbatim.
    out += [("README.md", REPO_ROOT / "README.md"),
            ("collectors.lock.json", REPO_ROOT / "collectors.lock.json")]
    return out


def _public_address(token: str) -> bool:
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        return False
    if any(addr in net for net in DOC_NETS if net.version == addr.version):
        return False
    if addr.version == 4 and (token.startswith(("0.", "255.")) or addr in _SHARED_SPACE):
        return False  # masks, wildcards, "this network", shared address space
    if addr.is_multicast or addr.is_reserved:
        return False
    return addr.is_global


def findings_in_text(text: str) -> list[tuple[int, str]]:
    """(line number, class) for each forbidden value. Values are never returned."""
    out: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for label, rx in PATH_MARKERS:
            if rx.search(line):
                out.append((lineno, label))
        for m in _IPV4.finditer(line):
            if _VERSION_CONTEXT.search(line[: m.start()]):
                continue
            if _public_address(m.group(1)):
                out.append((lineno, "public IPv4 outside documentation ranges"))
        for m in _IPV6.finditer(line):
            if _public_address(m.group(1).rstrip(":")):
                out.append((lineno, "public IPv6 outside 2001:db8::/32"))
        for m in _SERIAL.finditer(line):
            if not m.group(1).startswith(_SYNTHETIC_SERIAL):
                out.append((lineno, "device-serial-format number"))
        for m in _FQDN.finditer(line):
            labels = m.group(1).split(".")
            if "example" not in labels and ".".join(labels[-2:]) not in ALLOWED_DOMAINS:
                out.append((lineno, "host name outside reserved example domains"))
    return out


def scan_published_tree() -> list[str]:
    problems: list[str] = []
    files = published_files()
    sources = {source.resolve() for _published, source in files}
    for folder in pub.managed_folders():
        if not any(str(p).startswith(folder + "/") for p, _s in files):
            # Fail closed: an empty or renamed publish API must not read as clean.
            problems.append(f"{folder}/: absent from the publish file set")
    if Path(__file__).resolve() not in sources:
        problems.append("publish file set does not include this guard")
    for published, source in files:
        try:
            text = source.read_bytes().decode("utf-8", errors="ignore")
        except OSError as exc:
            problems.append(f"{published}: unreadable ({type(exc).__name__})")
            continue
        for lineno, label in findings_in_text(text):
            problems.append(f"{published}:{lineno}: {label}")
    return problems


def test_published_tree_has_no_machine_paths_or_public_addresses():
    problems = scan_published_tree()
    assert not problems, (
        "Files that scripts/publish_public.py would ship contain identifying values "
        "(use example.net hosts, documentation-range addresses and fixture-relative "
        "paths instead):\n  " + "\n  ".join(problems)
    )


def test_scan_covers_what_publish_ships():
    published = {p for p, _ in published_files()}
    assert "palo/panorama/test_palo_model.py" in published
    assert "AGENTS.md" in published and "README.md" in published
    assert not any(p.startswith("palo/scm/") for p in published), "scaffold must not ship"


def test_detector_flags_each_class_and_allows_synthetic_values():
    # The bad examples are assembled from fragments so this file, which ships and is
    # scanned like every other published file, carries none of them literally.
    pub_v4, pub_v6 = "8.8." + "4.4", "2606:" + "4700::1111"
    bad = "\n".join([
        'p = "/Use' + 'rs/someone/data.xml"',
        'p = "/ho' + 'me/someone/data.xml"',
        'p = "C:\\' + 'Users\\someone\\data.xml"',
        "see One" + "Drive-Example/folder",
        "see ~/Library/Cloud" + "Storage/x",
        "see netconverter-" + "clients/x",
        "<ip>" + pub_v4 + "</ip>",
        "peer " + pub_v6,
        "the peer is " + pub_v4 + ".",            # sentence-final address
        "saved as fw_" + pub_v4 + ".xml",         # address inside a file name
        "set local " + pub_v4,                    # "local" is not a version word
        '<entry name="0' + '16200001234"/>',      # 12-digit device-serial format
        "--host fmc.customer" + ".com",           # registrable domain, not reserved
    ])
    assert [n for n, _ in findings_in_text(bad)] == list(range(1, 14))
    good = "\n".join([
        "<ip>192.0.2.10</ip> <ip>198.51.100.1</ip> <ip>203.0.113.4/32</ip>",
        "<ip>10.0.0.1</ip> 172.16.0.1 192.168.1.1 127.0.0.1 169.254.0.1 224.0.0.5",
        "mask 255.255.255.0 wildcard 0.0.0.255 default 0.0.0.0/0 cgnat 100.64.0.1",
        "peer 2001:db8::1 fe80::1 ::1",
        "NetConverter.local 2.0.7.3 accepted it; version 1.2.3.4 shipped",
        "oid 1.3.6.1.4.1.25461 and release 1.2.3.4.5 are not addresses",
        "nets/users/machines and ./home/ are relative",
        '<entry name="000000000101"/> sha ab020476400828cd',
        "fmc.example.com SITE2-FW-01.example.net x.test y.invalid www.w3.org logger.info(x)",
    ])
    assert findings_in_text(good) == []


def test_scan_fails_closed_when_publish_lists_nothing(monkeypatch):
    monkeypatch.setattr(pub, "iter_source_files", lambda folders: [])
    assert any("publish file set" in p for p in scan_published_tree())


def test_guard_scans_itself():
    published = dict(published_files())
    me = Path(__file__).resolve()
    assert any(src.resolve() == me for src in published.values())
    assert not [p for p in scan_published_tree() if p.startswith("scripts/test_public_tree_hygiene.py")]


if __name__ == "__main__":
    probs = scan_published_tree()
    print("\n".join(probs) if probs else "clean")
    raise SystemExit(1 if probs else 0)
