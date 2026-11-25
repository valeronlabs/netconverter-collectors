#!/usr/bin/env python3
"""Customer entrypoint: collect FMC/FTD → package fmc_audit_*.zip for NetConverter.

Read-only. Prefer this script (or run_collect.sh / run_collect.bat) with mode
``full``. See CUSTOMER.md for the handoff checklist.

Examples:
    python3 collect_for_netconverter.py --host fmc.example.com --user api_ro
    python3 collect_for_netconverter.py --host 10.1.1.10 --user api_ro --insecure
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pull a read-only FMC/FTD snapshot and package fmc_audit_*.zip for NetConverter.",
    )
    parser.add_argument("--host", required=True, help="FMC hostname or IP (no https://)")
    parser.add_argument("--user", required=True, help="FMC API username (read-only preferred)")
    parser.add_argument("--password", default=os.environ.get("FMC_PASSWORD", ""),
                        help="Password (else FMC_PASSWORD env, else prompt)")
    parser.add_argument("--output", default=".", help="Output directory (default: current folder)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS verification (lab / self-signed only)")
    parser.add_argument("--all-domains", action="store_true",
                        help="Collect every authorized FMC domain")
    parser.add_argument("--mode", choices=("full", "quick"), default="full",
                        help="full = production package (default); quick = smoke only")
    args = parser.parse_args(argv)

    print("NetConverter — Cisco FMC / FTD collector")
    print("========================================")
    print("1) Authenticate (read-only)")
    print("2) Pull devices, policies, objects, and Access Policy SGT fields")
    print("3) Build HTML browser + package fmc_audit_*.zip")
    print("4) Send ONLY the ZIP to NetConverter (see CUSTOMER.md)")
    print()

    cmd = [
        sys.executable,
        str(HERE / "fmc_collect_data.py"),
        "--host", args.host,
        "--user", args.user,
        "--output", args.output,
    ]
    if args.password:
        cmd.extend(["--password", args.password])
    if args.insecure:
        cmd.append("--insecure")
    if args.all_domains:
        cmd.append("--all-domains")
    if args.mode == "quick":
        cmd.append("--quick")

    env = os.environ.copy()
    # Force UTF-8 so Windows consoles do not drop collection.log / manifest.json.
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")

    print(f"Collecting ({args.mode}) from {args.host} …")
    rc = subprocess.call(cmd, cwd=str(HERE), env=env)
    if rc != 0:
        print("Collect failed. See CUSTOMER.md troubleshooting.", file=sys.stderr)
        return rc

    # Locate newest run-* under output and package + HTML like run_collect.sh.
    out = Path(args.output).expanduser().resolve()
    runs = sorted(out.glob("run-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not runs:
        # collector may have written under HERE when --output is relative weirdly
        runs = sorted(HERE.glob("run-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not runs:
        print("Collect finished but no run-* folder was found.", file=sys.stderr)
        return 1
    run_dir = runs[0]

    print(f"Building HTML for {run_dir.name} …")
    rc = subprocess.call([sys.executable, str(HERE / "build_html.py"), "--input", str(run_dir)],
                         cwd=str(HERE), env=env)
    if rc != 0:
        print("HTML build failed; the raw run folder is still usable.", file=sys.stderr)

    print("Packaging ZIP …")
    out_dir = str(run_dir.parent.resolve())
    rc = subprocess.call(
        [sys.executable, str(HERE / "package_run.py"), "--input", str(run_dir),
         "--format", "zip", "--output-dir", out_dir],
        cwd=str(HERE), env=env,
    )
    if rc != 0:
        return rc

    zips = sorted(run_dir.parent.glob("fmc_audit_*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    print()
    print("Done.")
    if zips:
        print(f"  Send this file: {zips[0]}")
    print(f"  Local browser:  {run_dir / 'html_view' / 'index.html'}")
    print("  Instructions:   CUSTOMER.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
