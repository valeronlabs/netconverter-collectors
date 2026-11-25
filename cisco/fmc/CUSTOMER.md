# Customer instructions — Cisco FMC / FTD collect for NetConverter

Use this folder to pull a **read-only** snapshot of your Cisco Secure Firewall
Management Center (FMC) and the managed FTD devices it manages. The result is a
single ZIP that you send to NetConverter / ValeronLabs for audit, optimization,
and migration analysis.

This collector never changes your FMC. It only authenticates and issues `GET`
requests (plus the token call).

## What you need

- Python 3.8 or newer on a workstation that can reach FMC over HTTPS (TCP 443)
- An FMC API user with **read** access to the domains you want collected
  (a dedicated read-only account is preferred)
- Network reach to the FMC management address (hostname or IP)

```bash
cd cisco/fmc
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt    # installs: requests
```

## 1. Confirm credentials

```bash
python3 fmc_test_auth.py --host FMC_HOST --user API_USER
# password is prompted (or set FMC_PASSWORD / pass --password)
```

Success prints `OK: authentication succeeded` and the FMC version.

Lab / self-signed certificate: add `--insecure`.

## 2. Collect (recommended: one command)

**Any OS (Python)**

```bash
python3 collect_for_netconverter.py --host FMC_HOST --user API_USER
```

**macOS / Linux helper**

```bash
./run_collect.sh --host FMC_HOST --user API_USER full
```

**Windows helper**

```bat
run_collect.bat --host FMC_HOST --user API_USER full
```

Optional flags:

| Flag | Meaning |
|------|---------|
| `--insecure` | Skip TLS verify (lab / self-signed only) |
| `--all-domains` | Collect every authorized FMC domain |
| `--output DIR` | Where to write the `run-*` folder and ZIP |
| `quick` instead of `full` | Smaller smoke collect (not for production analysis) |

Password options (pick one): interactive prompt, `--password …`, or
`FMC_PASSWORD` in the environment / a local `.env` (never email the password).

## 3. What to send us

Send **only** the packaged file:

```text
fmc_audit_YYYYMMDD-HHMMSS.zip
```

Do **not** send the loose `run-*` folder, screenshots of the HTML browser, or
FMC credentials.

The ZIP includes:

- FMC + FTD inventory (devices, interfaces, routes)
- Access / NAT / prefilter / DNS / identity policy containers and rules
- Network, service, zone, application, and related objects
- **Security Group Tags (SGT)** used on Access Policy rules
  (`sourceSecurityGroupTags` / `destinationSecurityGroupTags`), plus the ISE /
  local SGT object catalogs when FMC exposes them
- Completeness evidence so missing API areas are explicit

Optional: open `run-*/html_view/index.html` locally to review before sending.
NetConverter analysis still needs the ZIP, not the HTML alone.

## 4. Security Group Tags (TrustSec / ISE)

If you use SGTs on Access Control rules:

- Keep those rules in the Access Policies that the API user can read
- Prefer `full` mode (not `quick`) so every ACP and its rules are pulled
- When ISE is integrated, FMC may refuse the local `/object/securitygrouptags`
  catalog; the collector still records SGT **references on each access rule**
  and attempts `/object/isesecuritygrouptags`

You do not need a separate SGT export from ISE for this package.

## 5. Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `AUTH FAILED: 401` | Wrong user/password, or the account lacks API access |
| `Auth 401 … retry` then success | Normal on busy lab/sandbox FMCs — let it finish |
| Connection / TLS errors | Confirm HTTPS reachability; lab certs need `--insecure` |
| ZIP missing / collect aborted | Re-run `full`; send `collection.log` from the `run-*` folder with the ZIP if it still fails |

## Support

Questions about the package or upload: your NetConverter contact, or
https://netconverter.ai
