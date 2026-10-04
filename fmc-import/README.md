# FMC Import Script — v2.2.1

Push NetConverter-generated FMC JSON files to a live Cisco Secure Firewall Management Center (FMC) via the REST API.

## What It Does

This script takes the FMC JSON output from [NetConverter.AI](https://netconverter.ai) and pushes it to your FMC in the correct dependency order:

1. **Network Objects** - hosts, networks, ranges, FQDNs
2. **Service Objects** - protocol/port objects
3. **Security Zones**
4. **Object Groups** - network groups, port groups (with member resolution)
5. **VPN Objects** - IKEv1/v2 policies and IPSec proposals
6. **Access Policies & Rules** - with zone, network, and port reference resolution
7. **NAT Policies & Rules** - manual and auto NAT with reference resolution

## Prerequisites

- Python 3.8 or higher
- `requests` library
- Network access from your machine to the FMC management interface (HTTPS/443)
- FMC user account with admin privileges

## Installation

```bash
pip install requests
```

That's it. No other dependencies required.

## Usage

### Basic Import

```bash
python3 fmc_import.py --host 10.1.1.100 --user admin --json converted_output.json
```

You'll be prompted for the password securely (not echoed to terminal).

### Dry Run (Preview Without Changes)

```bash
python3 fmc_import.py --host 10.1.1.100 --user admin --json converted_output.json --dry-run
```

Dry run authenticates and reads the FMC to resolve existing references and conflicts; it posts no configuration changes. Always recommended before your first live import.

### All Options

```
python3 fmc_import.py --host HOST --user USER --json FILE [options]

Required:
  --host HOST       FMC hostname or IP address
  --user USER       FMC username
  --json FILE       Path to NetConverter FMC JSON file

Optional:
  --password PASS   FMC password (prompted if not provided)
  --dry-run         Preview without making changes
  --reuse-policy    Explicitly reuse an existing named access/NAT policy
  --version         Print importer version
  --verify-ssl      Verify SSL certificate (default: skip for self-signed)
```

## Example Output

```
NetConverter.AI FMC Import
==================================================
FMC Host:    10.1.1.100
JSON File:   asa_to_fmc.json
Objects:     65
Policies:    54
==================================================

Authenticating to 10.1.1.100...
  Authenticated. FMC 7.6.5, Domain: e276abec-...

Pushing objects...
  hosts: 12 objects
  networks: 8 objects
  protocolportobjects: 15 objects
  securityzones: 4 objects
  networkgroups: 6 objects

  Objects: created=45, skipped=20, failed=0

Pushing access rules...
  Using existing policy: Migrated-Policy
  Pushing 43 access rules...
  Rules: created=43, failed=0

Pushing NAT rules...
  Created NAT policy: Migrated-NAT
  NAT: created=11, failed=0

==================================================
Import complete. Log into FMC to verify.
NOTE: Deploy changes to managed devices for rules to take effect.
==================================================
```

## Important Notes

- **Deploy after import**: FMC holds changes in a staging area. You must deploy to managed devices from the FMC UI for rules to take effect.
- **Skipped objects**: Objects that already exist on the FMC are automatically skipped (not duplicated).
- **Existing policies**: By default, a name collision creates a uniquely named policy. Use `--reuse-policy` explicitly to write into an existing policy; rule insertion retains file order and detects conflicts.
- **SSL certificates**: Most FMC installations use self-signed certificates. The script skips SSL verification by default. Use `--verify-ssl` if your FMC has a trusted certificate.

## Generating the FMC JSON File

1. Go to [netconverter.ai](https://netconverter.ai) and sign in
2. Open **Quick Convert**
3. Paste or upload your source firewall configuration (ASA, FortiGate, Palo Alto, etc.)
4. Select **Cisco FMC (JSON)** as the target
5. Click **Convert**
6. Download the converted output JSON file

## Supported FMC Versions

Tested with FMC 7.2+ through 7.6.5. The script uses stable v1 REST API endpoints.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `AUTH FAILED: 401` | Check username/password. Ensure the user has API access in FMC. |
| `Connection refused` | Verify FMC is reachable on port 443 from your machine. |
| `SSL certificate error` | Remove `--verify-ssl` flag (default behavior skips SSL check). |
| Objects show `FAIL` | Check FMC audit log for details. Usually a naming conflict or limit. |

## License

MIT License - see [LICENSE](../LICENSE) for details.

## Version 2.3.0: policy names and import receipts

```sh
python3 fmc_import.py --host FMC_HOST --user FMC_USER --json converted_output.json --verify-ssl --dry-run --access-policy-name NC-Access --nat-policy-name NC-NAT --report-json preview.json
python3 fmc_import.py --host FMC_HOST --user FMC_USER --json converted_output.json --verify-ssl --access-policy-name NC-Access --nat-policy-name NC-NAT --report-json import-receipt.json
```

Passwords are prompted. Each naming override requires exactly one policy of that type in the file;
zero/multiple policies or invalid names refuse before authentication. The original JSON is unchanged.
Without overrides names come from the file. Existing same-named policies are left untouched and fresh
unique names are chosen unless `--reuse-policy` deliberately selects the existing policies.

The receipt records the original artifact SHA-256, importer/FMC version, authenticated domain,
requested and actual policy names/IDs, per-policy counts, object renames, warnings and failures.
Dry-run policy IDs are absent for policies that would be created. An incomplete import exits nonzero.
Inspect actual names before retrying: target them explicitly with naming overrides and `--reuse-policy`
when resuming a single-policy import, rather than accidentally creating additional policies.

**Import is not assignment or deployment.** Use the receipt's actual names/IDs to find policies in FMC.
Bind FTD data interfaces to the imported security zones, recreate required routing and declared device
settings, complete any VPN endpoint/certificate prerequisites, assign access and NAT policies to the
intended managed FTD, then deploy through FMC and test permit/deny/NAT traffic. The script performs
none of those device-level steps. Back up existing assignments/configuration before changing them.
Do not delete shared/reused objects as a rollback shortcut.

Version 2.3.0 has focused mocked-API verification; new CLI/receipt behavior still needs a live FMC
retest. Existing lab proof for 2.2.1 must not be presented as a 2.3.0 deployment proof.
