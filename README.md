# sbom-snapshot-lite: CycloneDX 1.5 SBOM of the installed Python environment

sbom-snapshot-lite lists the Python packages that are actually installed in the current environment and writes a CycloneDX 1.5 JSON SBOM, offline, with Package URLs and license metadata when the package declares it. It does not call PyPI or any other network service, and it does not install anything into the environment it is describing. One file, Python 3.8+ standard library only, MIT.

Need npm packages from a `node_modules` folder, dpkg/rpm system packages, SPDX 2.3 output, or a diff between two snapshots? That is the full [SBOM Snapshot](https://py-forge.com/products/sbom-snapshot-installed-environment?utm_source=github&utm_medium=readme&utm_campaign=sbom-snapshot-lite) (one-time payment, yours to keep, no subscription). A table later in this README lists what lite does and what the paid tool adds. Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=sbom-snapshot-lite) ($99, one payment).

- Optional `pip install`, or just download the one file. No dependencies, no network access.
- Uses `importlib.metadata` (the standard library), so the tool does not have to be installed into the environment it scans.
- Package names in the SBOM are normalized the way PyPI / Package-URL expect (`Ruamel.Yaml` becomes `ruamel-yaml`).
- After `pip install`, use `sbom-snapshot-lite` in place of `python3 sbom_snapshot_lite.py`.

## Install

```bash
pip install sbom-snapshot-lite
sbom-snapshot-lite --help
```

Or download the single file (Python 3.8+, stdlib only, no extra packages):

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/sbom-snapshot-lite/main/sbom_snapshot_lite.py
python3 sbom_snapshot_lite.py --help
```

## See the output first (offline demo)

```bash
python3 sbom_snapshot_lite.py --demo
```

The demo writes a built-in sample document (three well-known packages). It does not scan your machine. Captured on 25 November 2026, Europe/Rome; real command and output, deterministic.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-25T00:00:00Z",
    "tools": [
      {
        "vendor": "PyForge",
        "name": "sbom-snapshot-lite",
        "version": "0.1.0"
      }
    ],
    "component": {
      "type": "application",
      "name": "Demo Environment",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "certifi",
      "purl": "pkg:pypi/certifi@2024.2.2",
      "version": "2024.2.2",
      "licenses": [
        {
          "license": {
            "id": "MPL-2.0"
          }
        }
      ]
    },
    {
      "type": "library",
      "name": "urllib3",
      "purl": "pkg:pypi/urllib3@2.2.1",
      "version": "2.2.1",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    },
    {
      "type": "library",
      "name": "idna",
      "purl": "pkg:pypi/idna@3.7",
      "version": "3.7",
      "licenses": [
        {
          "license": {
            "id": "BSD-3-Clause"
          }
        }
      ]
    }
  ]
}
```

## Snapshot your current environment

```bash
python3 sbom_snapshot_lite.py -o sbom.json
python3 sbom_snapshot_lite.py --doc-name "api-prod" -o sbom.json
```

Without `-o`, JSON is printed to stdout. A live scan sets `metadata.timestamp` and `serialNumber` at runtime; those two fields will differ between runs.

## Exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | SBOM written, or `--self-test` passed |
| `2` | The file could not be written, or `--self-test` failed |

## sbom-snapshot-lite vs SBOM Snapshot

sbom-snapshot-lite inventories the current Python environment and writes CycloneDX 1.5 JSON. That's it.

The full [SBOM Snapshot](https://py-forge.com/products/sbom-snapshot-installed-environment?utm_source=github&utm_medium=readme&utm_campaign=sbom-snapshot-lite) also reads npm packages from a `node_modules` folder, dpkg/rpm system packages, SPDX 2.3 output, install-record fingerprints, and `--diff` between two snapshots. One-time payment, yours to keep. No subscription.

| Capability | Lite (free) | Paid SBOM Snapshot |
| --- | --- | --- |
| Installed Python packages of the current environment | Yes | Yes |
| CycloneDX 1.5 JSON, with Package URLs | Yes | Yes |
| License field when the package metadata has one | Yes | Yes |
| npm packages from `--node-modules` | No | Yes |
| dpkg/rpm system packages (`--system`) | No | Yes |
| SPDX 2.3 output | No | Yes |
| SHA-256 fingerprint of each install record | No | Yes |
| `--diff` between two snapshots | No | Yes |
| Offline `--demo` and `--self-test` | Yes | Yes |

Neither version phones home, or claims to match CVEs by itself (that would be a later step on top of the inventory).

Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=sbom-snapshot-lite) ($99, one payment).

## Limits

- This is an inventory of the current Python environment, not a complete machine SBOM and not a vulnerability scanner.
- License strings are taken from package metadata (`License-Expression`, `License`, or a license classifier). They are only as accurate as that metadata.
- The JSON follows CycloneDX 1.5 as described in this README; this repository does not vendor the official schema or run an external schema validator.
- Duplicate distributions for the same normalized name are listed once.

## Tests

```bash
python3 test_sbom_snapshot_lite.py
python3 sbom_snapshot_lite.py --self-test
```

The tests are offline. No network needed.

## Other free tools from the same author

- [agentconfig-audit-lite](https://github.com/alessio1999xx-debug/agentconfig-audit-lite) — Audit MCP config for secrets: plaintext tokens and unpinned npx/uvx servers in `.mcp.json` and `CLAUDE.md`.
- [agenttrail-scrub-lite](https://github.com/alessio1999xx-debug/agenttrail-scrub-lite) — Claude Code secret scanner: find API keys and tokens leaked in AI agent transcripts.
- [cronpulse-lite](https://github.com/alessio1999xx-debug/cronpulse-lite) — Cron job monitoring in one Python file: alerts on failure or hang.
- [depcooldown-lite](https://github.com/alessio1999xx-debug/depcooldown-lite) — Dependency cooldown check: fail CI when a pinned PyPI or npm package is newer than N days.
- [homelab-doctor-lite](https://github.com/alessio1999xx-debug/homelab-doctor-lite) — Read-only homelab health check: stale images, exposed ports, expiring certs, silent cron, disk.
- [imagenudge-lite](https://github.com/alessio1999xx-debug/imagenudge-lite) — Docker image update checker: find running containers with a newer image (digest or tag).
- [pthguard-lite](https://github.com/alessio1999xx-debug/pthguard-lite) — Scan Python site-packages for malicious `.pth` files and startup backdoors.
- [pulseping-lite](https://github.com/alessio1999xx-debug/pulseping-lite) — Check SSL certificate expiry and URL/port uptime from cron.
- [portexpose-lite](https://github.com/alessio1999xx-debug/portexpose-lite) — Find Docker Compose ports that publish past UFW, including exposed databases.
- [secenv-lite](https://github.com/alessio1999xx-debug/secenv-lite) — Find `.env` files committed to git or missing from `.gitignore`, plus obvious API keys inside.
- [ssh-keyaudit-lite](https://github.com/alessio1999xx-debug/ssh-keyaudit-lite) — Audit authorized_keys: SHA256 fingerprints; flags DSA, weak RSA, no comment and invalid lines.

## License

MIT (this lite version). The full SBOM Snapshot is sold separately under its own license.
