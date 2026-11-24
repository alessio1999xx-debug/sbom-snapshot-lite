#!/usr/bin/env python3
"""sbom-snapshot-lite: CycloneDX 1.5 SBOM of the current Python environment.

Offline, read-only, standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    import importlib_metadata  # type: ignore

__version__ = "0.1.0"

SPEC_VERSION = "1.5"
TOOL_NAME = "sbom-snapshot-lite"

DEMO_PACKAGES = [
    {"name": "certifi", "version": "2024.2.2", "license": "MPL-2.0"},
    {"name": "urllib3", "version": "2.2.1", "license": "MIT"},
    {"name": "idna", "version": "3.7", "license": "BSD-3-Clause"},
]


def normalize_pypi_name(name: str) -> str:
    """PEP 503 / Package-URL name: lowercase, runs of -_. replaced by '-'."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def iso_utc_now() -> str:
    # Python 3.8: datetime.utcnow is aware via replace
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _license_of(meta: Any) -> Optional[str]:
    if meta is None:
        return None
    # importlib.metadata.PackageMetadata supports get()
    getter = meta.get if hasattr(meta, "get") else lambda k, d=None: d
    expr = (getter("License-Expression") or "").strip()
    if expr:
        return expr
    license_field = (getter("License") or "").strip()
    if license_field:
        # classifiers sometimes leak into License as a paragraph; keep a short token
        first = license_field.splitlines()[0].strip()
        if first and len(first) <= 80 and "\n" not in first:
            return first
    # classifiers: License :: OSI Approved :: MIT License
    get_all = getattr(meta, "get_all", None)
    classifiers = get_all("Classifier") if callable(get_all) else []
    for c in classifiers or []:
        if c.startswith("License ::") and not c.endswith("OSI Approved"):
            return c.split("::")[-1].strip()
    return None


def collect_installed() -> List[Dict[str, Optional[str]]]:
    seen = set()
    rows: List[Dict[str, Optional[str]]] = []
    for dist in importlib_metadata.distributions():
        try:
            name = dist.metadata["Name"] if dist.metadata and "Name" in dist.metadata else (
                getattr(dist, "name", None) or ""
            )
        except Exception:
            name = getattr(dist, "name", "") or ""
        name = str(name).strip()
        if not name:
            continue
        key = normalize_pypi_name(name)
        if key in seen:
            continue
        seen.add(key)
        version = ""
        try:
            version = dist.version or ""
        except Exception:
            version = ""
        try:
            license_name = _license_of(dist.metadata)
        except Exception:
            license_name = None
        rows.append({"name": name, "version": str(version), "license": license_name})
    rows.sort(key=lambda r: normalize_pypi_name(r["name"] or ""))
    return rows


def component_from(row: Dict[str, Optional[str]]) -> Dict[str, Any]:
    name = row["name"] or "unknown"
    version = row.get("version") or ""
    nname = normalize_pypi_name(name)
    purl = "pkg:pypi/%s" % nname
    if version:
        purl = "%s@%s" % (purl, version)
    comp: Dict[str, Any] = {
        "type": "library",
        "name": nname,
        "purl": purl,
    }
    if version:
        comp["version"] = version
    lic = row.get("license")
    if lic:
        # CycloneDX 1.5 license choice: license.id if it looks like an SPDX id, else license.name
        if re.fullmatch(r"[A-Za-z0-9.\-+]+", lic) and any(ch in lic for ch in ("-", ".")) or lic in {
            "MIT", "ISC", "MPL-2.0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "PSF-2.0", "Unlicense",
            "Zlib", "CC0-1.0",
        }:
            entry = {"license": {"id": lic}}
        else:
            entry = {"license": {"name": lic}}
        # MIT is a valid SPDX id
        if lic == "MIT":
            entry = {"license": {"id": "MIT"}}
        comp["licenses"] = [entry]
    return comp


def build_bom(
    rows: List[Dict[str, Optional[str]]],
    doc_name: str = "Python environment",
    timestamp: Optional[str] = None,
    serial: Optional[str] = None,
) -> Dict[str, Any]:
    ts = timestamp or iso_utc_now()
    serial = serial or ("urn:uuid:%s" % uuid.uuid4())
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [
                {
                    "vendor": "PyForge",
                    "name": TOOL_NAME,
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": doc_name,
                "version": "1.0.0",
            },
        },
        "components": [component_from(r) for r in rows],
    }


def render(bom: Dict[str, Any]) -> str:
    return json.dumps(bom, indent=2, sort_keys=False) + "\n"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sbom-snapshot-lite",
        description=(
            "Write a CycloneDX 1.5 JSON SBOM of the Python packages installed "
            "in the current environment. Offline, no extra packages."
        ),
    )
    p.add_argument("-V", "--version", action="version", version="sbom-snapshot-lite %s" % __version__)
    p.add_argument("-o", "--output", metavar="FILE", help="Write JSON to FILE instead of stdout")
    p.add_argument("--doc-name", default="Python environment", help="metadata.component.name (default: Python environment)")
    p.add_argument("--demo", action="store_true", help="Write a built-in sample SBOM (no environment scan) and exit")
    p.add_argument("--self-test", action="store_true", help="Run the built-in tests and exit")
    return p


def _write(text: str, path: Optional[str]) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


def _self_test() -> int:
    # Deterministic fixture document
    bom = build_bom(
        DEMO_PACKAGES,
        doc_name="Demo Environment",
        timestamp="2026-11-25T00:00:00Z",
        serial="urn:uuid:00000000-0000-4000-8000-000000000001",
    )
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert len(bom["components"]) == 3
    cert = bom["components"][0]
    assert cert["name"] == "certifi"
    assert cert["version"] == "2024.2.2"
    assert cert["purl"] == "pkg:pypi/certifi@2024.2.2"
    assert cert["licenses"][0]["license"]["id"] == "MPL-2.0"
    # name normalization
    row = {"name": "Ruamel.Yaml", "version": "0.18.0", "license": None}
    comp = component_from(row)
    assert comp["name"] == "ruamel-yaml"
    assert comp["purl"] == "pkg:pypi/ruamel-yaml@0.18.0"
    # missing version
    comp2 = component_from({"name": "foo", "version": "", "license": None})
    assert comp2["purl"] == "pkg:pypi/foo"
    assert "version" not in comp2
    # JSON round-trip
    parsed = json.loads(render(bom))
    assert parsed["metadata"]["tools"][0]["name"] == TOOL_NAME
    # Live collector returns a list (may be empty in a bare venv)
    live = collect_installed()
    assert isinstance(live, list)
    print("sbom-snapshot-lite self-test: 6 checks passed (CycloneDX 1.5, purl, licenses, normalize, live collector).")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        try:
            return _self_test()
        except AssertionError as exc:
            print("sbom-snapshot-lite self-test failed: %s" % exc, file=sys.stderr)
            return 2
    if args.demo:
        bom = build_bom(
            DEMO_PACKAGES,
            doc_name="Demo Environment",
            timestamp="2026-11-25T00:00:00Z",
            serial="urn:uuid:00000000-0000-4000-8000-000000000001",
        )
        _write(render(bom), args.output)
        return 0
    try:
        rows = collect_installed()
        bom = build_bom(rows, doc_name=args.doc_name)
        _write(render(bom), args.output)
        return 0
    except OSError as exc:
        print("sbom-snapshot-lite: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
