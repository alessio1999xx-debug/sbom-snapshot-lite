#!/usr/bin/env python3
"""Offline tests for sbom-snapshot-lite."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

import sbom_snapshot_lite as sl


class BuildTests(unittest.TestCase):
    def test_demo_document_shape(self):
        rc = sl.main(["--demo"])
        self.assertEqual(rc, 0)

    def test_demo_to_file_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bom.json")
            rc = sl.main(["--demo", "-o", path])
            self.assertEqual(rc, 0)
            with open(path, encoding="utf-8") as fh:
                bom = json.load(fh)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        self.assertEqual(bom["serialNumber"], "urn:uuid:00000000-0000-4000-8000-000000000001")
        self.assertEqual(bom["metadata"]["timestamp"], "2026-11-25T00:00:00Z")
        self.assertEqual(bom["metadata"]["tools"][0]["name"], "sbom-snapshot-lite")
        self.assertEqual(len(bom["components"]), 3)
        names = [c["name"] for c in bom["components"]]
        self.assertEqual(names, ["certifi", "urllib3", "idna"])
        self.assertEqual(bom["components"][0]["purl"], "pkg:pypi/certifi@2024.2.2")
        self.assertEqual(bom["components"][0]["licenses"][0]["license"]["id"], "MPL-2.0")

    def test_normalize_and_license_name(self):
        self.assertEqual(sl.normalize_pypi_name("Ruamel.Yaml"), "ruamel-yaml")
        self.assertEqual(sl.normalize_pypi_name("Some_Package"), "some-package")
        comp = sl.component_from({"name": "Fancy_Lib", "version": "1.0", "license": "MIT License"})
        self.assertEqual(comp["name"], "fancy-lib")
        self.assertEqual(comp["purl"], "pkg:pypi/fancy-lib@1.0")
        # "MIT License" is not a short SPDX id, stored as name
        self.assertIn("name", comp["licenses"][0]["license"])

    def test_mit_spdx_id(self):
        comp = sl.component_from({"name": "x", "version": "1", "license": "MIT"})
        self.assertEqual(comp["licenses"][0]["license"]["id"], "MIT")

    def test_self_test(self):
        self.assertEqual(sl.main(["--self-test"]), 0)

    def test_collect_installed_includes_this_stdlib_run(self):
        rows = sl.collect_installed()
        self.assertIsInstance(rows, list)
        # The running interpreter should see at least pip or the test package set,
        # but a truly empty env is allowed. Just check shape.
        for r in rows:
            self.assertTrue(r["name"])
            self.assertIn("version", r)

    def test_live_scan_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "live.json")
            rc = sl.main(["-o", path, "--doc-name", "Test env"])
            self.assertEqual(rc, 0)
            with open(path, encoding="utf-8") as fh:
                bom = json.load(fh)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        self.assertTrue(bom["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(bom["metadata"]["component"]["name"], "Test env")
        self.assertIsInstance(bom["components"], list)
        for c in bom["components"]:
            self.assertEqual(c["type"], "library")
            self.assertTrue(c["purl"].startswith("pkg:pypi/"))


if __name__ == "__main__":
    unittest.main()
