"""
Step 9.5 — Null Browser Branding Asset Verification Tests

Verifies all production branding assets:
1. Every asset referenced in manifest.json exists on disk.
2. Production SVGs parse as valid XML without syntax errors.
3. Production SVGs contain 0 external URLs and 0 embedded raster data.
4. Production PNGs match exact required pixel dimensions.
5. Production PNGs preserve alpha transparency (32bpp RGBA).
6. Manifest SHA-256 digests strictly match disk contents.
"""

import os
import json
import hashlib
import struct
import unittest
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BRANDING_DIR = os.path.join(REPO_ROOT, "branding")
MANIFEST_PATH = os.path.join(BRANDING_DIR, "manifest.json")


class TestBrandingAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.assertTrue(os.path.isfile(MANIFEST_PATH), f"Missing manifest: {MANIFEST_PATH}")
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            cls.manifest = json.load(f)

    def test_01_manifest_structure_and_count(self):
        """Verify branding manifest schema, metadata, and asset count."""
        self.assertEqual(self.manifest.get("schema_version"), "1.0.0")
        self.assertEqual(self.manifest.get("project"), "Null Browser")
        self.assertEqual(self.manifest.get("asset_count"), 16)
        assets = self.manifest.get("assets", [])
        self.assertEqual(len(assets), 16)

    def test_02_all_files_exist_and_sha256_match(self):
        """Verify that every manifest asset exists and matches its recorded SHA-256 digest."""
        assets = self.manifest.get("assets", [])
        for entry in assets:
            rel_path = entry["asset_path"]
            expected_sha = entry["sha256"]
            full_path = os.path.join(REPO_ROOT, rel_path.replace("/", os.sep))
            self.assertTrue(os.path.isfile(full_path), f"Asset file missing: {rel_path}")

            hasher = hashlib.sha256()
            with open(full_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            actual_sha = hasher.hexdigest()
            self.assertEqual(actual_sha, expected_sha, f"SHA-256 mismatch for {rel_path}")

    def test_03_svg_source_assets_valid_xml_and_no_external_resources(self):
        """Verify production SVGs parse, contain no external URLs, and contain no embedded rasters."""
        svg_assets = [
            "branding/source/null-emblem.svg",
            "branding/source/null-wordmark.svg",
            "branding/source/null-lockup.svg",
        ]
        for rel_path in svg_assets:
            full_path = os.path.join(REPO_ROOT, rel_path.replace("/", os.sep))
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()

            # 1. Valid XML parse
            try:
                root = ET.fromstring(content)
            except ET.ParseError as e:
                self.fail(f"SVG failed XML parse in {rel_path}: {e}")

            # 2. No embedded raster <image>
            for elem in root.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                self.assertNotEqual(tag.lower(), "image", f"Embedded <image> found in {rel_path}")

            # 3. No base64 data URIs
            self.assertNotIn("data:image", content, f"Embedded base64 data URI in {rel_path}")

            # 4. No external network references
            for elem in root.iter():
                for k, v in elem.attrib.items():
                    if any(sub in k.lower() for sub in ["href", "src", "url"]):
                        self.assertNotIn("http://", v.lower(), f"External HTTP URL found in {rel_path} attribute {k}")
                        self.assertNotIn("https://", v.lower(), f"External HTTPS URL found in {rel_path} attribute {k}")

    def test_04_png_dimensions_and_alpha_channels(self):
        """Verify exact PNG dimensions, bit-depth, and alpha transparency channels."""
        expected_specs = {
            "branding/reference/null-browser-approved.png": (1024, 1024, False),
            "branding/raster/app-icon-16.png": (16, 16, True),
            "branding/raster/app-icon-22.png": (22, 22, True),
            "branding/raster/app-icon-24.png": (24, 24, True),
            "branding/raster/app-icon-32.png": (32, 32, True),
            "branding/raster/app-icon-48.png": (48, 48, True),
            "branding/raster/app-icon-64.png": (64, 64, True),
            "branding/raster/app-icon-128.png": (128, 128, True),
            "branding/raster/app-icon-256.png": (256, 256, True),
            "branding/raster/about-logo-192.png": (192, 192, True),
            "branding/raster/about-logo-384.png": (384, 384, True),
            "branding/raster/visual-elements-70.png": (142, 142, True),
            "branding/raster/visual-elements-150.png": (300, 300, True),
        }
        for rel_path, (exp_w, exp_h, req_alpha) in expected_specs.items():
            full_path = os.path.join(REPO_ROOT, rel_path.replace("/", os.sep))
            with open(full_path, "rb") as f:
                header = f.read(26)
            self.assertEqual(header[:8], b'\x89PNG\r\n\x1a\n', f"Not a valid PNG: {rel_path}")
            w, h, bitdepth, colortype = struct.unpack(">IIBB", header[16:26])
            self.assertEqual((w, h), (exp_w, exp_h), f"Dimensions mismatch for {rel_path}: got ({w}, {h})")
            if req_alpha:
                # colortype 6 = RGBA (32bpp)
                self.assertEqual(colortype, 6, f"Expected RGBA (colortype=6) for {rel_path}, got {colortype}")
                self.assertEqual(bitdepth, 8, f"Expected 8 bits per channel for {rel_path}")


if __name__ == "__main__":
    unittest.main()
