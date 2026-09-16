"""
Step 9.6 — Null Browser Firefox Branding Integration Tests

Validates:
1. Null branding directory (browser/branding/null/) exists.
2. All required branding files exist (configure.sh, moz.build, branding.nsi, manifests, icons, content, locales).
3. Required brand strings are present (Null, Null Browser, Null Project).
4. No production Null branding asset references the old Firefox logo.
5. Production SVG assets contain no external resources or embedded raster data.
6. Branding assets match their expected dimensions.
7. SHA-256 integrity matches the root production branding assets.
8. The selected branding directory is actually used by the configured build (confvars.sh and config.status).
9. Built Firefox artifacts contain Null Browser branding (brand.ftl, brand.properties, VisualElements, embedded PE icon).
"""

import os
import json
import hashlib
import struct
import unittest
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ROOT_BRANDING = os.path.join(REPO_ROOT, "branding")
FIREFOX_ROOT = os.path.join(REPO_ROOT, "firefox")
NULL_BRANDING_DIR = os.path.join(FIREFOX_ROOT, "browser", "branding", "null")
OBJDIR = os.path.abspath(os.path.join(REPO_ROOT, "..", "Null-Browser-build", "obj-firefox"))


class TestFirefoxBrandingIntegration(unittest.TestCase):

    def test_01_null_branding_directory_exists(self):
        """Verify that browser/branding/null/ exists and contains required subdirectories."""
        self.assertTrue(os.path.isdir(NULL_BRANDING_DIR), f"Missing: {NULL_BRANDING_DIR}")
        for subdir in ["content", "locales", os.path.join("locales", "en-US"), "pref"]:
            p = os.path.join(NULL_BRANDING_DIR, subdir)
            self.assertTrue(os.path.isdir(p), f"Missing subdirectory: {p}")

    def test_02_required_branding_files_exist(self):
        """Verify all build-required files exist in browser/branding/null/."""
        required_files = [
            "configure.sh",
            "moz.build",
            "branding.nsi",
            "firefox.ico",
            "firefox64.ico",
            "document.ico",
            "document_pdf.ico",
            "newtab.ico",
            "newwindow.ico",
            "pbmode.ico",
            "firefox.VisualElementsManifest.xml",
            "private_browsing.VisualElementsManifest.xml",
            "VisualElements_70.png",
            "VisualElements_150.png",
            "PrivateBrowsing_70.png",
            "PrivateBrowsing_150.png",
            "default16.png",
            "default22.png",
            "default24.png",
            "default32.png",
            "default48.png",
            "default64.png",
            "default128.png",
            "default256.png",
            "wizHeader.bmp",
            "wizHeaderRTL.bmp",
            "wizWatermark.bmp",
            os.path.join("content", "moz.build"),
            os.path.join("content", "jar.mn"),
            os.path.join("content", "about-logo.png"),
            os.path.join("content", "about-logo@2x.png"),
            os.path.join("content", "about-logo.svg"),
            os.path.join("content", "about-wordmark.svg"),
            os.path.join("content", "firefox-wordmark.svg"),
            os.path.join("content", "aboutDialog.css"),
            os.path.join("locales", "moz.build"),
            os.path.join("locales", "jar.mn"),
            os.path.join("locales", "en-US", "brand.ftl"),
            os.path.join("locales", "en-US", "brand.properties"),
            os.path.join("pref", "firefox-branding.js"),
        ]
        for rel in required_files:
            p = os.path.join(NULL_BRANDING_DIR, rel)
            self.assertTrue(os.path.isfile(p), f"Missing required branding file: {rel}")

    def test_03_brand_strings_values(self):
        """Verify brand strings in brand.ftl, brand.properties, and configure.sh."""
        # 1. brand.ftl
        ftl_path = os.path.join(NULL_BRANDING_DIR, "locales", "en-US", "brand.ftl")
        with open(ftl_path, "r", encoding="utf-8") as f:
            ftl_content = f.read()
        self.assertIn("-brand-shorter-name = Null", ftl_content)
        self.assertIn("-brand-short-name = Null", ftl_content)
        self.assertIn("-brand-full-name = Null Browser", ftl_content)
        self.assertIn("-brand-product-name = Null Browser", ftl_content)
        self.assertIn("-vendor-short-name = Null Project", ftl_content)

        # 2. brand.properties
        prop_path = os.path.join(NULL_BRANDING_DIR, "locales", "en-US", "brand.properties")
        with open(prop_path, "r", encoding="utf-8") as f:
            prop_content = f.read()
        self.assertIn("brandShorterName=Null", prop_content)
        self.assertIn("brandShortName=Null", prop_content)
        self.assertIn("brandFullName=Null Browser", prop_content)

        # 3. configure.sh
        conf_path = os.path.join(NULL_BRANDING_DIR, "configure.sh")
        with open(conf_path, "r", encoding="utf-8") as f:
            conf_content = f.read()
        self.assertIn('MOZ_APP_DISPLAYNAME="Null Browser"', conf_content)

    def test_04_no_firefox_logo_in_production_null_branding(self):
        """Verify that null branding assets do not contain the old Firefox logo."""
        with open(os.path.join(NULL_BRANDING_DIR, "content", "about-logo.svg"), "r", encoding="utf-8") as f:
            emblem_content = f.read()
        self.assertIn("emblem-glyph", emblem_content)
        self.assertNotIn("firefox", emblem_content.lower())

        with open(os.path.join(NULL_BRANDING_DIR, "content", "about-wordmark.svg"), "r", encoding="utf-8") as f:
            wm_content = f.read()
        self.assertNotIn("firefox", wm_content.lower())

    def test_05_production_svgs_self_contained(self):
        """Verify SVG assets parse as XML and contain 0 external URLs or embedded images."""
        svg_files = [
            os.path.join(NULL_BRANDING_DIR, "content", "about-logo.svg"),
            os.path.join(NULL_BRANDING_DIR, "content", "about-wordmark.svg"),
            os.path.join(NULL_BRANDING_DIR, "content", "firefox-wordmark.svg"),
        ]
        for p in svg_files:
            with open(p, "r", encoding="utf-8") as f:
                content = f.read()
            root = ET.fromstring(content)
            self.assertNotIn("data:image", content)
            for elem in root.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                self.assertNotEqual(tag.lower(), "image")
                for k, v in elem.attrib.items():
                    if any(sub in k.lower() for sub in ["href", "src", "url"]):
                        self.assertNotIn("http://", v.lower())
                        self.assertNotIn("https://", v.lower())

    def test_06_branding_assets_match_dimensions(self):
        """Verify dimensions of branding PNG assets."""
        expected_dims = {
            "default16.png": (16, 16),
            "default22.png": (22, 22),
            "default24.png": (24, 24),
            "default32.png": (32, 32),
            "default48.png": (48, 48),
            "default64.png": (64, 64),
            "default128.png": (128, 128),
            "default256.png": (256, 256),
            "VisualElements_70.png": (142, 142),
            "VisualElements_150.png": (300, 300),
            os.path.join("content", "about-logo.png"): (192, 192),
            os.path.join("content", "about-logo@2x.png"): (384, 384),
        }
        for rel, (exp_w, exp_h) in expected_dims.items():
            p = os.path.join(NULL_BRANDING_DIR, rel)
            with open(p, "rb") as f:
                header = f.read(26)
            self.assertEqual(header[:8], b'\x89PNG\r\n\x1a\n')
            w, h, bitdepth, colortype = struct.unpack(">IIBB", header[16:26])
            self.assertEqual((w, h), (exp_w, exp_h), f"Dimension mismatch in {rel}")
            self.assertEqual(colortype, 6, f"Expected 32bpp RGBA in {rel}")

    def test_07_sha256_matches_root_production_assets(self):
        """Verify SHA-256 digests match root branding assets."""
        pairs = [
            (os.path.join(NULL_BRANDING_DIR, "content", "about-logo.svg"), os.path.join(ROOT_BRANDING, "source", "null-emblem.svg")),
            (os.path.join(NULL_BRANDING_DIR, "content", "about-wordmark.svg"), os.path.join(ROOT_BRANDING, "source", "null-wordmark.svg")),
            (os.path.join(NULL_BRANDING_DIR, "default16.png"), os.path.join(ROOT_BRANDING, "raster", "app-icon-16.png")),
            (os.path.join(NULL_BRANDING_DIR, "default32.png"), os.path.join(ROOT_BRANDING, "raster", "app-icon-32.png")),
            (os.path.join(NULL_BRANDING_DIR, "default256.png"), os.path.join(ROOT_BRANDING, "raster", "app-icon-256.png")),
            (os.path.join(NULL_BRANDING_DIR, "VisualElements_70.png"), os.path.join(ROOT_BRANDING, "raster", "visual-elements-70.png")),
            (os.path.join(NULL_BRANDING_DIR, "VisualElements_150.png"), os.path.join(ROOT_BRANDING, "raster", "visual-elements-150.png")),
        ]
        for null_p, root_p in pairs:
            with open(null_p, "rb") as f1, open(root_p, "rb") as f2:
                h1 = hashlib.sha256(f1.read()).hexdigest()
                h2 = hashlib.sha256(f2.read()).hexdigest()
            self.assertEqual(h1, h2, f"SHA mismatch between {null_p} and {root_p}")

    def test_08_selected_branding_directory_configured(self):
        """Verify that browser/confvars.sh selects browser/branding/null and objdir config matches."""
        confvars_path = os.path.join(FIREFOX_ROOT, "browser", "confvars.sh")
        with open(confvars_path, "r", encoding="utf-8") as f:
            confvars = f.read()
        self.assertIn("MOZ_BRANDING_DIRECTORY=browser/branding/null", confvars)

        config_status = os.path.join(OBJDIR, "config.status")
        if os.path.isfile(config_status):
            with open(config_status, "r", encoding="utf-8", errors="ignore") as f:
                cs = f.read()
            self.assertIn("'MOZ_BRANDING_DIRECTORY': 'browser/branding/null'", cs)

    def test_09_build_artifacts_contain_null_branding(self):
        """Verify build output in dist/bin contains Null Browser branding resources."""
        dist_bin = os.path.join(OBJDIR, "dist", "bin")
        if not os.path.isdir(dist_bin):
            self.skipTest(f"dist/bin not found at {dist_bin}")

        # 1. VisualElements in dist/bin
        ve150 = os.path.join(dist_bin, "browser", "VisualElements", "VisualElements_150.png")
        self.assertTrue(os.path.isfile(ve150), f"Missing {ve150}")
        with open(ve150, "rb") as f1, open(os.path.join(ROOT_BRANDING, "raster", "visual-elements-150.png"), "rb") as f2:
            h_ve150 = hashlib.sha256(f1.read()).hexdigest()
            h_root150 = hashlib.sha256(f2.read()).hexdigest()
        self.assertEqual(h_ve150, h_root150)

        # 2. Packaged brand strings in dist/bin
        brand_ftl = os.path.join(dist_bin, "browser", "localization", "en-US", "branding", "brand.ftl")
        if os.path.isfile(brand_ftl):
            with open(brand_ftl, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("-brand-full-name = Null Browser", content)
            self.assertIn("-vendor-short-name = Null Project", content)

        brand_prop = os.path.join(dist_bin, "browser", "chrome", "en-US", "locale", "branding", "brand.properties")
        if os.path.isfile(brand_prop):
            with open(brand_prop, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("brandFullName=Null Browser", content)

        # 3. firefox.exe icon resource contains 256x256 Null Browser icon
        exe_path = os.path.join(dist_bin, "firefox.exe")
        self.assertTrue(os.path.isfile(exe_path), f"Missing {exe_path}")
        with open(exe_path, "rb") as f:
            exe_data = f.read()
        with open(os.path.join(ROOT_BRANDING, "raster", "app-icon-256.png"), "rb") as f:
            icon256 = f.read()
        self.assertIn(icon256[:64], exe_data, "Null Browser 256x256 icon PNG signature missing from firefox.exe")

    def test_10_runtime_gecko_branding_strings_and_assets(self):
        """Verify that the Gecko runtime loads Null Browser brand properties and chrome branding resources."""
        import tempfile
        import subprocess
        xpcshell = os.path.join(OBJDIR, "dist", "bin", "xpcshell.exe")
        dist_bin = os.path.join(OBJDIR, "dist", "bin")
        browser_dir = os.path.join(dist_bin, "browser")
        if not os.path.isfile(xpcshell):
            self.skipTest(f"xpcshell not found at {xpcshell}")

        js_code = """
        const { classes: Cc, interfaces: Ci } = Components;
        try {
            let sbs = Cc['@mozilla.org/intl/stringbundle;1'].getService(Ci.nsIStringBundleService);
            let bundle = sbs.createBundle('chrome://branding/locale/brand.properties');
            let io = Cc['@mozilla.org/network/io-service;1'].getService(Ci.nsIIOService);
            let uri = io.newURI('chrome://branding/content/about-logo.png');
            let channel = io.newChannelFromURI(uri, null, Cc['@mozilla.org/systemprincipal;1'].createInstance(Ci.nsIPrincipal), null, Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL, Ci.nsIContentPolicy.TYPE_IMAGE);
            let stream = channel.open();
            let count = stream.available();
            stream.close();
            let results = {
                brandShortName: bundle.GetStringFromName('brandShortName'),
                brandFullName: bundle.GetStringFromName('brandFullName'),
                brandShorterName: bundle.GetStringFromName('brandShorterName'),
                aboutLogoPngBytes: count
            };
            print('JSON_RESULT:' + JSON.stringify(results));
        } catch(e) {
            print('ERROR:' + e.toString());
        }
        quit(0);
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as f:
            f.write(js_code)
            script_path = f.name

        try:
            cmd = [xpcshell, "-g", dist_bin, "-a", browser_dir, "-f", script_path]
            proc = subprocess.run(cmd, cwd=dist_bin, capture_output=True, text=True, timeout=15)
            parsed = None
            for line in proc.stdout.splitlines():
                if line.startswith("JSON_RESULT:"):
                    parsed = json.loads(line[len("JSON_RESULT:"):])
                    break
            self.assertIsNotNone(parsed, f"No JSON_RESULT in output:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
            self.assertEqual(parsed["brandShortName"], "Null")
            self.assertEqual(parsed["brandFullName"], "Null Browser")
            self.assertEqual(parsed["brandShorterName"], "Null")
            self.assertEqual(parsed["aboutLogoPngBytes"], 19606)
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)


if __name__ == "__main__":
    unittest.main()
