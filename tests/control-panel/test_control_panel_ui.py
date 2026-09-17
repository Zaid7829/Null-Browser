# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Null Browser Control Panel UI Regression Tests
Validates the visible Control Panel dashboard UI at about:null / about:controlpanel.
Ensures:
- Semantic dashboard structure and 8 required sections render
- Diagnostics populate safely from privileged IPC
- Configuration vs. runtime/observed states are clearly labeled
- Sensitive information (IPs, ports, paths, PIDs, URLs) is strictly excluded
- Zero synthetic scores, percentages, or fake gauges exist
- IPC failure produces an explicit unavailable state
- Keyboard and accessibility requirements are met
- Zero external resources are loaded
- Built Firefox runtime successfully renders about:null
"""

import json
import os
import subprocess
import tempfile
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIREFOX_SRC = os.path.join(ROOT_DIR, "firefox")
BUILD_DIR = os.path.join(ROOT_DIR, "..", "Null-Browser-build", "obj-firefox")
FIREFOX_EXE = os.path.join(BUILD_DIR, "dist", "bin", "firefox.exe")
XPCSHELL_EXE = os.path.join(BUILD_DIR, "dist", "bin", "xpcshell.exe")

CP_DIR = os.path.join(FIREFOX_SRC, "browser", "components", "controlpanel")
CP_XHTML = os.path.join(CP_DIR, "controlpanel.xhtml")
CP_CSS = os.path.join(CP_DIR, "controlpanel.css")
CP_JS = os.path.join(CP_DIR, "controlpanel.js")


def run_xpcshell_script(js_code):
    """Helper to run JavaScript inside xpcshell environment."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js_code)
        temp_path = f.name

    try:
        proc = subprocess.run(
            [XPCSHELL_EXE, "-f", temp_path],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=os.path.join(BUILD_DIR, "dist", "bin")
        )
        for line in proc.stdout.splitlines():
            if line.startswith("JSON_RESULT:"):
                return json.loads(line[len("JSON_RESULT:"):])
        if proc.returncode != 0:
            raise RuntimeError(f"xpcshell failed (code {proc.returncode}): {proc.stderr}\nOutput: {proc.stdout}")
        return None
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


class TestControlPanelUI(unittest.TestCase):

    def setUp(self):
        self.assertTrue(os.path.isfile(CP_XHTML), f"Missing {CP_XHTML}")
        self.assertTrue(os.path.isfile(CP_CSS), f"Missing {CP_CSS}")
        self.assertTrue(os.path.isfile(CP_JS), f"Missing {CP_JS}")

        with open(CP_XHTML, "r", encoding="utf-8") as f:
            self.xhtml_content = f.read()

        with open(CP_CSS, "r", encoding="utf-8") as f:
            self.css_content = f.read()

        with open(CP_JS, "r", encoding="utf-8") as f:
            self.js_content = f.read()

    def test_01_dashboard_structure_and_semantic_html(self):
        """Verify the XHTML contains all 8 required dashboard sections, header, and branding."""
        # Header components
        self.assertIn('id="controlpanel-title"', self.xhtml_content)
        self.assertIn('id="header-logo"', self.xhtml_content)
        self.assertIn('chrome://branding/content/about-logo.svg', self.xhtml_content)
        self.assertIn('id="browser-mode-badge"', self.xhtml_content)
        self.assertIn('id="process-badge"', self.xhtml_content)
        self.assertIn('id="refresh-btn"', self.xhtml_content)
        self.assertIn('id="last-updated"', self.xhtml_content)
        self.assertIn('id="diagnostics-error"', self.xhtml_content)

        # 8 Dashboard Sections
        self.assertIn('id="section-browser-mode"', self.xhtml_content)
        self.assertIn('id="section-network-dns"', self.xhtml_content)
        self.assertIn('id="section-webrtc"', self.xhtml_content)
        self.assertIn('id="section-privacy"', self.xhtml_content)
        self.assertIn('id="section-content-protection"', self.xhtml_content)
        self.assertIn('id="section-permissions"', self.xhtml_content)
        self.assertIn('id="section-security-notes"', self.xhtml_content)

        # Backward compatibility IDs
        self.assertIn('id="brand-val"', self.xhtml_content)
        self.assertIn('data-testid="brand-val"', self.xhtml_content)
        self.assertIn('id="rfp-val"', self.xhtml_content)
        self.assertIn('data-testid="rfp-val"', self.xhtml_content)
        self.assertIn('id="pbm-val"', self.xhtml_content)
        self.assertIn('data-testid="pbm-val"', self.xhtml_content)

    def test_02_diagnostics_populate_from_ipc(self):
        """Verify client JS handles FetchDiagnostics IPC payload and populates DOM elements."""
        js_code = """
        // Mock DOM elements
        let elements = {};
        function createElem(id) {
            elements[id] = {
                id: id,
                textContent: "—",
                dataset: {},
                style: { display: "none" }
            };
            return elements[id];
        }

        const ids = [
            "brand-val", "rfp-val", "pbm-val", "browser-mode-badge", "last-updated", "diagnostics-error",
            "session-pbm-val", "ghost-mode-val", "tor-lifecycle-val",
            "proxy-mode-val", "tor-routing-val", "socks-remote-dns-val", "trr-mode-val",
            "ipv6-dns-val", "ipv6-blocked-val", "webrtc-status-val", "webrtc-udp-val",
            "webrtc-ice-val", "history-val", "passwords-val", "cookie-val",
            "disk-cache-val", "https-only-val", "telemetry-val", "geo-val",
            "tp-val", "cryptomining-val", "fp-val", "social-tp-val", "email-tp-val",
            "session-perms-count-val", "session-perms-types-val", "geo-policy-val"
        ];
        ids.forEach(createElem);

        let document = {
            getElementById(id) {
                return elements[id] || null;
            },
            readyState: "complete",
            addEventListener() {}
        };

        // Mock privileged RPMSendQuery
        let mockPayload = {
            brand: "Null Browser",
            rfpEnabled: true,
            privateBrowsingDefault: true,
            browserMode: {
                privateBrowsingDefaultConfigured: true,
                currentWindowPrivate: true,
                torRoutingConfigured: false,
                ghostLifecycleState: "DISABLED",
                ghostModeActive: false
            },
            network: {
                proxyType: 5,
                proxyTypeDescription: "system",
                socksVersion: 5,
                socksRemoteDNSConfigured: true,
                failoverDirect: true,
                trrMode: 3,
                trrStrictConfigured: true,
                ipv6DisabledConfigured: true,
                observedBlockedIPv6Count: 0,
                webrtcEnabled: true,
                webrtcIceProxyOnly: false,
                webrtcIceNoHostConfigured: true,
                webrtcObfuscateHostAddresses: true
            },
            privacyProtections: {
                rfpConfigured: true,
                historyDisabledConfigured: true,
                rememberSignonsDisabled: true,
                cookieBehavior: 5,
                diskCacheDisabledConfigured: true,
                httpsOnlyModeConfigured: true,
                telemetryDisabledConfigured: true,
                geoDisabledConfigured: true
            },
            contentProtection: {
                trackingProtectionConfigured: true,
                cryptominingProtectionConfigured: true,
                fingerprintingProtectionConfigured: true,
                socialTrackingProtectionConfigured: true,
                emailTrackingProtectionConfigured: true
            },
            permissions: {
                sessionPermissionsCount: 2,
                sessionPermissionTypes: { "camera": 1, "microphone": 1 },
                defaultGeoPolicy: 2
            }
        };

        async function RPMSendQuery(query) {
            if (query === "FetchDiagnostics") return mockPayload;
            throw new Error("Unknown query");
        }
        """ + self.js_content + """
        let done = false;
        fetchAndRenderDiagnostics().then(() => {
            let res = {
                brand: elements["brand-val"].textContent,
                rfp: elements["rfp-val"].textContent,
                pbm: elements["pbm-val"].textContent,
                browserMode: elements["browser-mode-badge"].textContent,
                proxyMode: elements["proxy-mode-val"].textContent,
                trrMode: elements["trr-mode-val"].textContent,
                ipv6Blocked: elements["ipv6-blocked-val"].textContent,
                webrtcUdp: elements["webrtc-udp-val"].textContent,
                history: elements["history-val"].textContent,
                cookie: elements["cookie-val"].textContent,
                permsCount: elements["session-perms-count-val"].textContent,
                permsTypes: elements["session-perms-types-val"].textContent,
                errorDisplay: elements["diagnostics-error"].style.display
            };
            dump("JSON_RESULT:" + JSON.stringify(res) + "\\n");
            done = true;
        }).catch(err => {
            dump("ERROR:" + err + "\\n");
            done = true;
        });

        while (!done) {
            Services.tm.currentThread.processNextEvent(true);
        }
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertIsNotNone(res, "xpcshell returned None for test_02")
        self.assertEqual(res["brand"], "Null Browser")
        self.assertEqual(res["rfp"], "Enabled (Configured - Strict RFP)")
        self.assertEqual(res["pbm"], "Configured (Autostart)")
        self.assertEqual(res["browserMode"], "Private Browsing")
        self.assertIn("system", res["proxyMode"])
        self.assertIn("Mode 3 (Strict DoH, Fail-Closed)", res["trrMode"])
        self.assertIn("0 attempts observed (runtime count)", res["ipv6Blocked"])
        self.assertIn("Non-Proxied UDP Blocked", res["webrtcUdp"])
        self.assertIn("Disabled (Configured)", res["history"])
        self.assertIn("Total Cookie Protection", res["cookie"])
        self.assertEqual(res["permsCount"], "2 active")
        self.assertIn("camera (1)", res["permsTypes"])
        self.assertIn("microphone (1)", res["permsTypes"])
        self.assertEqual(res["errorDisplay"], "none")

    def test_03_configured_vs_runtime_labels(self):
        """Verify configuration vs runtime/observed labels are distinctly maintained."""
        self.assertIn('class="meta-tag tag-config">Configured</span>', self.xhtml_content)
        self.assertIn('class="meta-tag tag-runtime">Runtime</span>', self.xhtml_content)
        self.assertIn('class="meta-tag tag-observed">Observed</span>', self.xhtml_content)

        # Section pills
        self.assertIn('pill-config', self.xhtml_content)
        self.assertIn('pill-runtime', self.xhtml_content)
        self.assertIn('pill-mixed', self.xhtml_content)

    def test_04_sensitive_fields_not_rendered(self):
        """Verify no sensitive information (IPs, ports, URLs, filesystem paths, PIDs) is rendered."""
        raw = (self.xhtml_content + " " + self.js_content).lower()
        clean_raw = (
            raw.replace("http://www.w3.org/1999/xhtml", "")
            .replace("http://mozilla.org/mpl/2.0/", "")
        )

        # Sensitive IP / loopback exposure in UI text
        self.assertNotIn("127.0.0.1", clean_raw)
        self.assertNotIn("9050", clean_raw)
        self.assertNotIn("9150", clean_raw)
        self.assertNotIn("localhost:9", clean_raw)

        # No resolver URLs or domain leakage
        self.assertNotIn("https://", clean_raw)
        self.assertNotIn("http://", clean_raw)

        # No filesystem paths or PIDs
        self.assertNotIn("c:\\", clean_raw)
        self.assertNotIn("/users/", clean_raw)
        self.assertNotIn("appdata", clean_raw)
        self.assertNotIn("pid:", clean_raw)
        self.assertNotIn("process id", clean_raw)

    def test_05_no_score_ranking_percentage_anonymity_ui(self):
        """Verify zero synthetic scores, percentages, rankings, or fake gauges exist."""
        raw = (self.xhtml_content + " " + self.js_content + " " + self.css_content).lower()

        # Prohibited absolute security claims and scores
        self.assertNotIn("100% secure", raw)
        self.assertNotIn("100% anonymous", raw)
        self.assertNotIn("anonymous", raw)
        self.assertNotIn("untraceable", raw)
        self.assertNotIn("leak-proof", raw)
        self.assertNotIn("zero leaks", raw)
        self.assertNotIn("guaranteed", raw)
        self.assertNotIn("zero pings", raw)
        self.assertNotIn("score", raw)
        self.assertNotIn("ranking", raw)
        self.assertNotIn("percentage", raw)
        self.assertNotIn("gauge", raw)
        self.assertNotIn("meter", raw)
        self.assertNotIn("privacy grade", raw)

    def test_06_ipc_failure_produces_unavailable_state(self):
        """Verify that when IPC fails, an explicit unavailable state is shown with no fabricated values."""
        js_code = """
        let elements = {};
        function createElem(id) {
            elements[id] = {
                id: id,
                textContent: "—",
                dataset: {},
                style: { display: "none" }
            };
            return elements[id];
        }

        const ids = [
            "brand-val", "rfp-val", "pbm-val", "browser-mode-badge", "last-updated", "diagnostics-error"
        ];
        ids.forEach(createElem);

        let document = {
            getElementById(id) {
                return elements[id] || null;
            },
            readyState: "complete",
            addEventListener() {}
        };

        // Simulate failing RPMSendQuery
        async function RPMSendQuery(query) {
            throw new Error("IPC disconnected");
        }
        """ + self.js_content + """
        let done = false;
        fetchAndRenderDiagnostics().then(() => {
            let res = {
                errorDisplay: elements["diagnostics-error"].style.display,
                lastUpdated: elements["last-updated"].textContent,
                modeBadge: elements["browser-mode-badge"].textContent,
                modeState: elements["browser-mode-badge"].dataset.state,
                brandVal: elements["brand-val"].textContent
            };
            dump("JSON_RESULT:" + JSON.stringify(res) + "\\n");
            done = true;
        }).catch(err => {
            dump("ERROR:" + err + "\\n");
            done = true;
        });

        while (!done) {
            Services.tm.currentThread.processNextEvent(true);
        }
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertIsNotNone(res, "xpcshell returned None for test_06")
        self.assertEqual(res["errorDisplay"], "flex", "Error banner must be shown on IPC failure")
        self.assertEqual(res["lastUpdated"], "Unavailable")
        self.assertEqual(res["modeBadge"], "Unavailable")
        self.assertEqual(res["modeState"], "error")
        self.assertNotEqual(res["brandVal"], "Null Browser", "Must not fabricate values on IPC failure")

    def test_07_keyboard_and_accessibility_basics(self):
        """Verify semantic headings, ARIA live attributes, and keyboard accessibility."""
        # Semantic HTML
        self.assertIn('lang="en"', self.xhtml_content)
        self.assertIn('<header', self.xhtml_content)
        self.assertIn('<main', self.xhtml_content)
        self.assertIn('<section', self.xhtml_content)
        self.assertIn('<dl', self.xhtml_content)
        self.assertIn('<dt', self.xhtml_content)
        self.assertIn('<dd', self.xhtml_content)

        # ARIA attributes
        self.assertIn('aria-live="polite"', self.xhtml_content)
        self.assertIn('role="alert"', self.xhtml_content)
        self.assertIn('aria-label="Refresh diagnostics"', self.xhtml_content)

        # Keyboard focus in CSS
        self.assertIn(':focus-visible', self.css_content)

    def test_08_no_external_resources(self):
        """Verify the page loads zero external fonts, scripts, CDNs, or network resources."""
        clean_xhtml = self.xhtml_content.replace("http://www.w3.org/1999/xhtml", "")
        clean_css = self.css_content.replace("http://mozilla.org/MPL/2.0/", "")

        # In XHTML
        self.assertNotIn("http://", clean_xhtml)
        self.assertNotIn("https://", clean_xhtml)
        self.assertNotIn("fonts.googleapis.com", self.xhtml_content)
        self.assertNotIn("cdnjs", self.xhtml_content)

        # In CSS
        self.assertNotIn("http://", clean_css)
        self.assertNotIn("https://", clean_css)
        self.assertNotIn("@import", self.css_content)
        self.assertNotIn("url(", self.css_content)

    def test_09_gecko_runtime_screenshot_renders_dashboard(self):
        """Verify the actual built Firefox Gecko binary renders about:null dashboard in headless mode."""
        with tempfile.TemporaryDirectory(prefix="test_cp_ui_prof_", ignore_cleanup_errors=True) as prof:
            out_png = os.path.join(prof, "dashboard_rendered.png")
            cmd = [
                FIREFOX_EXE,
                "-profile", prof,
                "-no-remote",
                "--headless",
                f"--screenshot={out_png}",
                "--window-size=1280,900",
                "about:null",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, f"Headless execution failed: {proc.stderr}")
            self.assertTrue(os.path.isfile(out_png), "Screenshot was not generated for about:null")
            file_size = os.path.getsize(out_png)
            # A rich dashboard screenshot with cards and typography is well over 30KB
            self.assertGreater(file_size, 30000, f"Screenshot file unexpectedly small: {file_size} bytes")


if __name__ == "__main__":
    unittest.main()
