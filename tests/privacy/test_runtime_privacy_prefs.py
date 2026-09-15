"""
Integration test for Null Browser Step 5 Runtime Privacy Configuration.
Executes the Gecko preference engine via xpcshell linked against the active
Firefox ESR 153.4.0 build binary to verify that all default preferences
are evaluated and enforced in the live runtime.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest

DIST_BIN = r"C:\Users\Zaid\Projects\Null-Browser-build\obj-firefox\dist\bin"
XPCSHELL_EXE = os.path.join(DIST_BIN, "xpcshell.exe")
BROWSER_DIR = os.path.join(DIST_BIN, "browser")


def query_runtime_prefs():
    """Execute xpcshell to extract live default preference states."""
    js_code = """
    function getPrefVal(branch, name, type) {
        try {
            if (type === "bool") return branch.getBoolPref(name);
            if (type === "int") return branch.getIntPref(name);
            if (type === "string") return branch.getStringPref(name);
        } catch (e) {
            return null;
        }
        return null;
    }

    let p = Services.prefs;
    let queryList = [
        ["browser.privatebrowsing.autostart", "bool"],
        ["browser.privatebrowsing.forceMediaMemoryCache", "bool"],
        ["places.history.enabled", "bool"],
        ["browser.formfill.enable", "bool"],
        ["browser.sessionstore.privacy_level", "int"],
        ["browser.sessionstore.resume_from_crash", "bool"],
        ["browser.places.speculativeConnect.enabled", "bool"],
        ["signon.rememberSignons", "bool"],
        ["signon.autofillForms", "bool"],
        ["signon.generation.enabled", "bool"],
        ["signon.formlessCapture.enabled", "bool"],
        ["signon.privateBrowsingCapture.enabled", "bool"],
        ["signon.capture.inputChanges.enabled", "bool"],
        ["signon.formRemovalCapture.enabled", "bool"],
        ["signon.storeWhenAutocompleteOff", "bool"],
        ["network.cookie.cookieBehavior", "int"],
        ["network.cookie.cookieBehavior.pbmode", "int"],
        ["browser.cache.disk.enable", "bool"],
        ["browser.cache.disk_cache_ssl", "bool"],
        ["browser.cache.memory.enable", "bool"],
        ["dom.security.https_only_mode", "bool"],
        ["dom.security.https_only_mode_pbm", "bool"],
        ["dom.security.https_only_mode_error_page_user_suggestions", "bool"],
        ["dom.security.https_only_mode_send_http_background_request", "bool"],
        ["network.trr.mode", "int"],
        ["network.trr.uri", "string"],
        ["network.trr.default_provider_uri", "string"],
        ["network.dns.disableIPv6", "bool"],
        ["network.dns.preferIPv6", "bool"],
        ["media.peerconnection.ice.no_host", "bool"],
        ["media.peerconnection.ice.default_address_only", "bool"],
        ["media.peerconnection.ice.proxy_only", "bool"],
        ["media.peerconnection.ice.proxy_only_if_pbmode", "bool"],
        ["media.peerconnection.ice.proxy_only_if_behind_proxy", "bool"],
        ["media.peerconnection.ice.obfuscate_host_addresses", "bool"],
        ["privacy.resistFingerprinting", "bool"],
        ["privacy.resistFingerprinting.pbmode", "bool"],
        ["privacy.resistFingerprinting.block_mozAddonManager", "bool"],
        ["privacy.resistFingerprinting.exemptedDomains", "string"],
        ["privacy.trackingprotection.enabled", "bool"],
        ["privacy.trackingprotection.pbmode.enabled", "bool"],
        ["geo.enabled", "bool"],
        ["geo.provider.ms-windows-location", "bool"],
        ["geo.provider.network.url", "string"],
        ["datareporting.policy.dataSubmissionEnabled", "bool"],
        ["datareporting.healthreport.uploadEnabled", "bool"],
        ["toolkit.telemetry.unified", "bool"],
        ["toolkit.telemetry.archive.enabled", "bool"],
        ["toolkit.telemetry.shutdownPingSender.enabled", "bool"],
        ["toolkit.telemetry.firstShutdownPing.enabled", "bool"],
        ["toolkit.telemetry.newProfilePing.enabled", "bool"],
        ["toolkit.telemetry.updatePing.enabled", "bool"],
        ["toolkit.telemetry.bhrPing.enabled", "bool"],
        ["browser.newtabpage.activity-stream.telemetry.privatePing.enabled", "bool"],
        ["browser.search.serpEventTelemetryCategorization.enabled", "bool"],
        ["identity.fxaccounts.telemetry.clientAssociationPing.enabled", "bool"],
        ["app.shield.optoutstudies.enabled", "bool"],
        ["app.normandy.enabled", "bool"],
        ["app.normandy.api_url", "string"],
        ["breakpad.reportURL", "string"],
        ["browser.tabs.crashReporting.sendReport", "bool"]
    ];

    let results = {};
    for (let item of queryList) {
        let name = item[0];
        let type = item[1];
        results[name] = getPrefVal(p, name, type);
    }
    dump("###PREF_DUMP_START###" + JSON.stringify(results) + "###PREF_DUMP_END###\\n");
    """

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js_code)
        script_path = f.name

    try:
        cmd = [XPCSHELL_EXE, "-a", BROWSER_DIR, script_path]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        output = proc.stdout
        match = re.search(r"###PREF_DUMP_START###(.*?)###PREF_DUMP_END###", output, re.DOTALL)
        if not match:
            raise RuntimeError(f"Failed to parse xpcshell pref dump. Output was:\n{output}")
        return json.loads(match.group(1))
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)


class TestRuntimePrivacyPrefs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assertTrue(
            os.path.exists(XPCSHELL_EXE),
            f"xpcshell executable not found at: {XPCSHELL_EXE}",
        )
        cls.assertTrue(
            os.path.exists(BROWSER_DIR),
            f"Browser directory not found at: {BROWSER_DIR}",
        )
        cls.runtime_prefs = query_runtime_prefs()

    def test_01_runtime_private_browsing_default(self):
        """Gecko runtime verifies Private Browsing autostart and in-memory media cache."""
        self.assertTrue(self.runtime_prefs.get("browser.privatebrowsing.autostart"))
        self.assertTrue(self.runtime_prefs.get("browser.privatebrowsing.forceMediaMemoryCache"))

    def test_02_runtime_no_browsing_history(self):
        """Gecko runtime verifies history, formfill, and session disk persistence are disabled."""
        self.assertFalse(self.runtime_prefs.get("places.history.enabled"))
        self.assertFalse(self.runtime_prefs.get("browser.formfill.enable"))
        self.assertEqual(self.runtime_prefs.get("browser.sessionstore.privacy_level"), 2)
        self.assertFalse(self.runtime_prefs.get("browser.sessionstore.resume_from_crash"))
        self.assertFalse(self.runtime_prefs.get("browser.places.speculativeConnect.enabled"))

    def test_03_runtime_no_saved_passwords(self):
        """Gecko runtime verifies password manager and form capturing are disabled."""
        self.assertFalse(self.runtime_prefs.get("signon.rememberSignons"))
        self.assertFalse(self.runtime_prefs.get("signon.autofillForms"))
        self.assertFalse(self.runtime_prefs.get("signon.generation.enabled"))
        self.assertFalse(self.runtime_prefs.get("signon.formlessCapture.enabled"))
        self.assertFalse(self.runtime_prefs.get("signon.privateBrowsingCapture.enabled"))
        self.assertFalse(self.runtime_prefs.get("signon.capture.inputChanges.enabled"))
        self.assertFalse(self.runtime_prefs.get("signon.formRemovalCapture.enabled"))
        self.assertFalse(self.runtime_prefs.get("signon.storeWhenAutocompleteOff"))

    def test_04_runtime_cookie_and_storage_isolation(self):
        """Gecko runtime verifies cookieBehavior=5 (dFPI/TCP) and disk cache disabled."""
        self.assertEqual(self.runtime_prefs.get("network.cookie.cookieBehavior"), 5)
        self.assertEqual(self.runtime_prefs.get("network.cookie.cookieBehavior.pbmode"), 5)
        self.assertFalse(self.runtime_prefs.get("browser.cache.disk.enable"))
        self.assertFalse(self.runtime_prefs.get("browser.cache.disk_cache_ssl"))
        self.assertTrue(self.runtime_prefs.get("browser.cache.memory.enable"))

    def test_05_runtime_https_only_enforcement(self):
        """Gecko runtime verifies HTTPS-Only mode enabled for all windows and PBM."""
        self.assertTrue(self.runtime_prefs.get("dom.security.https_only_mode"))
        self.assertTrue(self.runtime_prefs.get("dom.security.https_only_mode_pbm"))
        self.assertFalse(
            self.runtime_prefs.get("dom.security.https_only_mode_error_page_user_suggestions")
        )
        self.assertFalse(
            self.runtime_prefs.get("dom.security.https_only_mode_send_http_background_request")
        )

    def test_06_runtime_trr_mode_3_strict_doh(self):
        """Gecko runtime verifies TRR Mode 3 (DNS-over-HTTPS strict fail-closed)."""
        self.assertEqual(self.runtime_prefs.get("network.trr.mode"), 3)
        self.assertEqual(
            self.runtime_prefs.get("network.trr.uri"),
            "https://mozilla.cloudflare-dns.com/dns-query",
        )
        self.assertEqual(
            self.runtime_prefs.get("network.trr.default_provider_uri"),
            "https://mozilla.cloudflare-dns.com/dns-query",
        )

    def test_07_runtime_ipv6_dns_aaaa_suppression(self):
        """Gecko runtime verifies IPv6 DNS queries are suppressed."""
        self.assertTrue(self.runtime_prefs.get("network.dns.disableIPv6"))
        self.assertFalse(self.runtime_prefs.get("network.dns.preferIPv6"))

    def test_08_runtime_webrtc_host_address_protection(self):
        """Gecko runtime verifies WebRTC ICE candidate local host address stripping."""
        self.assertTrue(self.runtime_prefs.get("media.peerconnection.ice.no_host"))
        self.assertTrue(self.runtime_prefs.get("media.peerconnection.ice.default_address_only"))
        self.assertTrue(self.runtime_prefs.get("media.peerconnection.ice.proxy_only"))
        self.assertTrue(self.runtime_prefs.get("media.peerconnection.ice.proxy_only_if_pbmode"))
        self.assertTrue(self.runtime_prefs.get("media.peerconnection.ice.proxy_only_if_behind_proxy"))
        self.assertTrue(self.runtime_prefs.get("media.peerconnection.ice.obfuscate_host_addresses"))

    def test_09_runtime_resist_fingerprinting_active(self):
        """Gecko runtime verifies Resist Fingerprinting (RFP) is enabled with no exemptions."""
        self.assertTrue(self.runtime_prefs.get("privacy.resistFingerprinting"))
        self.assertTrue(self.runtime_prefs.get("privacy.resistFingerprinting.pbmode"))
        self.assertTrue(self.runtime_prefs.get("privacy.resistFingerprinting.block_mozAddonManager"))
        self.assertEqual(self.runtime_prefs.get("privacy.resistFingerprinting.exemptedDomains"), "")
        self.assertTrue(self.runtime_prefs.get("privacy.trackingprotection.enabled"))
        self.assertTrue(self.runtime_prefs.get("privacy.trackingprotection.pbmode.enabled"))

    def test_10_runtime_geolocation_denial(self):
        """Gecko runtime verifies real device geolocation is hard denied."""
        self.assertFalse(self.runtime_prefs.get("geo.enabled"))
        self.assertFalse(self.runtime_prefs.get("geo.provider.ms-windows-location"))
        self.assertEqual(self.runtime_prefs.get("geo.provider.network.url"), "")

    def test_11_runtime_telemetry_disabled(self):
        """Gecko runtime verifies telemetry, health reports, and crash reports are disabled."""
        self.assertFalse(self.runtime_prefs.get("datareporting.policy.dataSubmissionEnabled"))
        self.assertFalse(self.runtime_prefs.get("datareporting.healthreport.uploadEnabled"))
        self.assertFalse(self.runtime_prefs.get("toolkit.telemetry.unified"))
        self.assertFalse(self.runtime_prefs.get("toolkit.telemetry.archive.enabled"))
        self.assertFalse(self.runtime_prefs.get("toolkit.telemetry.shutdownPingSender.enabled"))
        self.assertFalse(self.runtime_prefs.get("toolkit.telemetry.firstShutdownPing.enabled"))
        self.assertFalse(self.runtime_prefs.get("toolkit.telemetry.newProfilePing.enabled"))
        self.assertFalse(self.runtime_prefs.get("toolkit.telemetry.updatePing.enabled"))
        self.assertFalse(self.runtime_prefs.get("toolkit.telemetry.bhrPing.enabled"))
        self.assertFalse(self.runtime_prefs.get("browser.newtabpage.activity-stream.telemetry.privatePing.enabled"))
        self.assertFalse(self.runtime_prefs.get("browser.search.serpEventTelemetryCategorization.enabled"))
        self.assertFalse(self.runtime_prefs.get("identity.fxaccounts.telemetry.clientAssociationPing.enabled"))
        self.assertFalse(self.runtime_prefs.get("app.shield.optoutstudies.enabled"))
        self.assertFalse(self.runtime_prefs.get("app.normandy.enabled"))
        self.assertEqual(self.runtime_prefs.get("app.normandy.api_url"), "")
        self.assertEqual(self.runtime_prefs.get("breakpad.reportURL"), "")
        self.assertFalse(self.runtime_prefs.get("browser.tabs.crashReporting.sendReport"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
