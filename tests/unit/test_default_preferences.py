"""
Unit tests for Null Browser Step 5 Default Privacy Configuration.
Validates the static preference file syntax, required preference values,
and negative constraints (no premature feature implementations).
"""

import os
import re
import unittest

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "privacy", "00-null-default-prefs.js"
)

PREF_PATTERN = re.compile(
    r'^\s*pref\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)\s*;\s*(?://.*)?$'
)


def parse_prefs(filepath):
    prefs = {}
    with open(filepath, "r", encoding="utf-8-sig") as f:
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue
            match = PREF_PATTERN.match(line)
            if not match:
                raise ValueError(f"Syntax error at {filepath}:{line_num}: {raw_line}")
            pref_name = match.group(1)
            raw_val = match.group(2).strip()

            if raw_val == "true":
                val = True
            elif raw_val == "false":
                val = False
            elif raw_val.startswith('"') and raw_val.endswith('"'):
                val = raw_val[1:-1]
            elif raw_val.startswith("'") and raw_val.endswith("'"):
                val = raw_val[1:-1]
            else:
                try:
                    val = int(raw_val)
                except ValueError:
                    val = raw_val
            prefs[pref_name] = val
    return prefs


class TestDefaultPreferences(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config_file = os.path.abspath(CONFIG_PATH)
        cls.assertTrue(
            os.path.exists(cls.config_file),
            f"Config file not found: {cls.config_file}",
        )
        cls.prefs = parse_prefs(cls.config_file)

    def test_01_private_browsing_default(self):
        """Verify Private Browsing is default and forced to RAM cache."""
        self.assertIn("browser.privatebrowsing.autostart", self.prefs)
        self.assertTrue(self.prefs["browser.privatebrowsing.autostart"])
        self.assertIn("browser.privatebrowsing.forceMediaMemoryCache", self.prefs)
        self.assertTrue(self.prefs["browser.privatebrowsing.forceMediaMemoryCache"])

    def test_02_no_browsing_history(self):
        """Verify Places history, form fill, and session persist are disabled."""
        self.assertIn("places.history.enabled", self.prefs)
        self.assertFalse(self.prefs["places.history.enabled"])
        self.assertIn("browser.formfill.enable", self.prefs)
        self.assertFalse(self.prefs["browser.formfill.enable"])
        self.assertEqual(self.prefs.get("browser.sessionstore.privacy_level"), 2)
        self.assertFalse(self.prefs.get("browser.sessionstore.resume_from_crash"))
        self.assertFalse(self.prefs.get("browser.places.speculativeConnect.enabled"))

    def test_03_no_saved_passwords(self):
        """Verify password saving, autofill, generation and capture are disabled."""
        self.assertFalse(self.prefs.get("signon.rememberSignons"))
        self.assertFalse(self.prefs.get("signon.autofillForms"))
        self.assertFalse(self.prefs.get("signon.generation.enabled"))
        self.assertFalse(self.prefs.get("signon.formlessCapture.enabled"))
        self.assertFalse(self.prefs.get("signon.privateBrowsingCapture.enabled"))
        self.assertFalse(self.prefs.get("signon.capture.inputChanges.enabled"))
        self.assertFalse(self.prefs.get("signon.formRemovalCapture.enabled"))
        self.assertFalse(self.prefs.get("signon.storeWhenAutocompleteOff"))

    def test_04_no_persistent_cookies_and_storage(self):
        """Verify dFPI/TCP (cookieBehavior=5) and disk caching disabled."""
        self.assertEqual(self.prefs.get("network.cookie.cookieBehavior"), 5)
        self.assertEqual(self.prefs.get("network.cookie.cookieBehavior.pbmode"), 5)
        self.assertFalse(self.prefs.get("browser.cache.disk.enable"))
        self.assertFalse(self.prefs.get("browser.cache.disk_cache_ssl"))
        self.assertTrue(self.prefs.get("browser.cache.memory.enable"))

    def test_05_https_only_enforcement(self):
        """Verify HTTPS-Only mode enabled for all windows and PBM, no plaintext leak."""
        self.assertTrue(self.prefs.get("dom.security.https_only_mode"))
        self.assertTrue(self.prefs.get("dom.security.https_only_mode_pbm"))
        self.assertFalse(
            self.prefs.get("dom.security.https_only_mode_error_page_user_suggestions")
        )
        self.assertFalse(
            self.prefs.get("dom.security.https_only_mode_send_http_background_request")
        )

    def test_06_trr_mode_3_fail_closed(self):
        """Verify TRR mode 3 (strict DoH) with no silent plaintext fallback."""
        self.assertEqual(self.prefs.get("network.trr.mode"), 3)
        self.assertEqual(
            self.prefs.get("network.trr.uri"),
            "https://mozilla.cloudflare-dns.com/dns-query",
        )
        self.assertEqual(
            self.prefs.get("network.trr.default_provider_uri"),
            "https://mozilla.cloudflare-dns.com/dns-query",
        )

    def test_07_ipv6_dns_aaaa_suppression(self):
        """Verify IPv6 DNS queries are suppressed at resolver."""
        self.assertTrue(self.prefs.get("network.dns.disableIPv6"))
        self.assertFalse(self.prefs.get("network.dns.preferIPv6"))

    def test_08_webrtc_host_address_protection(self):
        """Verify WebRTC ICE candidates hide local host addresses."""
        self.assertTrue(self.prefs.get("media.peerconnection.ice.no_host"))
        self.assertTrue(self.prefs.get("media.peerconnection.ice.default_address_only"))
        self.assertTrue(self.prefs.get("media.peerconnection.ice.proxy_only"))
        self.assertTrue(self.prefs.get("media.peerconnection.ice.proxy_only_if_pbmode"))
        self.assertTrue(self.prefs.get("media.peerconnection.ice.obfuscate_host_addresses"))

    def test_09_resist_fingerprinting_enabled(self):
        """Verify Resist Fingerprinting (RFP) is enabled with no domain exemptions."""
        self.assertTrue(self.prefs.get("privacy.resistFingerprinting"))
        self.assertTrue(self.prefs.get("privacy.resistFingerprinting.pbmode"))
        self.assertTrue(self.prefs.get("privacy.resistFingerprinting.block_mozAddonManager"))
        self.assertEqual(self.prefs.get("privacy.resistFingerprinting.exemptedDomains"), "")
        self.assertTrue(self.prefs.get("privacy.trackingprotection.enabled"))

    def test_10_geolocation_device_denial(self):
        """Verify real device geolocation is hard-denied and providers stripped."""
        self.assertFalse(self.prefs.get("geo.enabled"))
        self.assertFalse(self.prefs.get("geo.provider.ms-windows-location"))
        self.assertEqual(self.prefs.get("geo.provider.network.url"), "")

    def test_11_telemetry_and_analytics_disabled(self):
        """Verify telemetry, health reports, studies, and crash pings are disabled."""
        self.assertFalse(self.prefs.get("datareporting.policy.dataSubmissionEnabled"))
        self.assertFalse(self.prefs.get("datareporting.healthreport.uploadEnabled"))
        self.assertFalse(self.prefs.get("toolkit.telemetry.unified"))
        self.assertFalse(self.prefs.get("toolkit.telemetry.archive.enabled"))
        self.assertFalse(self.prefs.get("toolkit.telemetry.shutdownPingSender.enabled"))
        self.assertFalse(self.prefs.get("toolkit.telemetry.firstShutdownPing.enabled"))
        self.assertFalse(self.prefs.get("toolkit.telemetry.newProfilePing.enabled"))
        self.assertFalse(self.prefs.get("toolkit.telemetry.updatePing.enabled"))
        self.assertFalse(self.prefs.get("toolkit.telemetry.bhrPing.enabled"))
        self.assertFalse(
            self.prefs.get(
                "browser.newtabpage.activity-stream.telemetry.privatePing.enabled"
            )
        )
        self.assertFalse(
            self.prefs.get("browser.search.serpEventTelemetryCategorization.enabled")
        )
        self.assertFalse(self.prefs.get("app.shield.optoutstudies.enabled"))
        self.assertFalse(self.prefs.get("app.normandy.enabled"))
        self.assertEqual(self.prefs.get("app.normandy.api_url"), "")
        self.assertEqual(self.prefs.get("breakpad.reportURL"), "")
        self.assertFalse(self.prefs.get("browser.tabs.crashReporting.sendReport"))

    def test_12_negative_constraints(self):
        """Verify Step 5 boundaries: No Secure Mode, no synthetic London, no Panic/CP prefs."""
        for pref in self.prefs:
            self.assertFalse(
                pref.startswith("nullbrowser.securemode"),
                f"Secure Mode pref prematurely present: {pref}",
            )
            self.assertFalse(
                pref.startswith("nullbrowser.controlpanel"),
                f"Control panel pref prematurely present: {pref}",
            )
            self.assertFalse(
                pref.startswith("nullbrowser.panic"),
                f"Panic mode pref prematurely present: {pref}",
            )
            self.assertFalse(
                "london" in str(self.prefs[pref]).lower(),
                f"Synthetic London location prematurely present in: {pref}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
