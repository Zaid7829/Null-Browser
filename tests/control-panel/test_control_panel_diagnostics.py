"""
Step 10.2A — Control Panel Live Diagnostics Data Model Security Corrections Test Suite.

Validates the security corrections to the Control Panel diagnostics data layer:
1. Ghost/Tor State Separation:
   - Proves Tor "READY" is NOT reported merely because SOCKS preferences point at 127.0.0.1
   - Authoritative Ghost lifecycle state (DISABLED, STARTING, TOR_BOOTSTRAPPING, READY, STOPPING, FAILED) is respected
   - Configuration (torRoutingConfigured) is strictly separated from actual lifecycle (ghostLifecycleState)
2. Configuration vs Verified State:
   - Preferences are labeled as configuration/effective configuration
   - No false claims of zero DNS leaks, zero WebRTC leaks, or end-to-end anonymity
3. TRR Endpoint:
   - trrUri is strictly removed from the IPC payload
   - Only non-sensitive trrMode and strict-mode status are exposed
4. IPv6 Counter:
   - observedBlockedIPv6Count is in-memory only, non-persistent, and resets with process lifecycle
   - Verified as a count of observed socket blocks only (not a guarantee of impossible leaks)
5. Payload Minimization:
   - No URLs, hostnames, IP addresses, filesystem paths, PIDs, secrets, or user-origin strings
6. Security Boundaries:
   - Child cannot submit, override, or spoof diagnostic state
   - Privileged parent remains authoritative
"""

import json
import os
import subprocess
import unittest

DIST_BIN = r"C:\Users\Zaid\Projects\Null-Browser-build\obj-firefox\dist\bin"
XPCSHELL_EXE = os.path.join(DIST_BIN, "xpcshell.exe")
BROWSER_DIR = os.path.join(DIST_BIN, "browser")
REPO_ROOT = os.path.realpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
FIREFOX_SRC = os.path.join(REPO_ROOT, "firefox")


def run_xpcshell_diagnostics(js_snippet: str) -> dict:
    """Executes a JavaScript snippet in xpcshell with app provider and returns parsed JSON_RESULT."""
    manifest_path = os.path.join(DIST_BIN, "browser", "chrome", "browser.manifest").replace("\\", "\\\\")
    full_script = f"""
    let manifestFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    manifestFile.initWithPath("{manifest_path}");
    Components.manager.QueryInterface(Ci.nsIComponentRegistrar).autoRegister(manifestFile);

    let {{ NullControlPanelParent, _resetDiagnosticsStateForTesting }} = ChromeUtils.importESModule("resource:///actors/NullControlPanelParent.sys.mjs");
    let parentActor = new NullControlPanelParent();

    (async function() {{
        {js_snippet}
    }})().then(res => {{
        dump("JSON_RESULT:" + JSON.stringify(res) + "\\n");
        quit(0);
    }}).catch(err => {{
        dump("JSON_RESULT:" + JSON.stringify({{ error: String(err), message: err?.message }}) + "\\n");
        quit(1);
    }});

    let thread = Services.tm.currentThread;
    for (let i = 0; i < 50; i++) {{
        thread.processNextEvent(false);
    }}
    """
    proc = subprocess.run(
        [XPCSHELL_EXE, "-g", DIST_BIN, "-a", BROWSER_DIR, "-e", full_script],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 and "JSON_RESULT:" not in proc.stdout:
        raise RuntimeError(f"xpcshell failed (code {proc.returncode}):\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")

    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("JSON_RESULT:"):
            return json.loads(line[len("JSON_RESULT:"):])

    raise ValueError(f"No JSON_RESULT found in xpcshell output:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")


class TestControlPanelDiagnostics(unittest.TestCase):
    """Verifies security corrections, configuration/state separation, and data minimization."""

    def test_01_browser_mode_configuration_vs_actual_lifecycle(self):
        """Verify Ghost READY is NOT reported merely because SOCKS preferences point at 127.0.0.1."""
        js = """
        _resetDiagnosticsStateForTesting();
        let baseline = parentActor.fetchDiagnostics().browserMode;

        // 1. Simulate setting SOCKS5 preferences pointing to localhost:
        // This configures Tor routing in prefs, but does NOT start or bootstrap Tor!
        Services.prefs.setIntPref("network.proxy.type", 1);
        Services.prefs.setStringPref("network.proxy.socks", "127.0.0.1");
        Services.prefs.setIntPref("network.proxy.socks_port", 9050);
        Services.prefs.setIntPref("network.proxy.socks_version", 5);

        let socksConfiguredOnly = parentActor.fetchDiagnostics().browserMode;

        // 2. Simulate authoritative Ghost Mode transition to TOR_BOOTSTRAPPING via observer
        Services.obs.notifyObservers(null, "nullbrowser-ghost-state-changed", "TOR_BOOTSTRAPPING");
        let bootstrapping = parentActor.fetchDiagnostics().browserMode;

        // 3. Simulate authoritative Ghost Mode transition to READY
        Services.obs.notifyObservers(null, "nullbrowser-ghost-state-changed", "READY");
        let ready = parentActor.fetchDiagnostics().browserMode;

        // 4. Simulate STOPPING and DISABLED transitions
        Services.obs.notifyObservers(null, "nullbrowser-ghost-state-changed", "STOPPING");
        let stopping = parentActor.fetchDiagnostics().browserMode;

        Services.obs.notifyObservers(null, "nullbrowser-ghost-state-changed", "DISABLED");
        let disabledAgain = parentActor.fetchDiagnostics().browserMode;

        // Reset prefs
        Services.prefs.clearUserPref("network.proxy.type");
        Services.prefs.clearUserPref("network.proxy.socks");
        Services.prefs.clearUserPref("network.proxy.socks_port");
        Services.prefs.clearUserPref("network.proxy.socks_version");
        _resetDiagnosticsStateForTesting();

        return { baseline, socksConfiguredOnly, bootstrapping, ready, stopping, disabledAgain };
        """
        res = run_xpcshell_diagnostics(js)

        # Baseline: normal unproxied browsing
        base = res["baseline"]
        self.assertTrue(base["privateBrowsingDefaultConfigured"])
        self.assertFalse(base["torRoutingConfigured"])
        self.assertEqual(base["ghostLifecycleState"], "DISABLED")
        self.assertFalse(base["ghostModeActive"])

        # SOCKS configured only: proves configuration, but actual lifecycle remains DISABLED
        socks_only = res["socksConfiguredOnly"]
        self.assertTrue(socks_only["torRoutingConfigured"], "SOCKS5 proxy configuration should be detected")
        self.assertEqual(
            socks_only["ghostLifecycleState"],
            "DISABLED",
            "Ghost lifecycle must NOT report READY merely because SOCKS preferences point to 127.0.0.1!",
        )
        self.assertFalse(
            socks_only["ghostModeActive"],
            "ghostModeActive must remain False when Tor daemon is not running/active",
        )

        # Authoritative transitions
        boot = res["bootstrapping"]
        self.assertEqual(boot["ghostLifecycleState"], "TOR_BOOTSTRAPPING")
        self.assertTrue(boot["ghostModeActive"])

        rdy = res["ready"]
        self.assertEqual(rdy["ghostLifecycleState"], "READY")
        self.assertTrue(rdy["ghostModeActive"])

        stp = res["stopping"]
        self.assertEqual(stp["ghostLifecycleState"], "STOPPING")
        self.assertFalse(stp["ghostModeActive"])

        dis = res["disabledAgain"]
        self.assertEqual(dis["ghostLifecycleState"], "DISABLED")
        self.assertFalse(dis["ghostModeActive"])

    def test_02_network_diagnostics_and_trr_uri_absence(self):
        """Verify network diagnostics: TRR mode 3, strict-mode status, and trrUri strictly absent."""
        js = """
        let net = parentActor.fetchDiagnostics().network;
        return { net };
        """
        res = run_xpcshell_diagnostics(js)
        net = res["net"]

        # TRR strict DoH configuration
        self.assertEqual(net["trrMode"], 3)
        self.assertTrue(net["trrStrictConfigured"])

        # SECURITY INVARIANT: trrUri must be ABSENT from the payload
        self.assertNotIn("trrUri", net, "trrUri must NOT be exposed in the IPC payload!")

        # Configuration labels
        self.assertTrue(net["ipv6DisabledConfigured"])
        self.assertIsInstance(net["failoverDirect"], bool)
        self.assertTrue(net["webrtcIceNoHostConfigured"])
        self.assertTrue(net["webrtcIceDefaultAddressOnly"])
        self.assertTrue(net["webrtcObfuscateHostAddresses"])

    def test_03_ipv6_counter_in_memory_and_non_persistent(self):
        """Verify observedBlockedIPv6Count is in-memory only and resets with process lifecycle."""
        js = """
        _resetDiagnosticsStateForTesting();
        let initialCount = parentActor.fetchDiagnostics().network.observedBlockedIPv6Count;

        // Emit simulated blocked attempts
        Services.obs.notifyObservers(null, "nullbrowser-blocked-ipv6", "::1");
        Services.obs.notifyObservers(null, "nullbrowser-blocked-ipv6", "2001:db8::1");

        let observedCount = parentActor.fetchDiagnostics().network.observedBlockedIPv6Count;

        // Reset in-memory diagnostic state (simulating new diagnostic session)
        _resetDiagnosticsStateForTesting();
        let resetCount = parentActor.fetchDiagnostics().network.observedBlockedIPv6Count;

        return { initialCount, observedCount, resetCount };
        """
        res = run_xpcshell_diagnostics(js)
        self.assertEqual(res["initialCount"], 0)
        self.assertEqual(res["observedCount"], 2)
        self.assertEqual(res["resetCount"], 0, "IPv6 counter must be reset and strictly non-persistent")

    def test_04_privacy_and_content_protections_configuration_labels(self):
        """Verify privacy and content protections are accurately labeled as effective configuration."""
        js = """
        let diag = parentActor.fetchDiagnostics();
        return {
            priv: diag.privacyProtections,
            content: diag.contentProtection
        };
        """
        res = run_xpcshell_diagnostics(js)
        p = res["priv"]
        c = res["content"]

        # Effective preference configurations
        self.assertTrue(p["rfpConfigured"])
        self.assertTrue(p["rfpPbmConfigured"])
        self.assertEqual(p["spoofEnglish"], 2)
        self.assertEqual(p["fontVisibility"], 1)
        self.assertTrue(p["webglDebugRendererSuppressed"])
        self.assertEqual(p["timerPrecisionMicroseconds"], 1000)
        self.assertTrue(p["timerJitterConfigured"])

        self.assertTrue(p["geoDisabledConfigured"])
        self.assertEqual(p["defaultGeoPolicy"], 2)
        self.assertTrue(p["windowsLocationDisabled"])

        self.assertTrue(p["historyDisabledConfigured"])
        self.assertTrue(p["formFillDisabledConfigured"])
        self.assertEqual(p["sessionPrivacyLevel"], 2)

        self.assertTrue(p["rememberSignonsDisabled"])
        self.assertTrue(p["autofillFormsDisabled"])
        self.assertEqual(p["cookieBehavior"], 5)  # dFPI / Total Cookie Protection
        self.assertTrue(p["diskCacheDisabledConfigured"])
        self.assertTrue(p["memoryCacheEnabled"])

        self.assertTrue(p["httpsOnlyModeConfigured"])
        self.assertTrue(p["httpsOnlyModePbmConfigured"])

        # Content protection configuration
        self.assertTrue(c["trackingProtectionConfigured"])
        self.assertTrue(c["trackingProtectionPbmConfigured"])
        self.assertTrue(c["cryptominingProtectionConfigured"])
        self.assertTrue(c["fingerprintingProtectionConfigured"])

        # No fake counts or synthetic percentage metrics
        for key, val in c.items():
            self.assertIsInstance(val, bool, f"Content protection '{key}' must be boolean configuration")

    def test_05_permissions_sanitization(self):
        """Verify session permissions reporting without sensitive origin or URL leakage."""
        js = """
        let before = parentActor.fetchDiagnostics().permissions;

        let ssm = Services.scriptSecurityManager;
        let p1 = ssm.createContentPrincipal(Services.io.newURI("https://example.com"), {});
        let p2 = ssm.createContentPrincipal(Services.io.newURI("https://trusted.org"), {});

        Services.perms.addFromPrincipal(p1, "camera", Ci.nsIPermissionManager.ALLOW_ACTION, Ci.nsIPermissionManager.EXPIRE_SESSION);
        Services.perms.addFromPrincipal(p2, "microphone", Ci.nsIPermissionManager.DENY_ACTION, Ci.nsIPermissionManager.EXPIRE_SESSION);
        Services.perms.addFromPrincipal(p1, "geo", Ci.nsIPermissionManager.DENY_ACTION, Ci.nsIPermissionManager.EXPIRE_NEVER);

        let after = parentActor.fetchDiagnostics().permissions;

        Services.perms.removeFromPrincipal(p1, "camera");
        Services.perms.removeFromPrincipal(p2, "microphone");
        Services.perms.removeFromPrincipal(p1, "geo");

        return { before, after };
        """
        res = run_xpcshell_diagnostics(js)
        before = res["before"]
        after = res["after"]

        self.assertEqual(after["sessionPermissionsCount"], before["sessionPermissionsCount"] + 2)
        self.assertEqual(after["sessionPermissionTypes"].get("camera"), 1)
        self.assertEqual(after["sessionPermissionTypes"].get("microphone"), 1)
        self.assertNotIn("geo", after["sessionPermissionTypes"])

        # Zero origin leakage
        raw_perms = json.dumps(after)
        self.assertNotIn("example.com", raw_perms)
        self.assertNotIn("trusted.org", raw_perms)
        self.assertNotIn("https://", raw_perms)

    def test_06_negative_child_cannot_inject_or_override_diagnostics(self):
        """Verify the child/page cannot submit, override, or spoof diagnostic state."""
        js = """
        let unauthorizedError = null;
        try {
            await parentActor.receiveMessage({ name: "SetDiagnostics", data: { rfpEnabled: false } });
        } catch (e) {
            unauthorizedError = e.message;
        }

        let spoofAttemptResult = await parentActor.receiveMessage({
            name: "FetchDiagnostics",
            data: {
                rfpEnabled: false,
                browserMode: { ghostModeActive: true, ghostLifecycleState: "READY" },
                injectedField: "attacker_controlled"
            }
        });

        return {
            unauthorizedError,
            rfpStillTrue: spoofAttemptResult.rfpEnabled,
            injectedUndefined: (spoofAttemptResult.injectedField === undefined),
            lifecycleAuthoritative: spoofAttemptResult.browserMode.ghostLifecycleState
        };
        """
        res = run_xpcshell_diagnostics(js)
        self.assertIsNotNone(res["unauthorizedError"])
        self.assertIn("Unauthorized message", res["unauthorizedError"])
        self.assertTrue(res["rfpStillTrue"])
        self.assertTrue(res["injectedUndefined"])
        self.assertEqual(res["lifecycleAuthoritative"], "DISABLED")

    def test_07_payload_minimization_and_security_invariants(self):
        """Verify the entire IPC payload contains zero fake metrics, telemetry, URLs, PIDs, or filesystem paths."""
        js = """
        let diag = parentActor.fetchDiagnostics();
        return { diag };
        """
        res = run_xpcshell_diagnostics(js)
        diag = res["diag"]
        raw_json = json.dumps(diag).lower()

        # Invariant 1: No fake security/anonymity scores
        self.assertNotIn("score", raw_json)
        self.assertNotIn("ranking", raw_json)
        self.assertNotIn("100% anonymous", raw_json)
        self.assertNotIn("anonymity_level", raw_json)

        # Invariant 2: No URLs or endpoints
        self.assertNotIn("http://", raw_json)
        self.assertNotIn("https://", raw_json)
        self.assertNotIn("trruri", raw_json)

        # Invariant 3: No internal filesystem paths
        self.assertNotIn("c:\\", raw_json)
        self.assertNotIn("users\\zaid", raw_json)
        self.assertNotIn("appdata", raw_json)
        self.assertNotIn("profile", raw_json)

        # Invariant 4: No process identifiers or executable paths
        self.assertNotIn("pid", raw_json)
        self.assertNotIn("firefox.exe", raw_json)
        self.assertNotIn("tor.exe", raw_json)

        # Invariant 5: No telemetry tokens
        self.assertNotIn("telemetry", raw_json)
        self.assertNotIn("ping", raw_json)


if __name__ == "__main__":
    unittest.main()
