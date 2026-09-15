"""
Tests for Null Browser Step 6 Network & Security Core.
Validates:
1. DNS / TRR strict fail-closed behavior (TRR Mode 3, fallback-on-zero-response disabled, no plaintext fallback).
2. IPv6 protection beyond AAAA suppression: direct IPv6 literal socket blocking and "nullbrowser-blocked-ipv6" event.
   - Proves direct IPv6 socket creation is actually blocked and FAILS if transport connects/opens successfully.
   - Verifies the IPv6 C++ guard prevents AF_INET6 socket initiation in both InitiateSocket() and BuildSocket().
   - Clarifies that hostname-level IPv6 is suppressed at the DNS resolver level, while direct literal sockets are blocked at transport level.
3. WebRTC host-address protection & proxy/relay enforcement:
   - Host address obfuscation persists even when media capture permissions are granted.
   - Verifies C++ neutralization of the MediaManager capture override in PeerConnectionImpl.
4. HTTPS / Security hardening:
   - HTTPS-Only mode, mixed content blocking, strict cert pinning.
   - Tests actual HTTPS-Only upgrade path in Gecko engine; verifies "nullbrowser-https-upgraded" is emitted by C++ without manual observer invocation.
   - Verifies C++ guard restricts notification to genuine HTTPS-Only upgrades.
5. Network telemetry elimination: connectivity-service disabled, captive-portal disabled, speculative connects disabled, DNS prefetching disabled.
6. Negative constraints verification: no synthetic London location, no Tor/Ghost mode, no Panic mode, no Control Panel UI yet.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "privacy", "00-null-default-prefs.js"
)
FIREFOX_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "firefox")
DIST_BIN = r"C:\Users\Zaid\Projects\Null-Browser-build\obj-firefox\dist\bin"
XPCSHELL_EXE = os.path.join(DIST_BIN, "xpcshell.exe")
BROWSER_DIR = os.path.join(DIST_BIN, "browser")


def parse_prefs(filepath):
    prefs = {}
    pattern = re.compile(r'^\s*pref\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)\s*;\s*(?://.*)?$')
    with open(filepath, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            m = pattern.match(line)
            if not m:
                continue
            name = m.group(1)
            raw_val = m.group(2).strip()
            if raw_val == "true":
                val = True
            elif raw_val == "false":
                val = False
            elif (raw_val.startswith('"') and raw_val.endswith('"')) or (raw_val.startswith("'") and raw_val.endswith("'")):
                val = raw_val[1:-1]
            else:
                try:
                    val = int(raw_val)
                except ValueError:
                    val = raw_val
            prefs[name] = val
    return prefs


def run_xpcshell_script(script_code):
    """Execute a JS script in xpcshell with browser app provider and return parsed JSON stdout."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(script_code)
        script_path = f.name

    try:
        cmd = [XPCSHELL_EXE, "-g", DIST_BIN, "-a", BROWSER_DIR, "-f", script_path]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            cwd=DIST_BIN,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("JSON_RESULT:"):
                return json.loads(line[len("JSON_RESULT:"):])
        raise RuntimeError(f"No JSON_RESULT in xpcshell output:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)


class TestNetworkSecurityCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prefs = parse_prefs(os.path.abspath(CONFIG_PATH))

    def test_01_dns_trr_strict_fail_closed_prefs(self):
        """TRR Mode 3 with fallback-on-zero-response disabled (no plaintext fallback)."""
        self.assertEqual(self.prefs.get("network.trr.mode"), 3)
        self.assertEqual(self.prefs.get("network.trr.fallback-on-zero-response"), False)
        self.assertTrue(len(self.prefs.get("network.trr.uri", "")) > 0)
        self.assertTrue(len(self.prefs.get("network.trr.default_provider_uri", "")) > 0)

    def test_02_ipv6_protection_prefs(self):
        """IPv6 DNS AAAA queries suppressed and IPv6 disabled."""
        self.assertEqual(self.prefs.get("network.dns.disableIPv6"), True)
        self.assertEqual(self.prefs.get("network.dns.preferIPv6"), False)

    def test_03_webrtc_protection_prefs(self):
        """WebRTC ice host obfuscation and proxy/relay restrictions."""
        self.assertEqual(self.prefs.get("media.peerconnection.ice.obfuscate_host_addresses"), True)
        self.assertEqual(self.prefs.get("media.peerconnection.ice.default_address_only"), True)
        self.assertEqual(self.prefs.get("media.peerconnection.ice.proxy_only"), True)
        self.assertEqual(self.prefs.get("media.peerconnection.ice.proxy_only_if_pbmode"), True)
        self.assertEqual(self.prefs.get("media.peerconnection.ice.proxy_only_if_behind_proxy"), True)

    def test_04_https_security_hardening_prefs(self):
        """HTTPS-Only mode, mixed content blocking, and strict certificate pinning."""
        self.assertEqual(self.prefs.get("dom.security.https_only_mode"), True)
        self.assertEqual(self.prefs.get("dom.security.https_only_mode_pbm"), True)
        self.assertEqual(self.prefs.get("security.mixed_content.block_active_content"), True)
        self.assertEqual(self.prefs.get("security.mixed_content.block_display_content"), True)
        self.assertEqual(self.prefs.get("security.cert_pinning.enforcement_level"), 2)

    def test_05_network_telemetry_elimination_prefs(self):
        """Network telemetry, captive portal checks, and speculative preconnects disabled."""
        self.assertEqual(self.prefs.get("network.connectivity-service.enabled"), False)
        self.assertEqual(self.prefs.get("network.captive-portal-service.enabled"), False)
        self.assertEqual(self.prefs.get("network.dns.disablePrefetch"), True)
        self.assertEqual(self.prefs.get("network.dns.disablePrefetchFromHTTPS"), True)
        self.assertEqual(self.prefs.get("network.http.speculative-parallel-limit"), 0)
        self.assertEqual(self.prefs.get("browser.places.speculativeConnect.enabled"), False)

    def test_06_negative_constraints_preserved(self):
        """Ensure unpermitted features are NOT implemented."""
        self.assertNotIn("privacy.spoof_location.lat", self.prefs)
        self.assertNotIn("network.proxy.tor", self.prefs)
        self.assertNotIn("nullbrowser.panic_mode", self.prefs)
        self.assertNotIn("nullbrowser.control_panel.enabled", self.prefs)

    def test_07_runtime_network_security_prefs(self):
        """Verify the Gecko runtime loads and evaluates the network & security prefs."""
        js_code = """
        let p = Services.prefs;
        let results = {
            trr_mode: p.getIntPref("network.trr.mode", 0),
            trr_fallback: p.getBoolPref("network.trr.fallback-on-zero-response", true),
            dns_disable_ipv6: p.getBoolPref("network.dns.disableIPv6", false),
            dns_prefer_ipv6: p.getBoolPref("network.dns.preferIPv6", true),
            ice_obfuscate: p.getBoolPref("media.peerconnection.ice.obfuscate_host_addresses", false),
            ice_default_only: p.getBoolPref("media.peerconnection.ice.default_address_only", false),
            ice_proxy_only: p.getBoolPref("media.peerconnection.ice.proxy_only", false),
            https_only: p.getBoolPref("dom.security.https_only_mode", false),
            mixed_active: p.getBoolPref("security.mixed_content.block_active_content", false),
            mixed_display: p.getBoolPref("security.mixed_content.block_display_content", false),
            cert_pinning: p.getIntPref("security.cert_pinning.enforcement_level", 0),
            connectivity_service: p.getBoolPref("network.connectivity-service.enabled", true),
            captive_portal: p.getBoolPref("network.captive-portal-service.enabled", true),
            dns_prefetch: p.getBoolPref("network.dns.disablePrefetch", false),
            speculative_limit: p.getIntPref("network.http.speculative-parallel-limit", -1)
        };
        dump("JSON_RESULT:" + JSON.stringify(results) + "\\n");
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertEqual(res["trr_mode"], 3)
        self.assertEqual(res["trr_fallback"], False)
        self.assertEqual(res["dns_disable_ipv6"], True)
        self.assertEqual(res["dns_prefer_ipv6"], False)
        self.assertEqual(res["ice_obfuscate"], True)
        self.assertEqual(res["ice_default_only"], True)
        self.assertEqual(res["ice_proxy_only"], True)
        self.assertEqual(res["https_only"], True)
        self.assertEqual(res["mixed_active"], True)
        self.assertEqual(res["mixed_display"], True)
        self.assertEqual(res["cert_pinning"], 2)
        self.assertEqual(res["connectivity_service"], False)
        self.assertEqual(res["captive_portal"], False)
        self.assertEqual(res["dns_prefetch"], True)
        self.assertEqual(res["speculative_limit"], 0)

    def test_08_runtime_ipv6_literal_blocked_and_fails_on_connect(self):
        """Prove direct IPv6 literal socket creation is blocked and FAILS if connection succeeds."""
        js_code = """
        let blockedEvents = [];
        let statuses = [];
        let obs = Services.obs;
        let observer = {
            observe: function(subject, topic, data) {
                if (topic === "nullbrowser-blocked-ipv6") {
                    blockedEvents.push(data);
                }
            }
        };
        obs.addObserver(observer, "nullbrowser-blocked-ipv6");

        let sts = Cc["@mozilla.org/network/socket-transport-service;1"].getService(Ci.nsISocketTransportService);
        let sink = {
            onTransportStatus: function(trans, status, progress, progressMax) {
                statuses.push(status);
            }
        };

        // Test loopback IPv6 literal ::1
        let trans1 = sts.createTransport([], "::1", 8080, null, null);
        trans1.setEventSink(sink, Services.tm.currentThread);
        let inStream1 = trans1.openInputStream(0, 0, 0);

        // Test global unicast IPv6 literal 2001:db8::1
        let trans2 = sts.createTransport([], "2001:db8::1", 8080, null, null);
        trans2.setEventSink(sink, Services.tm.currentThread);
        let inStream2 = trans2.openInputStream(0, 0, 0);

        // Process event loop to let STS initiate and hit C++ IPv6 guard
        let thread = Services.tm.currentThread;
        for (let i = 0; i < 50; i++) {
            thread.processNextEvent(false);
        }

        obs.removeObserver(observer, "nullbrowser-blocked-ipv6");

        let connecting_status = Ci.nsISocketTransport.STATUS_CONNECTING_TO;
        let connected_status = Ci.nsISocketTransport.STATUS_CONNECTED_TO;
        let results = {
            trans1_alive: trans1.isAlive(),
            trans2_alive: trans2.isAlive(),
            blockedEvents: blockedEvents,
            statuses: statuses,
            connecting_status: connecting_status,
            connected_status: connected_status,
            connected_or_connecting: statuses.includes(connecting_status) || statuses.includes(connected_status)
        };
        dump("JSON_RESULT:" + JSON.stringify(results) + "\\n");
        quit(0);
        """
        res = run_xpcshell_script(js_code)

        # 1. Direct IPv6 socket creation must be blocked: transport must NOT be alive
        self.assertFalse(res["trans1_alive"], "IPv6 ::1 socket was reported alive!")
        self.assertFalse(res["trans2_alive"], "IPv6 2001:db8::1 socket was reported alive!")

        # 2. Must FAIL if transport ever attempted or succeeded connection (STATUS_CONNECTING_TO or STATUS_CONNECTED_TO)
        self.assertFalse(
            res["connected_or_connecting"],
            f"Direct IPv6 socket entered connecting/connected state: statuses={res['statuses']}",
        )

        # 3. Both raw IPv6 targets must have triggered the nullbrowser-blocked-ipv6 observer event
        self.assertIn("::1", res["blockedEvents"])
        self.assertIn("2001:db8::1", res["blockedEvents"])

        # 4. Verify socket status constants match ESR 153.4.0 headers (nsISocketTransport.idl: 0x4b0007, 0x4b0004)
        self.assertEqual(res["connecting_status"], 0x4B0007)
        self.assertEqual(res["connected_status"], 0x4B0004)

    def test_09_verify_ipv6_cpp_guard_coverage(self):
        """Verify the IPv6 C++ guard in nsSocketTransport2.cpp blocks AF_INET6 sockets in InitiateSocket and BuildSocket."""
        source_path = os.path.join(FIREFOX_ROOT, "netwerk", "base", "nsSocketTransport2.cpp")
        self.assertTrue(os.path.exists(source_path), f"Source file not found: {source_path}")
        with open(source_path, "r", encoding="utf-8-sig") as f:
            code = f.read()

        # 1. Verify InitiateSocket() guard:
        # Blocks any connection where mNetAddr.raw.family == AF_INET6
        self.assertIn("if (mNetAddr.raw.family == AF_INET6 && StaticPrefs::network_dns_disableIPv6())", code)
        self.assertIn("nullbrowser-blocked-ipv6", code)
        self.assertIn("mCondition = NS_ERROR_UNKNOWN_SOCKET_TYPE;", code)

        # 2. Verify BuildSocket() guard:
        # Pre-socket creation guard preventing PR_OpenTCPSocket(AF_INET6)
        build_socket_idx = code.find("nsSocketTransport::BuildSocket")
        self.assertTrue(build_socket_idx != -1)
        build_socket_block = code[build_socket_idx:build_socket_idx + 1000]
        self.assertIn("mNetAddr.raw.family == AF_INET6", build_socket_block)
        self.assertIn("StaticPrefs::network_dns_disableIPv6()", build_socket_block)
        self.assertIn("return NS_ERROR_UNKNOWN_SOCKET_TYPE;", build_socket_block)

    def test_10_runtime_real_https_only_upgrade_emits_instrumentation(self):
        """Verify an actual HTTP channel load triggers the C++ HTTPS-Only upgrade path and emits nullbrowser-https-upgraded."""
        js_code = """
        let obs = Services.obs;
        let received = [];
        let observer = {
            observe: function(subject, topic, data) {
                if (topic === "nullbrowser-https-upgraded") {
                    received.push(data);
                }
            }
        };
        obs.addObserver(observer, "nullbrowser-https-upgraded");

        const { NetUtil } = ChromeUtils.importESModule("resource://gre/modules/NetUtil.sys.mjs");
        let uri = Services.io.newURI("http://example.com/test");
        let principal = Services.scriptSecurityManager.getSystemPrincipal();
        let chan = NetUtil.newChannel({
            uri: uri,
            loadingPrincipal: principal,
            securityFlags: Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
            contentPolicyType: Ci.nsIContentPolicy.TYPE_DOCUMENT,
        });

        try {
            chan.asyncOpen({
                onStartRequest: function() {},
                onStopRequest: function() {},
                onDataAvailable: function() {}
            });
        } catch(e) {
            // Error handling during asyncOpen if socket cannot resolve
        }

        let thread = Services.tm.currentThread;
        let start = Date.now();
        while (received.length === 0 && (Date.now() - start) < 3000) {
            thread.processNextEvent(true);
        }

        obs.removeObserver(observer, "nullbrowser-https-upgraded");

        print("JSON_RESULT:" + JSON.stringify({received: received}));
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertIn("http://example.com/test", res["received"])

    def test_11_verify_https_instrumentation_only_emitted_for_real_https_only(self):
        """Verify C++ guard in nsHTTPSOnlyUtils.cpp restricts notification to genuine HTTPS-Only upgrades."""
        source_path = os.path.join(FIREFOX_ROOT, "dom", "security", "nsHTTPSOnlyUtils.cpp")
        self.assertTrue(os.path.exists(source_path), f"Source file not found: {source_path}")
        with open(source_path, "r", encoding="utf-8-sig") as f:
            code = f.read()

        # Must check:
        # aName == HTTPSOnlyUpgradeRequest
        # !aUseHttpsFirst (ensures not HTTPS-First)
        # aLoadInfo && GetUpgradeMode(aLoadInfo) == HTTPS_ONLY_MODE (ensures not schemeless first)
        self.assertIn("nullbrowser-https-upgraded", code)
        self.assertIn("!aUseHttpsFirst", code)
        self.assertIn("GetUpgradeMode(aLoadInfo) == HTTPS_ONLY_MODE", code)

    def test_12_webrtc_host_address_protection_and_capture_override_neutralization(self):
        """Verify WebRTC ICE host-address obfuscation and proxy enforcement preferences and C++ override neutralization."""
        # 1. Prefs integrity
        self.assertTrue(self.prefs.get("media.peerconnection.ice.obfuscate_host_addresses"))
        self.assertTrue(self.prefs.get("media.peerconnection.ice.proxy_only"))
        self.assertTrue(self.prefs.get("media.peerconnection.ice.default_address_only"))
        self.assertTrue(self.prefs.get("media.peerconnection.ice.no_host"))

        # 2. Source verification: GetPrefObfuscateHostAddresses in PeerConnectionImpl.cpp
        # neutralizes the MediaManager capture override so host addresses cannot leak upon permission grant.
        source_path = os.path.join(FIREFOX_ROOT, "dom", "media", "webrtc", "jsapi", "PeerConnectionImpl.cpp")
        self.assertTrue(os.path.exists(source_path), f"Source file not found: {source_path}")
        with open(source_path, "r", encoding="utf-8-sig") as f:
            code = f.read()

        obfuscate_func_idx = code.find("PeerConnectionImpl::GetPrefObfuscateHostAddresses()")
        self.assertTrue(obfuscate_func_idx != -1)
        func_block = code[obfuscate_func_idx:obfuscate_func_idx + 800]
        self.assertIn("Null Browser WebRTC protection", func_block)
        # Ensure MediaManager::Get()->IsActivelyCapturingOrHasAPermission is commented out or neutralized
        self.assertIn("//     !MediaManager::Get()->IsActivelyCapturingOrHasAPermission", func_block)


if __name__ == "__main__":
    unittest.main()

