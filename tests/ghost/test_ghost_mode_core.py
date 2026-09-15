"""
Tests for Null Browser Step 8: Ghost Mode & Tor Architecture and Implementation.

Validates:
1. Ghost Mode Lifecycle State Machine:
   - Strict state progression: DISABLED -> STARTING -> TOR_BOOTSTRAPPING -> READY -> STOPPING -> DISABLED.
   - Disallow invalid transitions (e.g. DISABLED -> READY).
   - Emergency fail-closed force_reset() upon any unexpected error.
2. Ghost Ephemeral Profile & Session Isolation:
   - Dynamically generated temporary profile with isolated user.js.
   - SOCKS5 routing to 127.0.0.1:9050 with SOCKS5 remote DNS.
   - Fail-closed proxy policy (no direct failover).
   - Zero disk persistence (disk cache disabled, history disabled, formfill disabled, private browsing autostart).
   - Extension isolation (autoDisableScopes=15, enabledScopes=0).
3. Preservation of User-Owned Downloads:
   - Cleanup completely removes temporary profile directories while preserving user downloads.
   - Target safety checks prevent accidental wipe of download directories.
4. Tor Process Supervisor & Fail-Closed Behavior:
   - Tor binary discovery (bundled tools/tor or system PATH).
   - Fail-closed when Tor executable is missing (refuses to start, state reverts to DISABLED).
   - Process supervision, bootstrap progress tracking, and unexpected termination handling.
5. Firefox Launch Arguments:
   - Enforces `-no-remote -profile <ephemeral_dir>` for strict session isolation.
6. Privileged Diagnostics & Security Boundaries:
   - Factual diagnostics without fake Tor metrics or fake anonymity scores.
   - Strict security boundary (privileged internal API only, never exposed to web content).
7. Ordinary Browsing Remains Unaffected:
   - Default preferences do not force SOCKS5 proxying; Ghost Mode is strictly opt-in.
8. Static ESR 153.4.0 Source Verification:
   - nsProtocolProxyService.cpp: socks5_remote_dns sets TRANSPARENT_PROXY_RESOLVES_HOST.
   - nsSocketTransport2.cpp: mProxyTransparentResolvesHost handles remote DNS.
   - nsDNSService2.cpp: blockDotOnion prevents local DNS leakage of .onion addresses.
   - StaticPrefList.yaml: verifies definitions for network.proxy.socks5_remote_dns and network.proxy.failover_direct.
9. Runtime Gecko SOCKS5 Fail-Closed Evaluation:
   - Executes xpcshell to verify that Gecko fails closed (NS_ERROR_PROXY_CONNECTION_REFUSED) when SOCKS proxy is unreachable and does not fall back to direct internet.
10. Negative Constraints Preserved:
   - No Panic Mode, no Control Panel UI, no Secure Mode, no synthetic geolocation.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import importlib

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

ghost_mode = importlib.import_module("ghost-mode")
sys.modules["ghost_mode"] = ghost_mode

GhostState = ghost_mode.GhostState
GhostLifecycleStateMachine = ghost_mode.GhostLifecycleStateMachine
StateTransitionError = ghost_mode.StateTransitionError
TorConfig = ghost_mode.TorConfig
TorSupervisor = ghost_mode.TorSupervisor
TorExecutableNotFoundError = ghost_mode.TorExecutableNotFoundError
TorBootstrapError = ghost_mode.TorBootstrapError
TorPortConflictError = ghost_mode.TorPortConflictError
find_available_loopback_port = ghost_mode.find_available_loopback_port
is_port_in_use = ghost_mode.is_port_in_use
GhostProfileManager = ghost_mode.GhostProfileManager
GhostDiagnostics = ghost_mode.GhostDiagnostics
GhostModeManager = ghost_mode.GhostModeManager
GhostModeError = ghost_mode.GhostModeError

CONFIG_PATH = os.path.join(REPO_ROOT, "config", "privacy", "00-null-default-prefs.js")
FIREFOX_ROOT = os.path.join(REPO_ROOT, "firefox")
DIST_BIN = r"C:\Users\Zaid\Projects\Null-Browser-build\obj-firefox\dist\bin"
XPCSHELL_EXE = os.path.join(DIST_BIN, "xpcshell.exe")
BROWSER_DIR = os.path.join(DIST_BIN, "browser")


def parse_prefs(filepath):
    """Parses a Firefox .js preference file into a dictionary."""
    prefs = {}
    pattern = re.compile(r'^\s*(?:pref|user_pref)\(\s*["\']([^"\']+)["\']\s*,\s*([^)]+)\)\s*;\s*(?://.*)?$')
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


class TestGhostModeCore(unittest.TestCase):
    """Comprehensive test suite for Ghost Mode and Tor architecture."""

    def test_01_ghost_state_machine_valid_transitions(self):
        """[UNIT] Verify strict linear Ghost state progression and listener notifications."""
        sm = GhostLifecycleStateMachine()
        self.assertEqual(sm.current_state, GhostState.DISABLED)
        self.assertFalse(sm.is_active)
        self.assertFalse(sm.is_ready)

        transitions = []
        sm.add_listener(lambda old_s, new_s: transitions.append((old_s, new_s)))

        # DISABLED -> STARTING
        sm.transition_to(GhostState.STARTING)
        self.assertEqual(sm.current_state, GhostState.STARTING)
        self.assertTrue(sm.is_active)
        self.assertFalse(sm.is_ready)

        # STARTING -> TOR_BOOTSTRAPPING
        sm.transition_to(GhostState.TOR_BOOTSTRAPPING)
        self.assertEqual(sm.current_state, GhostState.TOR_BOOTSTRAPPING)
        self.assertTrue(sm.is_active)
        self.assertFalse(sm.is_ready)

        # TOR_BOOTSTRAPPING -> READY
        sm.transition_to(GhostState.READY)
        self.assertEqual(sm.current_state, GhostState.READY)
        self.assertTrue(sm.is_active)
        self.assertTrue(sm.is_ready)

        # READY -> STOPPING
        sm.transition_to(GhostState.STOPPING)
        self.assertEqual(sm.current_state, GhostState.STOPPING)
        self.assertFalse(sm.is_ready)

        # STOPPING -> DISABLED
        sm.transition_to(GhostState.DISABLED)
        self.assertEqual(sm.current_state, GhostState.DISABLED)
        self.assertFalse(sm.is_active)
        self.assertFalse(sm.is_ready)

        expected = [
            (GhostState.DISABLED, GhostState.STARTING),
            (GhostState.STARTING, GhostState.TOR_BOOTSTRAPPING),
            (GhostState.TOR_BOOTSTRAPPING, GhostState.READY),
            (GhostState.READY, GhostState.STOPPING),
            (GhostState.STOPPING, GhostState.DISABLED),
        ]
        self.assertEqual(transitions, expected)

    def test_02_ghost_state_machine_invalid_transitions(self):
        """[UNIT] Verify invalid state transitions are strictly rejected with StateTransitionError."""
        sm = GhostLifecycleStateMachine()

        # Cannot jump from DISABLED directly to READY
        with self.assertRaises(StateTransitionError):
            sm.transition_to(GhostState.READY)

        # Cannot jump from DISABLED directly to TOR_BOOTSTRAPPING
        with self.assertRaises(StateTransitionError):
            sm.transition_to(GhostState.TOR_BOOTSTRAPPING)

        # Advance to STARTING
        sm.transition_to(GhostState.STARTING)

        # Cannot jump from STARTING to STOPPING
        with self.assertRaises(StateTransitionError):
            sm.transition_to(GhostState.STOPPING)

        # Advance to TOR_BOOTSTRAPPING
        sm.transition_to(GhostState.TOR_BOOTSTRAPPING)

        # Cannot jump from TOR_BOOTSTRAPPING back to STARTING
        with self.assertRaises(StateTransitionError):
            sm.transition_to(GhostState.STARTING)

    def test_03_ghost_state_machine_force_reset(self):
        """[UNIT] Verify force_reset() safely returns any state back to DISABLED."""
        sm = GhostLifecycleStateMachine()
        sm.transition_to(GhostState.STARTING)
        sm.transition_to(GhostState.TOR_BOOTSTRAPPING)

        sm.force_reset("Simulated Tor crash")
        self.assertEqual(sm.current_state, GhostState.DISABLED)
        self.assertEqual(sm.last_error, "Simulated Tor crash")
        self.assertFalse(sm.is_active)

    def test_04_ephemeral_profile_generation_and_user_js(self):
        """[INTEGRATION] Verify ephemeral profile creation and strict SOCKS5 Tor preferences."""
        with tempfile.TemporaryDirectory() as fake_downloads:
            pm = GhostProfileManager(socks_host="127.0.0.1", socks_port=9050, downloads_dir=fake_downloads)
            profile_dir = pm.create_ephemeral_profile()

            try:
                self.assertTrue(os.path.isdir(profile_dir))
                user_js = os.path.join(profile_dir, "user.js")
                self.assertTrue(os.path.isfile(user_js))

                prefs = parse_prefs(user_js)

                # SOCKS5 Tor Routing & Remote DNS
                self.assertEqual(prefs.get("network.proxy.type"), 1)
                self.assertEqual(prefs.get("network.proxy.socks"), "127.0.0.1")
                self.assertEqual(prefs.get("network.proxy.socks_port"), 9050)
                self.assertEqual(prefs.get("network.proxy.socks_version"), 5)
                self.assertEqual(prefs.get("network.proxy.socks5_remote_dns"), True)
                self.assertEqual(prefs.get("network.proxy.socks_remote_dns"), True)
                self.assertEqual(prefs.get("network.proxy.failover_direct"), False)
                self.assertEqual(prefs.get("network.proxy.no_proxies_on"), "")
                self.assertEqual(prefs.get("network.dns.blockDotOnion"), False)

                # Session Isolation & Ephemeral Memory
                self.assertEqual(prefs.get("browser.privatebrowsing.autostart"), True)
                self.assertEqual(prefs.get("privacy.history.custom"), True)
                self.assertEqual(prefs.get("places.history.enabled"), False)
                self.assertEqual(prefs.get("browser.formfill.enable"), False)
                self.assertEqual(prefs.get("browser.cache.disk.enable"), False)
                self.assertEqual(prefs.get("browser.cache.memory.enable"), True)

                # Extension Isolation
                self.assertEqual(prefs.get("extensions.autoDisableScopes"), 15)
                self.assertEqual(prefs.get("extensions.enabledScopes"), 0)

                # Downloads Preservation
                self.assertEqual(prefs.get("privacy.clearOnShutdown.downloads"), False)
                self.assertEqual(prefs.get("browser.download.folderList"), 2)

                # Core Hardening Preserved
                self.assertEqual(prefs.get("network.dns.disableIPv6"), True)
                self.assertEqual(prefs.get("media.peerconnection.enabled"), False)
                self.assertEqual(prefs.get("privacy.resistFingerprinting"), True)
                self.assertEqual(prefs.get("geo.enabled"), False)
                self.assertEqual(prefs.get("permissions.default.geo"), 2)

            finally:
                pm.cleanup(profile_dir)

    def test_05_profile_cleanup_preserves_user_downloads(self):
        """[INTEGRATION] Verify session cleanup obliterates ephemeral data while preserving user downloads."""
        with tempfile.TemporaryDirectory() as fake_downloads:
            # Create user download file
            download_file = os.path.join(fake_downloads, "important_download.pdf")
            with open(download_file, "w") as f:
                f.write("user downloaded document content")

            pm = GhostProfileManager(downloads_dir=fake_downloads)
            profile_dir = pm.create_ephemeral_profile()

            # Create ephemeral browser cache/storage inside profile
            profile_cache_file = os.path.join(profile_dir, "session_cache.dat")
            with open(profile_cache_file, "w") as f:
                f.write("ephemeral session cookies and cache")

            self.assertTrue(os.path.exists(profile_cache_file))
            self.assertTrue(os.path.exists(download_file))

            # Execute cleanup
            cleaned = pm.cleanup(profile_dir)
            self.assertTrue(cleaned)

            # Ephemeral profile must be gone
            self.assertFalse(os.path.exists(profile_dir))
            self.assertFalse(os.path.exists(profile_cache_file))

            # User download file MUST be completely intact
            self.assertTrue(os.path.exists(download_file))
            with open(download_file, "r") as f:
                self.assertEqual(f.read(), "user downloaded document content")

            # Safety check: cleanup refuses to wipe downloads directory
            self.assertFalse(pm.cleanup(fake_downloads))
            self.assertTrue(os.path.exists(download_file))

    def test_06_tor_supervisor_missing_binary_fails_closed(self):
        """[INTEGRATION] Verify fail-closed behavior when official Tor executable cannot be found."""
        bogus_config = TorConfig(binary_path=r"C:\non_existent_path\tor.exe")
        supervisor = TorSupervisor(config=bogus_config)

        self.assertFalse(supervisor.is_available())
        with self.assertRaises(TorExecutableNotFoundError):
            supervisor.start()

        self.assertFalse(supervisor.is_running)
        self.assertFalse(supervisor.is_bootstrapped)

        # Test GhostModeManager fail-closed handling
        manager = GhostModeManager(tor_config=bogus_config)
        self.assertEqual(manager.current_state, GhostState.DISABLED)

        with self.assertRaises(GhostModeError) as ctx:
            manager.enable_ghost_mode()

        self.assertIn("Tor binary not found", str(ctx.exception))
        # Manager must roll back to DISABLED and not leave active state
        self.assertEqual(manager.current_state, GhostState.DISABLED)
        self.assertFalse(manager.is_ghost_mode_active)
        self.assertFalse(manager.is_ghost_mode_ready)
        self.assertIsNone(manager.active_profile_path)

    def test_07_tor_supervisor_simulated_lifecycle_and_unexpected_exit(self):
        """[MOCK/SIMULATION] Verify supervisor bootstrap detection, listener check, and unexpected exit handling using a simulated mock daemon (NOT real Tor binary)."""
        # Find a free TCP port for testing
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
        s.close()

        # Create a mock tor script using Python
        mock_script = f"""
import sys, time, socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', {free_port}))
s.listen(1)

print('Bootstrapped 10%', flush=True)
time.sleep(0.1)
print('Bootstrapped 50%', flush=True)
time.sleep(0.1)
print('Bootstrapped 100% (done): Done', flush=True)

# Keep alive until terminated
try:
    while True:
        time.sleep(0.1)
except KeyboardInterrupt:
    pass
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(mock_script)
            mock_py = f.name

        # Wrapper bat/cmd or python runner
        if sys.platform == "win32":
            mock_cmd = f'@echo off\n"{sys.executable}" "{mock_py}" %*\n'
            mock_binary = mock_py.replace(".py", ".cmd")
            with open(mock_binary, "w") as f:
                f.write(mock_cmd)
        else:
            mock_binary = mock_py

        try:
            exit_events = []
            progress_events = []

            config = TorConfig(
                binary_path=mock_binary,
                socks_port=free_port,
                bootstrap_timeout_sec=5.0,
            )
            supervisor = TorSupervisor(
                config=config,
                on_unexpected_exit=lambda code, err: exit_events.append((code, err)),
                on_bootstrap_progress=lambda pct, msg: progress_events.append(pct),
            )

            # Start supervisor
            supervisor.start()
            self.assertTrue(supervisor.is_running)
            self.assertTrue(supervisor.is_bootstrapped)
            self.assertEqual(supervisor.bootstrap_percent, 100)
            self.assertIn(100, progress_events)

            # Simulate unexpected kill of the process
            proc_pid = supervisor.pid
            self.assertIsNotNone(proc_pid)
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc_pid)], capture_output=True)
            else:
                supervisor._process.kill()

            # Wait for monitor thread to catch termination
            time.sleep(1.0)

            self.assertFalse(supervisor.is_bootstrapped)
            self.assertTrue(len(exit_events) > 0)
            self.assertIn("terminated unexpectedly", supervisor.last_error or "")

        finally:
            if os.path.exists(mock_py):
                os.remove(mock_py)
            if sys.platform == "win32" and os.path.exists(mock_binary):
                os.remove(mock_binary)

    def test_08_firefox_launch_args_strict_isolation(self):
        """[UNIT] Verify launch arguments enforce session isolation (-no-remote -profile)."""
        manager = GhostModeManager()
        # When disabled, generating launch args must error
        with self.assertRaises(GhostModeError):
            manager.get_firefox_launch_args()

        # Manually set state to READY with a mock profile path
        manager.state_machine.transition_to(GhostState.STARTING)
        manager.state_machine.transition_to(GhostState.TOR_BOOTSTRAPPING)
        manager.state_machine.transition_to(GhostState.READY)
        manager._active_profile_path = r"C:\fake\ephemeral\profile"

        args = manager.get_firefox_launch_args()
        self.assertEqual(args, ["-no-remote", "-profile", r"C:\fake\ephemeral\profile"])

        # Reset back to disabled
        manager.state_machine.force_reset()

    def test_09_privileged_diagnostics_security_boundary(self):
        """[UNIT] Verify factual diagnostics reporting and security boundary constraints."""
        manager = GhostModeManager()
        report = manager.diagnostics.get_full_report()

        # Factual values (no fabricated metrics)
        self.assertEqual(report["ghost_mode"]["state"], "DISABLED")
        self.assertFalse(report["ghost_mode"]["is_active"])
        self.assertFalse(report["ghost_mode"]["is_ready"])
        self.assertFalse(report["tor_daemon"]["process_running"])
        self.assertFalse(report["tor_daemon"]["bootstrapped_100"])
        self.assertEqual(report["network_routing"]["proxy_type"], "SOCKS5")
        self.assertTrue(report["network_routing"]["remote_dns_enforced"])
        self.assertTrue(report["network_routing"]["fail_closed_direct_fallback_blocked"])
        self.assertEqual(report["network_routing"]["live_tor_network_connectivity"], "UNVERIFIED / PROPOSED")
        self.assertEqual(report["network_routing"]["live_onion_routing_tested"], "UNVERIFIED / PROPOSED")

        # Security boundary assertions
        self.assertTrue(report["security_boundaries"]["privileged_api_only"])
        self.assertFalse(report["security_boundaries"]["web_content_accessible"])

        # Fail-closed check
        self.assertTrue(manager.diagnostics.verify_fail_closed())

    def test_10_normal_browsing_remains_unproxied_by_default(self):
        """[INTEGRATION] Verify normal browsing config does NOT force SOCKS5 proxy (Ghost is strictly opt-in)."""
        default_prefs = parse_prefs(CONFIG_PATH)

        # Normal browsing must not have network.proxy.type = 1
        proxy_type = default_prefs.get("network.proxy.type")
        self.assertNotEqual(proxy_type, 1, "Normal browsing must not force manual proxy mode.")

        # Ensure no ghost prefs are in the default profile
        for pref in default_prefs:
            self.assertFalse(
                "ghost" in pref.lower() and not pref.startswith("places."),
                f"Ghost mode pref prematurely present in normal default prefs: {pref}",
            )

    def test_11_static_esr153_socks5_remote_dns_and_failclosed_evidence(self):
        """[STATIC/SOURCE] Static source verification: ESR 153.4.0 SOCKS5 remote DNS and failover behavior."""
        # 1. nsProtocolProxyService.cpp: socks5_remote_dns sets TRANSPARENT_PROXY_RESOLVES_HOST
        pps_path = os.path.join(FIREFOX_ROOT, "netwerk", "base", "nsProtocolProxyService.cpp")
        self.assertTrue(os.path.exists(pps_path), f"Source missing: {pps_path}")
        with open(pps_path, "r", encoding="utf-8-sig") as f:
            pps_code = f.read()

        self.assertIn('PROXY_PREF("socks5_remote_dns")', pps_code)
        self.assertIn("mSOCKS5ProxyRemoteDNS", pps_code)
        self.assertIn("SOCKSRemoteDNS()", pps_code)
        self.assertIn("nsIProxyInfo::TRANSPARENT_PROXY_RESOLVES_HOST", pps_code)

        # 2. nsSocketTransport2.cpp: mProxyTransparentResolvesHost enforces remote resolution
        st_path = os.path.join(FIREFOX_ROOT, "netwerk", "base", "nsSocketTransport2.cpp")
        self.assertTrue(os.path.exists(st_path), f"Source missing: {st_path}")
        with open(st_path, "r", encoding="utf-8-sig") as f:
            st_code = f.read()

        self.assertIn("mProxyTransparentResolvesHost", st_code)

        # 3. nsDNSService2.cpp: blockDotOnion prevents local DNS lookup leakage
        dns_path = os.path.join(FIREFOX_ROOT, "netwerk", "dns", "nsDNSService2.cpp")
        self.assertTrue(os.path.exists(dns_path), f"Source missing: {dns_path}")
        with open(dns_path, "r", encoding="utf-8-sig") as f:
            dns_code = f.read()

        self.assertIn("StaticPrefs::network_dns_blockDotOnion()", dns_code)
        self.assertIn("NS_ERROR_UNKNOWN_HOST", dns_code)

        # 4. StaticPrefList.yaml: verify pref definitions
        yaml_path = os.path.join(FIREFOX_ROOT, "modules", "libpref", "init", "StaticPrefList.yaml")
        self.assertTrue(os.path.exists(yaml_path), f"Source missing: {yaml_path}")
        with open(yaml_path, "r", encoding="utf-8-sig") as f:
            yaml_code = f.read()

        self.assertIn("network.proxy.socks5_remote_dns", yaml_code)
        self.assertIn("network.proxy.socks_remote_dns", yaml_code)
        self.assertIn("network.proxy.failover_direct", yaml_code)

    def test_12_runtime_gecko_socks5_fail_closed_rejection(self):
        """[RUNTIME] Runtime xpcshell test: verify Gecko fails closed when SOCKS5 proxy is unreachable."""
        # Port 59998 has no listener -> proxy connection must be refused and NOT leak directly
        js_code = """
        let finished = false;
        let finalStatus = 0;

        Services.prefs.setIntPref("network.proxy.type", 1);
        Services.prefs.setCharPref("network.proxy.socks", "127.0.0.1");
        Services.prefs.setIntPref("network.proxy.socks_port", 59998);
        Services.prefs.setIntPref("network.proxy.socks_version", 5);
        Services.prefs.setBoolPref("network.proxy.socks5_remote_dns", true);
        Services.prefs.setBoolPref("network.proxy.failover_direct", false);
        Services.prefs.setCharPref("network.proxy.no_proxies_on", "");
        Services.prefs.setBoolPref("network.proxy.allow_hijacking_localhost", true);

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
                onStartRequest: function(request) {},
                onStopRequest: function(request, status) {
                    finalStatus = status;
                    finished = true;
                },
                onDataAvailable: function(request, stream, offset, count) {}
            });
        } catch(e) {
            finalStatus = -1;
            finished = true;
        }

        let thread = Services.tm.currentThread;
        let start = Date.now();
        while (!finished && (Date.now() - start) < 4000) {
            thread.processNextEvent(true);
        }

        print("JSON_RESULT:" + JSON.stringify({
            finished: finished,
            status: finalStatus,
            failed_closed: (finalStatus !== Cr.NS_OK),
            is_proxy_refused: (finalStatus === Cr.NS_ERROR_PROXY_CONNECTION_REFUSED)
        }));
        quit(0);
        """
        result = run_xpcshell_script(js_code)
        self.assertTrue(result.get("failed_closed"), "Connection must fail when proxy is unreachable.")
        self.assertTrue(result.get("is_proxy_refused"), "Expected NS_ERROR_PROXY_CONNECTION_REFUSED.")

    def test_13_negative_constraints_preserved(self):
        """[STATIC/CONFIG] Verify unpermitted features (Panic Mode, Control Panel, Secure Mode) remain absent."""
        default_prefs = parse_prefs(CONFIG_PATH)
        for pref in default_prefs:
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

    def test_14_security_tor_config_rejects_external_hosts(self):
        """[UNIT/SECURITY] Verify TorConfig strictly rejects non-loopback hosts (prevents external listener exposure)."""
        # Reject 0.0.0.0 (binding to all interfaces)
        with self.assertRaises(ValueError):
            TorConfig(socks_host="0.0.0.0")

        # Reject public / LAN IP
        with self.assertRaises(ValueError):
            TorConfig(socks_host="192.168.1.100")

        # Reject invalid ports
        with self.assertRaises(ValueError):
            TorConfig(socks_port=-1)

        with self.assertRaises(ValueError):
            TorConfig(socks_port=70000)

        # Allow valid loopback addresses
        cfg1 = TorConfig(socks_host="127.0.0.1")
        self.assertEqual(cfg1.socks_host, "127.0.0.1")
        cfg2 = TorConfig(socks_host="localhost")
        self.assertEqual(cfg2.socks_host, "localhost")

        # Allow dynamic port allocation (None or 0)
        cfg3 = TorConfig(socks_port=None)
        self.assertIsNone(cfg3.socks_port)
        cfg4 = TorConfig(socks_port=0)
        self.assertEqual(cfg4.socks_port, 0)

    def test_15_security_cleanup_rejects_untracked_paths(self):
        """[UNIT/SECURITY] Verify GhostProfileManager cleanup strictly rejects untracked directories (prevents arbitrary deletion)."""
        with tempfile.TemporaryDirectory() as fake_downloads:
            pm = GhostProfileManager(downloads_dir=fake_downloads)

            # Create an external directory NOT created by pm
            with tempfile.TemporaryDirectory() as untracked_dir:
                victim_file = os.path.join(untracked_dir, "victim.txt")
                with open(victim_file, "w") as f:
                    f.write("important external file")

                # Cleanup must refuse to touch untracked_dir
                result = pm.cleanup(untracked_dir)
                self.assertFalse(result, "Cleanup must return False for untracked paths.")
                self.assertTrue(os.path.exists(victim_file), "Untracked directory must not be touched.")

    def test_16_tor_supervisor_detects_preoccupied_port_conflict(self):
        """[UNIT/SECURITY] Verify TorSupervisor refuses to launch and raises TorPortConflictError if target port is already occupied."""
        # Bind a socket to a loopback port with backlog to hold it occupied
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        occupied_port = listener.getsockname()[1]

        try:
            self.assertTrue(is_port_in_use("127.0.0.1", occupied_port))

            # Point supervisor at the occupied port with a valid executable
            config = TorConfig(binary_path=sys.executable, socks_port=occupied_port)
            supervisor = TorSupervisor(config=config)

            with self.assertRaises(TorPortConflictError) as ctx:
                supervisor.start()

            self.assertIn("already occupied", str(ctx.exception))
            self.assertFalse(supervisor.is_running)
        finally:
            listener.close()

    def test_17_windows_junction_cleanup_does_not_traverse_target(self):
        """[INTEGRATION/SECURITY] Verify cleanup unlinks NTFS directory junctions without deleting target contents."""
        if sys.platform != "win32":
            self.skipTest("Windows-specific junction cleanup test")

        with tempfile.TemporaryDirectory() as fake_downloads:
            # Create external directory with a critical file
            real_target = os.path.join(fake_downloads, "external_user_files")
            os.makedirs(real_target)
            victim_file = os.path.join(real_target, "precious_data.docx")
            with open(victim_file, "w") as f:
                f.write("important user data")

            pm = GhostProfileManager(downloads_dir=fake_downloads)
            profile_dir = pm.create_ephemeral_profile()

            # Create an NTFS directory junction inside the ephemeral profile pointing to real_target
            junction_path = os.path.join(profile_dir, "symlinked_folder")
            proc = subprocess.run(f'cmd /c mklink /J "{junction_path}" "{real_target}"', capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"mklink failed: {proc.stderr}")
            self.assertTrue(os.path.exists(junction_path))

            # Execute profile cleanup
            cleaned = pm.cleanup(profile_dir)
            self.assertTrue(cleaned)

            # Profile and junction must be gone
            self.assertFalse(os.path.exists(profile_dir))
            self.assertFalse(os.path.exists(junction_path))

            # External target files MUST remain intact and untouched!
            self.assertTrue(os.path.exists(real_target))
            self.assertTrue(os.path.exists(victim_file))
            with open(victim_file, "r") as f:
                self.assertEqual(f.read(), "important user data")

    def test_18_tor_supervisor_dynamic_port_allocation(self):
        """[UNIT] Verify dynamic localhost port allocation allocates an available free port."""
        port = find_available_loopback_port()
        self.assertGreater(port, 1024)
        self.assertLessEqual(port, 65535)

        # Ensure port is not currently occupied
        self.assertFalse(is_port_in_use("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main()
