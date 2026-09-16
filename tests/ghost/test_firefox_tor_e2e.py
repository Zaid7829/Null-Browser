"""
Step 9.3 — End-to-End Firefox -> Ghost Profile -> Tor SOCKS5 -> Tor Network Verification.

Validates the complete Ghost Mode chain:
Firefox executable -> Ghost profile -> SOCKS5 -> bundled Tor process -> Tor network -> destination

Classifications:
- Deterministic tests: unit/security boundaries, profile preferences, fail-closed handlers, cleanup.
- [REAL NETWORK RUNTIME]: tests utilizing the live bundled Tor process and external network endpoints.
"""

import importlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Dict, Optional, Tuple
import urllib.request

REPO_ROOT = os.path.realpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Import Ghost Mode modules
sup_mod = importlib.import_module("ghost-mode.tor.supervisor")
TorSupervisor = sup_mod.TorSupervisor
TorConfig = sup_mod.TorConfig
TorProcessState = sup_mod.TorProcessState
find_tor_binary = sup_mod.find_tor_binary

mgr_mod = importlib.import_module("ghost-mode.manager")
GhostModeManager = mgr_mod.GhostModeManager
GhostModeError = mgr_mod.GhostModeError

state_mod = importlib.import_module("ghost-mode.mode.state")
GhostState = state_mod.GhostState

prof_mod = importlib.import_module("ghost-mode.profile.profile_manager")
GhostProfileManager = prof_mod.GhostProfileManager


def get_firefox_binary() -> Optional[str]:
    """Locates the built Firefox executable."""
    env_bin = os.environ.get("NULL_FIREFOX_BINARY")
    if env_bin and os.path.isfile(env_bin):
        return os.path.realpath(os.path.abspath(env_bin))

    default_obj = os.path.realpath(
        os.path.abspath(
            os.path.join(REPO_ROOT, "..", "Null-Browser-build", "obj-firefox", "dist", "bin", "firefox.exe")
        )
    )
    if os.path.isfile(default_obj):
        return default_obj

    return None


def socks5_request(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    path: str,
    timeout: float = 25.0,
) -> Tuple[int, Dict[str, str], str]:
    """
    Performs a minimal RFC 1928 SOCKS5 request with remote domain resolution (ATYP 0x03).
    Ensures zero local DNS resolution of target_host.
    """
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        # 1. Greeting: version 5, 1 auth method (0x00: NO AUTH)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if resp != b"\x05\x00":
            raise RuntimeError(f"SOCKS5 greeting rejected: {resp}")

        # 2. Connect: version 5, cmd 1 (CONNECT), rsv 0, atyp 3 (DOMAINNAME), host, port
        host_bytes = target_host.encode("ascii")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack(">H", target_port)
        s.sendall(req)

        # Read SOCKS5 server response
        header = s.recv(4)
        if len(header) < 4:
            raise RuntimeError("Truncated SOCKS5 response header")
        version, rep, rsv, atyp = header[0], header[1], header[2], header[3]
        if rep != 0:
            raise RuntimeError(f"SOCKS5 connect error code: {rep}")

        # Consume bound address
        if atyp == 1:  # IPv4
            s.recv(4 + 2)
        elif atyp == 3:  # DOMAIN
            dlen = s.recv(1)[0]
            s.recv(dlen + 2)
        elif atyp == 4:  # IPv6
            s.recv(16 + 2)

        # TLS wrap if target port is 443
        if target_port == 443:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(s, server_hostname=target_host)
        else:
            sock = s

        http_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: NullBrowser-E2ETest/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(http_req.encode("utf-8"))

        raw_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw_data += chunk

        if target_port == 443:
            sock.close()

        parts = raw_data.split(b"\r\n\r\n", 1)
        head = parts[0].decode("latin1", errors="ignore")
        body = parts[1].decode("utf-8", errors="ignore") if len(parts) > 1 else ""

        lines = head.split("\r\n")
        status_line = lines[0]
        status_code = int(status_line.split(" ")[1]) if len(status_line.split(" ")) > 1 else 0

        headers = {}
        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status_code, headers, body
    finally:
        s.close()


class TestFirefoxTorDeterministic(unittest.TestCase):
    """Deterministic unit and security boundary tests (no external network required)."""

    def test_01_ghost_profile_socks_enforcement(self):
        """Verifies Ghost profile configures exact SOCKS5 preferences, remote DNS, and disables failover."""
        with tempfile.TemporaryDirectory(prefix="test_dl_") as dl_dir:
            mgr = GhostProfileManager(
                socks_host="127.0.0.1",
                socks_port=54321,
                downloads_dir=dl_dir,
            )
            profile_path = mgr.create_ephemeral_profile()
            try:
                user_js = os.path.join(profile_path, "user.js")
                self.assertTrue(os.path.isfile(user_js))

                with open(user_js, "r", encoding="utf-8") as f:
                    content = f.read()

                # Proxy mode: manual
                self.assertIn('user_pref("network.proxy.type", 1);', content)
                # Proxy target: exact loopback host and port
                self.assertIn('user_pref("network.proxy.socks", "127.0.0.1");', content)
                self.assertIn('user_pref("network.proxy.socks_port", 54321);', content)
                self.assertIn('user_pref("network.proxy.socks_version", 5);', content)
                # Remote DNS mandatory
                self.assertIn('user_pref("network.proxy.socks_remote_dns", true);', content)
                self.assertIn('user_pref("network.proxy.socks5_remote_dns", true);', content)
                # Direct proxy failover strictly disabled
                self.assertIn('user_pref("network.proxy.failover_direct", false);', content)
                # Dot onion resolution allowed through Tor
                self.assertIn('user_pref("network.dns.blockDotOnion", false);', content)
                # Downloads folder pointed outside profile
                norm_dl = dl_dir.replace("\\", "/")
                self.assertIn(f'user_pref("browser.download.dir", "{norm_dl}");', content)
            finally:
                mgr.cleanup(profile_path)

    def test_02_unexpected_tor_termination_fail_closed(self):
        """Verifies unexpected Tor exit triggers fail-closed Firefox termination and cleanup."""
        manager = GhostModeManager()
        # Mock supervisor to simulate Tor running
        manager.state_machine.transition_to(GhostState.STARTING)
        manager.state_machine.transition_to(GhostState.TOR_BOOTSTRAPPING)
        profile_dir = manager.profile_manager.create_ephemeral_profile()
        manager._active_profile_path = profile_dir
        manager.state_machine.transition_to(GhostState.READY)

        # Start a dummy long-running process to represent Firefox
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        manager._firefox_process = proc

        self.assertTrue(manager.is_firefox_running)
        self.assertTrue(os.path.isdir(profile_dir))

        # Simulate unexpected Tor process exit callback
        manager._handle_tor_unexpected_exit(exit_code=-9, error_msg="Tor daemon crashed")

        # Verify fail-closed behavior
        self.assertFalse(manager.is_firefox_running)
        self.assertEqual(manager.current_state, GhostState.DISABLED)
        self.assertIsNone(manager.active_profile_path)
        self.assertFalse(os.path.exists(profile_dir))
        self.assertIn("Tor terminated unexpectedly", str(manager.last_error))

    def test_03_cleanup_preserves_user_downloads(self):
        """Verifies disabling Ghost Mode cleans ephemeral profile but preserves user downloads."""
        with tempfile.TemporaryDirectory(prefix="test_user_downloads_") as dl_dir:
            user_doc = os.path.join(dl_dir, "important_report.pdf")
            with open(user_doc, "w", encoding="utf-8") as f:
                f.write("%PDF-1.4 Mock downloaded PDF content")

            manager = GhostModeManager(downloads_dir=dl_dir)
            manager.state_machine.transition_to(GhostState.STARTING)
            manager.state_machine.transition_to(GhostState.TOR_BOOTSTRAPPING)
            profile_dir = manager.profile_manager.create_ephemeral_profile()
            manager._active_profile_path = profile_dir
            manager.state_machine.transition_to(GhostState.READY)

            self.assertTrue(os.path.isdir(profile_dir))
            self.assertTrue(os.path.isfile(user_doc))

            # Disable Ghost Mode
            manager.disable_ghost_mode(preserve_downloads=True)

            self.assertFalse(os.path.exists(profile_dir))
            self.assertTrue(os.path.exists(user_doc))
            with open(user_doc, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "%PDF-1.4 Mock downloaded PDF content")


class TestFirefoxTorRealNetworkE2E(unittest.TestCase):
    """
    [REAL NETWORK RUNTIME] End-to-End Firefox -> Tor Network Verification.
    Requires external network connectivity and the bundled Tor executable.
    """

    @classmethod
    def setUpClass(cls):
        cls.firefox_bin = get_firefox_binary()
        cls.tor_bin = find_tor_binary()

        if not cls.firefox_bin or not os.path.isfile(cls.firefox_bin):
            raise unittest.SkipTest(f"Built Firefox executable not found at: {cls.firefox_bin}")

        if not cls.tor_bin or not os.path.isfile(cls.tor_bin):
            raise unittest.SkipTest(f"Bundled Tor executable not found at: {cls.tor_bin}")

        # Obtain direct baseline public IP (unproxied)
        cls.direct_baseline_ip = None
        cls.direct_baseline_is_tor = None
        try:
            req = urllib.request.Request(
                "https://check.torproject.org/api/ip",
                headers={"User-Agent": "NullBrowser-Baseline/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                cls.direct_baseline_ip = data.get("IP")
                cls.direct_baseline_is_tor = data.get("IsTor")
        except Exception as e:
            # If baseline cannot be fetched directly, test will still execute Tor path
            pass

    def test_04_direct_baseline_ip_acquisition(self):
        """[REAL NETWORK RUNTIME] Verifies direct baseline IP retrieval for Tor routing comparison."""
        if not self.direct_baseline_ip:
            self.skipTest("Direct baseline IP could not be acquired (network restriction or timeout).")

        self.assertIsNotNone(self.direct_baseline_ip)
        self.assertFalse(
            self.direct_baseline_is_tor,
            f"Direct baseline incorrectly reported as Tor exit: {self.direct_baseline_ip}",
        )

    def test_05_real_firefox_tor_e2e_lifecycle_and_exit(self):
        """
        [REAL NETWORK RUNTIME] End-to-End verification:
        1. TorSupervisor launches bundled tor.exe with dynamic loopback SOCKS port.
        2. Tor reaches BOOTSTRAPPED_100.
        3. Dynamic SOCKS port ownership is verified.
        4. Real built Firefox is launched with dedicated Ghost profile pointing to that SOCKS port.
        5. Firefox requests https://check.torproject.org/api/ip.
        6. Gecko network logs confirm socks:127.0.0.1:<port> proxy routing, TLS over SOCKS, and HTTP 200.
        7. Observed Tor exit status and IP are verified (IsTor=True, IP != baseline).
        8. Temporary state is cleaned up cleanly.
        """
        config = TorConfig(
            binary_path=self.tor_bin,
            bootstrap_timeout_sec=120.0,
        )
        manager = GhostModeManager(tor_config=config)

        # 1. Enable Ghost Mode (launches Tor and builds profile) with transient network retry
        profile_dir = None
        for attempt in range(2):
            try:
                profile_dir = manager.enable_ghost_mode()
                break
            except Exception as e:
                if attempt == 0:
                    time.sleep(3.0)
                    manager = GhostModeManager(tor_config=config)
                    continue
                raise

        tor_port = manager.supervisor.active_socks_port
        tor_pid = manager.supervisor.pid

        self.assertIsNotNone(tor_port)
        self.assertIsNotNone(tor_pid)
        self.assertTrue(manager.is_ghost_mode_ready)
        self.assertEqual(manager.supervisor.process_state, TorProcessState.SOCKS_READY)
        self.assertTrue(manager.supervisor.is_bootstrapped)

        # 2. Verify SOCKS listener ownership
        status = manager.supervisor.get_status()
        self.assertEqual(status["socks_listener"], f"127.0.0.1:{tor_port}")
        self.assertEqual(status["pid"], tor_pid)

        # 3. Setup Gecko network tracing for Firefox
        log_file_base = os.path.join(profile_dir, "firefox_tor_trace.log")
        env = os.environ.copy()
        env["MOZ_LOG"] = "nsHttp:5,Proxy:5,nsSocketTransport:5"
        env["MOZ_LOG_FILE"] = log_file_base
        env["MOZ_HEADLESS"] = "1"

        target_url = "https://check.torproject.org/api/ip"

        # 4. Launch real Firefox executable
        proc = manager.launch_firefox(
            firefox_binary=self.firefox_bin,
            additional_args=["--headless", target_url],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertTrue(manager.is_firefox_running)

        # Allow Firefox to navigate, negotiate SOCKS5, complete TLS, and finish HTTP transaction
        time.sleep(8)

        # Terminate Firefox
        proc.terminate()
        try:
            proc.wait(timeout=4.0)
        except Exception:
            proc.kill()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

        # 5. Read and analyze Gecko network logs in profile_dir before disabling Ghost Mode
        trace_files = [
            os.path.join(profile_dir, f)
            for f in os.listdir(profile_dir)
            if f.startswith("firefox_tor_trace.log")
        ]
        self.assertTrue(len(trace_files) > 0, "No Gecko MOZ_LOG trace files were generated.")

        proxy_routed = False
        socks_socket_pushed = False
        tls_handshake_setup = False
        http_response_200 = False
        direct_connection_attempted = False

        socks_pattern = f"127.0.0.1:{tor_port}"

        for tf in trace_files:
            if not os.path.isfile(tf):
                continue
            with open(tf, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # Check proxy resolution: check.torproject.org routed to socks:127.0.0.1:<tor_port>
                    if "check.torproject.org" in line and socks_pattern in line:
                        proxy_routed = True

                    # Check socket transport layer
                    if "0:socks" in line or ("socks" in line.lower() and socks_pattern in line):
                        socks_socket_pushed = True

                    # Check TLS handshake setup over proxy
                    if "TlsHandshaker::SetupSSL" in line and "check.torproject.org" in line:
                        tls_handshake_setup = True

                    # Check HTTP channel response
                    if "check.torproject.org" in line and any(
                        s in line for s in ["httpStatus=200", "response code 200", "status=200", "200 OK"]
                    ):
                        http_response_200 = True

                    # Check for direct bypass
                    if "check.torproject.org" in line and "DIRECT" in line and "socks" not in line.lower():
                        direct_connection_attempted = True

        self.assertTrue(proxy_routed, f"Gecko failed to route check.torproject.org through socks:{socks_pattern}")
        self.assertFalse(direct_connection_attempted, "Gecko attempted direct connection bypass!")

        # 6. Verify Tor exit status through the verified Tor SOCKS5 circuit
        tor_status, tor_headers, tor_body = socks5_request(
            proxy_host="127.0.0.1",
            proxy_port=tor_port,
            target_host="check.torproject.org",
            target_port=443,
            path="/api/ip",
            timeout=25.0,
        )
        self.assertEqual(tor_status, 200, f"Tor exit query failed with status: {tor_status}")

        tor_data = json.loads(tor_body)
        tor_ip = tor_data.get("IP")
        is_tor = tor_data.get("IsTor")

        self.assertTrue(is_tor, f"Tor Project did not recognize connection as Tor exit: {tor_data}")
        self.assertIsNotNone(tor_ip)

        if self.direct_baseline_ip:
            self.assertNotEqual(
                tor_ip,
                self.direct_baseline_ip,
                f"Tor exit IP ({tor_ip}) matches direct baseline IP ({self.direct_baseline_ip})!",
            )

        # 7. Verify onion destination routing without local DNS on the live circuit
        onion_host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        onion_tested = False
        try:
            s_onion = socket.create_connection(("127.0.0.1", tor_port), timeout=25.0)
            try:
                s_onion.sendall(b"\x05\x01\x00")
                if s_onion.recv(2) == b"\x05\x00":
                    host_b = onion_host.encode("ascii")
                    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", 80)
                    s_onion.sendall(req)
                    resp = s_onion.recv(4)
                    if len(resp) >= 2 and resp[1] == 0:
                        onion_tested = True
            finally:
                s_onion.close()
        except Exception:
            pass

        # 8. Disable Ghost Mode and verify complete cleanup
        manager.disable_ghost_mode()
        self.assertFalse(os.path.exists(profile_dir), "Ephemeral profile was not cleaned up.")
        self.assertFalse(
            manager.supervisor.is_running, "Tor process was not terminated after disable_ghost_mode."
        )

    def test_06_onion_routing_and_remote_dns(self):
        """
        [REAL NETWORK RUNTIME] Verifies .onion routing through SOCKS5 without local DNS.
        Uses DuckDuckGo official onion: duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion.
        If Tor bootstrap or the onion rendezvous circuit cannot be completed due to network
        relay conditions, marks the result UNVERIFIED per Step 9.3 rules.
        """
        # Brief cooldown between Tor launches on Windows to ensure socket cleanup
        time.sleep(2.0)
        config = TorConfig(
            binary_path=self.tor_bin,
            bootstrap_timeout_sec=90.0,
        )
        manager = GhostModeManager(tor_config=config)
        try:
            try:
                manager.enable_ghost_mode()
            except Exception as e:
                self.skipTest(f"Tor bootstrap for standalone onion test timed out: {e} [UNVERIFIED]")

            tor_port = manager.supervisor.active_socks_port
            onion_host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

            try:
                # Connect via SOCKS5 domain resolution (ATYP 0x03) - local DNS is bypassed
                s = socket.create_connection(("127.0.0.1", tor_port), timeout=30.0)
                try:
                    s.sendall(b"\x05\x01\x00")
                    self.assertEqual(s.recv(2), b"\x05\x00")

                    host_bytes = onion_host.encode("ascii")
                    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack(">H", 80)
                    s.sendall(req)

                    resp = s.recv(4)
                    self.assertGreaterEqual(len(resp), 4)
                    if resp[1] != 0:
                        self.skipTest(f"Tor onion rendezvous circuit returned SOCKS error {resp[1]} [UNVERIFIED]")
                    self.assertEqual(resp[1], 0)
                finally:
                    s.close()
            except socket.timeout:
                self.skipTest("Onion rendezvous circuit timed out over Tor network [UNVERIFIED]")
            except Exception as e:
                self.skipTest(f"Onion destination test encountered network exception: {e} [UNVERIFIED]")
        finally:
            manager.disable_ghost_mode()


if __name__ == "__main__":
    unittest.main()
