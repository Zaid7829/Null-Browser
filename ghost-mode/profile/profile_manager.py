"""
Ghost Profile Manager for Null Browser.

Creates, configures, and safely cleans up ephemeral Firefox profiles for Ghost Mode:
- Strictly isolated temporary profile directory (`-no-remote -profile <path>`).
- Enforces SOCKS5 routing to Tor with remote DNS.
- Enforces zero persistent disk history, formfill, passwords, or disk cache.
- Blocks extension inheritance (`extensions.autoDisableScopes = 15`, `extensions.enabledScopes = 0`).
- Strict cleanup upon session end.
- Preserves user-owned downloads: downloads directory is kept outside the ephemeral
  profile directory and is strictly preserved during cleanup.
"""

import os
import shutil
import sys
import tempfile
from typing import Dict, Optional, Set


class GhostProfileManager:
    """Manages creation and cleanup of isolated temporary Ghost Mode profiles."""

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        downloads_dir: Optional[str] = None,
    ):
        self.socks_host = socks_host
        self.socks_port = socks_port
        raw_downloads = downloads_dir or os.path.expanduser("~/Downloads")
        self.downloads_dir = os.path.realpath(os.path.abspath(raw_downloads))
        self._profile_dir: Optional[str] = None
        self._created_profiles: Set[str] = set()

    @property
    def current_profile_dir(self) -> Optional[str]:
        return self._profile_dir

    def create_ephemeral_profile(self) -> str:
        """
        Creates an isolated temporary profile directory and writes user.js with
        strict Tor routing, remote DNS, and ephemeral storage settings.
        Returns the absolute path to the profile directory.
        """
        profile_dir = tempfile.mkdtemp(prefix="null_ghost_profile_")
        canonical_dir = os.path.realpath(os.path.abspath(profile_dir))
        self._profile_dir = canonical_dir
        self._created_profiles.add(canonical_dir)

        # Write dedicated user.js
        user_js_path = os.path.join(canonical_dir, "user.js")
        prefs_content = self.generate_ghost_preferences()

        with open(user_js_path, "w", encoding="utf-8") as f:
            f.write(prefs_content)

        return canonical_dir

    def generate_ghost_preferences(self) -> str:
        """
        Generates the preference string for user.js in the ephemeral Ghost profile.
        Enforces Tor routing, SOCKS5 remote DNS, fail-closed policy, and zero persistent storage.
        """
        lines = [
            "// Null Browser Ghost Mode Ephemeral Profile Configuration",
            "// Generated dynamically - all data in this session is temporary.",
            "",
            "// --- SOCKS5 Tor Routing & Remote DNS ---",
            "user_pref(\"network.proxy.type\", 1);",
            f"user_pref(\"network.proxy.socks\", \"{self.socks_host}\");",
            f"user_pref(\"network.proxy.socks_port\", {self.socks_port});",
            "user_pref(\"network.proxy.socks_version\", 5);",
            "user_pref(\"network.proxy.socks5_remote_dns\", true);",
            "user_pref(\"network.proxy.socks_remote_dns\", true);",
            "user_pref(\"network.proxy.failover_direct\", false);",
            "user_pref(\"network.proxy.no_proxies_on\", \"\");",
            "// Allow .onion hostnames to pass to Tor SOCKS5 instead of being rejected by local DNS",
            "user_pref(\"network.dns.blockDotOnion\", false);",
            "",
            "// --- Session Isolation & Zero Persistence ---",
            "user_pref(\"browser.privatebrowsing.autostart\", true);",
            "user_pref(\"privacy.history.custom\", true);",
            "user_pref(\"places.history.enabled\", false);",
            "user_pref(\"browser.formfill.enable\", false);",
            "user_pref(\"signon.rememberSignons\", false);",
            "user_pref(\"browser.sessionstore.privacy_level\", 2);",
            "user_pref(\"privacy.clearOnShutdown.cookies\", true);",
            "user_pref(\"privacy.clearOnShutdown.history\", true);",
            "user_pref(\"privacy.clearOnShutdown.formdata\", true);",
            "user_pref(\"privacy.clearOnShutdown.downloads\", false); // User downloads preserved",
            "user_pref(\"privacy.clearOnShutdown.cache\", true);",
            "user_pref(\"privacy.clearOnShutdown.sessions\", true);",
            "",
            "// --- Ephemeral Cache & Storage (Memory Only) ---",
            "user_pref(\"browser.cache.disk.enable\", false);",
            "user_pref(\"browser.cache.memory.enable\", true);",
            "user_pref(\"browser.cache.offline.enable\", false);",
            "user_pref(\"network.cookie.cookieBehavior\", 1); // Reject third-party cookies",
            "user_pref(\"dom.indexedDB.enabled\", true); // Memory/session scoped in private browsing",
            "",
            "// --- Extension & Addon Isolation ---",
            "user_pref(\"extensions.autoDisableScopes\", 15);",
            "user_pref(\"extensions.enabledScopes\", 0);",
            "",
            "// --- Preserved Step 6 / Step 7 Core Hardening ---",
            "user_pref(\"network.dns.disableIPv6\", true);",
            "user_pref(\"media.peerconnection.enabled\", false);",
            "user_pref(\"media.peerconnection.ice.proxy_only\", true);",
            "user_pref(\"media.peerconnection.ice.default_address_only\", true);",
            "user_pref(\"dom.webrtc.transports.ice.enforce_interface\", \"lo\");",
            "user_pref(\"dom.security.https_only_mode\", true);",
            "user_pref(\"privacy.resistFingerprinting\", true);",
            "user_pref(\"privacy.spoof_english\", 2);",
            "user_pref(\"geo.enabled\", false);",
            "user_pref(\"permissions.default.geo\", 2);",
            "",
            "// --- Downloads Destination (Outside Ephemeral Directory) ---",
            f"user_pref(\"browser.download.dir\", \"{self.downloads_dir.replace(chr(92), '/')}\");",
            "user_pref(\"browser.download.folderList\", 2);",
            "user_pref(\"browser.download.useDownloadDir\", true);",
            "",
        ]
        return "\n".join(lines)

    def cleanup(self, profile_dir: Optional[str] = None) -> bool:
        """
        Cleans up the ephemeral profile directory.
        WINDOWS REPARSE POINT & TOCTOU SECURITY AUDIT:
        - Only removes directories tracked in _created_profiles to prevent deletion outside the profile.
        - Canonicalizes paths with realpath.
        - Checks root target with lstat: if target is a reparse point/junction, unlinks it directly
          without calling recursive rmtree.
        - Child directory junctions/symlinks are unlinked without traversing into their targets,
          protecting user files outside the profile (e.g., Downloads, Documents).
        - Explicit TOCTOU Boundary: Userland validation mitigates junction traversal, but cannot
          eliminate kernel-level filesystem TOCTOU races if an attacker has concurrent local write
          access to the temp directory.
        Returns True if cleanup succeeded, False otherwise.
        """
        target = profile_dir or self._profile_dir
        if not target:
            return True

        target_real = os.path.realpath(os.path.abspath(target))
        downloads_real = self.downloads_dir

        # Safety check 1: Target must have been created by this manager instance
        if target_real not in self._created_profiles:
            return False

        # Safety check 2: Target must not be or contain the downloads dir, or vice versa
        if target_real == downloads_real or downloads_real.startswith(target_real):
            return False

        # Safety check 3: Target must not be system temp directory itself
        if target_real == os.path.realpath(tempfile.gettempdir()):
            return False

        if not os.path.exists(target_real):
            self._created_profiles.discard(target_real)
            if self._profile_dir == target_real:
                self._profile_dir = None
            return True

        # Check if root target itself is a reparse point / junction
        try:
            st = os.lstat(target_real)
            import stat
            is_reparse = bool(
                (sys.platform == "win32" and (st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT))
                or os.path.islink(target_real)
            )
            if is_reparse:
                os.unlink(target_real)
                self._created_profiles.discard(target_real)
                if self._profile_dir == target_real:
                    self._profile_dir = None
                return not os.path.exists(target_real)
        except Exception:
            pass

        def _handle_remove_readonly(func, path, exc):
            """Error handler for read-only or locked files on Windows."""
            import stat
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass

        try:
            shutil.rmtree(target_real, onexc=_handle_remove_readonly)
            self._created_profiles.discard(target_real)
            if self._profile_dir == target_real:
                self._profile_dir = None
            return not os.path.exists(target_real)
        except Exception:
            return False

    def cleanup_all(self) -> int:
        """Cleans up all tracked ephemeral profiles created by this manager instance."""
        cleaned = 0
        for p in list(self._created_profiles):
            if self.cleanup(p):
                cleaned += 1
        return cleaned
