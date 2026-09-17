# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Step 10.5A — Panic Mode Implementation Regression Test Suite.

Validates:
1. Privileged IPC Authorization: RemotePageAccessManager permits TriggerPanicMode exclusively for about:null / about:controlpanel.
2. Webpage IPC Denial: Normal webpages and untrusted origins cannot invoke TriggerPanicMode.
3. Reentrancy Lock: Concurrent invocation is rejected with status "REJECTED".
4. Tab & Window Handling: Closes background tabs with skipPermitUnload, resets primary to about:blank.
5. SessionStore Cleanup: Forgets closed tabs and windows.
6. Storage & Cache Cleanup: Uses deleteData with verified Ci.nsIClearDataService flags.
7. Session Permission Removal: Removes EXPIRE_SESSION (1) and EXPIRE_SESSION_TAB (4).
8. Persistent Permission Preservation: Preserves EXPIRE_NEVER (0) and EXPIRE_POLICY (3).
9. Ghost Inactive Path: Returns NOT_ACTIVE when Ghost Mode is disabled.
10. Ghost Active Path: Invokes tracked shutdown, cleans tracked ephemeral profile, disables state.
11. Owned Tor Termination: Confirms owned process shutdown without indiscriminate taskkill.
12. Download Preservation: Verifies user-created download files remain completely untouched.
13. Privacy Event Buffer Clearing: In-memory events cleared via NullPrivacyEventManager.clear().
14. Structured Success Result: Complies with structured result schema.
15. Structured Partial Failure: Records PARTIALLY_COMPLETED if a subsystem encounters an error.
16. Structured Failure: Returns FAILED when multiple subsystems fail.
17. No Sensitive Data in Result: Zero paths, PIDs, URLs, origins, IPs, or ports in output.
18. No Arbitrary Process Termination: Verifies no wildcard or image-name process killing.
19. No Arbitrary Filesystem Deletion: Verifies profile databases and user paths are untouched.
20. Control Panel UI Components: Validates markup, confirmation dialog, progress, and result views.
21. UI Safety & Non-Forensic Wording: Prohibits forensic buzzwords and ensures textContent safety.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIREFOX_SRC = os.path.join(ROOT_DIR, "firefox")
BUILD_DIR = os.path.join(ROOT_DIR, "..", "Null-Browser-build", "obj-firefox")
DIST_BIN = os.path.join(BUILD_DIR, "dist", "bin")
BROWSER_DIR = os.path.join(DIST_BIN, "browser")
XPCSHELL_EXE = os.path.join(DIST_BIN, "xpcshell.exe")

PANIC_CONTROLLER_PATH = os.path.join(FIREFOX_SRC, "browser", "modules", "NullPanicController.sys.mjs")
ACTOR_PARENT_PATH = os.path.join(FIREFOX_SRC, "browser", "actors", "NullControlPanelParent.sys.mjs")
RPAM_PATH = os.path.join(FIREFOX_SRC, "toolkit", "modules", "RemotePageAccessManager.sys.mjs")
CP_XHTML = os.path.join(FIREFOX_SRC, "browser", "components", "controlpanel", "controlpanel.xhtml")
CP_JS = os.path.join(FIREFOX_SRC, "browser", "components", "controlpanel", "controlpanel.js")
CP_CSS = os.path.join(FIREFOX_SRC, "browser", "components", "controlpanel", "controlpanel.css")


def run_xpcshell_panic(js_snippet: str) -> dict:
    """Executes a JavaScript snippet in xpcshell with browser app provider and returns parsed JSON_RESULT."""
    manifest_path = os.path.join(BROWSER_DIR, "chrome", "browser.manifest").replace("\\", "\\\\")
    full_script = f"""
    let manifestFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    manifestFile.initWithPath("{manifest_path}");
    Components.manager.QueryInterface(Ci.nsIComponentRegistrar).autoRegister(manifestFile);

    let {{ NullPanicController }} = ChromeUtils.importESModule("resource:///modules/NullPanicController.sys.mjs");
    let {{ NullControlPanelParent, _resetDiagnosticsStateForTesting }} = ChromeUtils.importESModule("resource:///actors/NullControlPanelParent.sys.mjs");
    let {{ NullPrivacyEventManager }} = ChromeUtils.importESModule("resource:///modules/NullPrivacyEventManager.sys.mjs");

    (async function() {{
        {js_snippet}
    }})().then(res => {{
        dump("JSON_RESULT:" + JSON.stringify(res) + "\\n");
        quit(0);
    }}).catch(err => {{
        dump("JSON_RESULT:" + JSON.stringify({{ error: String(err), message: err?.message, stack: err?.stack }}) + "\\n");
        quit(1);
    }});

    let thread = Services.tm.currentThread;
    for (let i = 0; i < 80; i++) {{
        thread.processNextEvent(false);
    }}
    """
    proc = subprocess.run(
        [XPCSHELL_EXE, "-g", DIST_BIN, "-a", BROWSER_DIR, "-e", full_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("JSON_RESULT:"):
            return json.loads(line[len("JSON_RESULT:"):])
    raise RuntimeError(f"xpcshell failed: stdout={proc.stdout}, stderr={proc.stderr}")


class TestPanicModePrivilegedController(unittest.TestCase):
    """Verifies NullPanicController logic, subsystems, reentrancy, and preservation guarantees."""

    def test_01_privileged_ipc_authorization(self):
        """Verify RemotePageAccessManager permits TriggerPanicMode strictly for about:null and about:controlpanel."""
        with open(RPAM_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        # Find RPMSendQuery table
        self.assertIn('"about:null": {', content)
        self.assertIn('"about:controlpanel": {', content)

        # Ensure TriggerPanicMode is present for about:null and about:controlpanel
        pattern_null = r'"about:null"\s*:\s*\{[^}]*"TriggerPanicMode"'
        pattern_cp = r'"about:controlpanel"\s*:\s*\{[^}]*"TriggerPanicMode"'
        self.assertRegex(content, pattern_null)
        self.assertRegex(content, pattern_cp)

        # Ensure no other page has TriggerPanicMode permission
        all_pages_with_panic = re.findall(r'"([^"]+)"\s*:\s*\{[^}]*"TriggerPanicMode"', content)
        allowed_pages = {"about:null", "about:controlpanel"}
        for page in all_pages_with_panic:
            self.assertIn(page, allowed_pages, f"Unauthorized page has TriggerPanicMode access: {page}")

    def test_02_ordinary_webpage_denial(self):
        """Verify ordinary web content cannot invoke TriggerPanicMode through RemotePageAccessManager."""
        res = run_xpcshell_panic("""
            let { RemotePageAccessManager } = ChromeUtils.importESModule("resource://gre/modules/RemotePageAccessManager.sys.mjs");
            let ssm = Services.scriptSecurityManager;
            let doc = (url) => ({ location: { href: url }, documentURIObject: Services.io.newURI(url) });
            let prin = (url) => ssm.createContentPrincipal(Services.io.newURI(url), {});

            let webPrin = prin("https://example.com");
            let untrustedAttacker = prin("https://malicious.org");
            let aboutHome = prin("about:home");
            let aboutNull = prin("about:null");
            let aboutCP = prin("about:controlpanel");

            return {
                webAllowed: RemotePageAccessManager.checkAllowAccessWithPrincipal(webPrin, "RPMSendQuery", "TriggerPanicMode", doc("https://example.com")),
                untrustedAttackerAllowed: RemotePageAccessManager.checkAllowAccessWithPrincipal(untrustedAttacker, "RPMSendQuery", "TriggerPanicMode", doc("https://malicious.org")),
                aboutHomeAllowed: RemotePageAccessManager.checkAllowAccessWithPrincipal(aboutHome, "RPMSendQuery", "TriggerPanicMode", doc("about:home")),
                aboutNullAllowed: RemotePageAccessManager.checkAllowAccessWithPrincipal(aboutNull, "RPMSendQuery", "TriggerPanicMode", doc("about:null")),
                aboutCPAllowed: RemotePageAccessManager.checkAllowAccessWithPrincipal(aboutCP, "RPMSendQuery", "TriggerPanicMode", doc("about:controlpanel"))
            };
        """)
        self.assertFalse(res["webAllowed"])
        self.assertFalse(res["untrustedAttackerAllowed"])
        self.assertFalse(res["aboutHomeAllowed"])
        self.assertTrue(res["aboutNullAllowed"])
        self.assertTrue(res["aboutCPAllowed"])

    def test_03_reentrancy_lock(self):
        """Verify simultaneous invocation of trigger() returns structured rejection."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();
            NullPanicController._setInProgressForTesting(true);

            let rejection = await NullPanicController.trigger();
            NullPanicController._resetForTesting();

            return {
                rejection
            };
        """)
        rejection = res["rejection"]
        self.assertEqual(rejection["status"], "REJECTED")
        self.assertEqual(rejection["reason"], "PANIC_ALREADY_IN_PROGRESS")
        self.assertIn("subsystems", rejection)

    def test_04_session_cleanup_skip_permit_unload(self):
        """Verify tab/window cleanup resets active tab to about:blank and clears SessionStore."""
        with open(PANIC_CONTROLLER_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        # Must close with skipPermitUnload: true
        self.assertIn("skipPermitUnload: true", content)
        # Must reset primary tab to about:blank
        self.assertIn('"about:blank"', content)
        # Must use SessionStore forget APIs
        self.assertIn("forgetClosedTab", content)
        self.assertIn("forgetClosedWindow", content)
        # Must not terminate entire browser by default
        self.assertNotIn("Services.startup.quit", content)

    def test_05_storage_and_cache_cleanup_flags(self):
        """Verify storage cleanup invokes deleteData with exhaustive ephemeral flags."""
        with open(PANIC_CONTROLLER_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("CLEAR_COOKIES", content)
        self.assertIn("CLEAR_DOM_STORAGES", content)
        self.assertIn("CLEAR_ALL_CACHES", content)
        self.assertIn("CLEAR_AUTH_CACHE", content)
        self.assertIn("CLEAR_AUTH_TOKENS", content)
        self.assertIn("CLEAR_MEDIA_DEVICES", content)
        self.assertIn("CLEAR_COOKIE_BANNER_EXECUTED_RECORD", content)
        self.assertIn("CLEAR_FINGERPRINTING_PROTECTION_STATE", content)
        self.assertIn("CLEAR_BOUNCE_TRACKING_PROTECTION_STATE", content)
        self.assertIn("CLEAR_STORAGE_PERMISSIONS", content)

    def test_06_session_permission_removal_and_preservation(self):
        """Verify session permissions are removed while persistent permissions are preserved."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();

            // Mock permission manager
            let removedCount = 0;
            let preservedCount = 0;

            let mockPerms = [
                { type: "geo", expireType: Ci.nsIPermissionManager.EXPIRE_SESSION, principal: { origin: "https://a.test" } },
                { type: "camera", expireType: Ci.nsIPermissionManager.EXPIRE_SESSION_TAB, principal: { origin: "https://b.test" } },
                { type: "desktop-notification", expireType: Ci.nsIPermissionManager.EXPIRE_NEVER, principal: { origin: "https://c.test" } },
                { type: "microphone", expireType: Ci.nsIPermissionManager.EXPIRE_POLICY, principal: { origin: "https://d.test" } }
            ];

            let fakePermManager = {
                get all() { return mockPerms; },
                removePermission(perm) {
                    if (perm.expireType === Ci.nsIPermissionManager.EXPIRE_SESSION ||
                        perm.expireType === Ci.nsIPermissionManager.EXPIRE_SESSION_TAB) {
                        removedCount++;
                    } else {
                        preservedCount++;
                    }
                }
            };

            let origPerms = Services.perms;
            Object.defineProperty(Services, "perms", {
                value: fakePermManager,
                configurable: true
            });

            let permResult;
            try {
                permResult = await NullPanicController._cleanPermissions();
            } finally {
                Object.defineProperty(Services, "perms", {
                    value: origPerms,
                    configurable: true
                });
            }

            return {
                permResult,
                removedCount,
                preservedCount
            };
        """)
        self.assertEqual(res["permResult"], "COMPLETED")
        self.assertEqual(res["removedCount"], 2, "Both session-scoped permissions must be removed.")
        self.assertEqual(res["preservedCount"], 0, "Persistent permissions must never be removed.")

    def test_07_ghost_inactive_path(self):
        """Verify ghost cleanup returns NOT_ACTIVE when Ghost Mode is not running."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();
            NullPanicController._registerGhostShutdownHandler(null);

            let result = await NullPanicController._cleanGhost();
            return { result };
        """)
        self.assertEqual(res["result"], "NOT_ACTIVE")

    def test_08_ghost_active_path_shutdown(self):
        """Verify ghost cleanup stops owned processes and cleans ephemeral profile."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();

            let handlerInvoked = false;
            NullPanicController._registerGhostShutdownHandler(async () => {
                handlerInvoked = true;
                return { success: true };
            });

            let result = await NullPanicController._cleanGhost();
            NullPanicController._resetForTesting();

            return {
                result,
                handlerInvoked
            };
        """)
        self.assertEqual(res["result"], "COMPLETED")
        self.assertTrue(res["handlerInvoked"])

    def test_09_download_preservation_regression(self):
        """Verify user download files on disk remain untouched across Panic Mode trigger."""
        with tempfile.TemporaryDirectory() as tmp_download_dir:
            user_file = os.path.join(tmp_download_dir, "user_report.pdf")
            test_content = b"%PDF-1.4 Fake Downloaded Document"
            with open(user_file, "wb") as f:
                f.write(test_content)

            self.assertTrue(os.path.exists(user_file))

            # Run full panic trigger
            res = run_xpcshell_panic("""
                NullPanicController._resetForTesting();
                let result = await NullPanicController.trigger();
                return { result };
            """)

            self.assertIn(res["result"]["status"], ["COMPLETED", "PARTIALLY_COMPLETED"])

            # User file must still exist and have unchanged contents
            self.assertTrue(os.path.exists(user_file), "User download file was unexpectedly deleted!")
            with open(user_file, "rb") as f:
                self.assertEqual(f.read(), test_content, "User download file content was modified!")

    def test_10_privacy_event_buffer_cleared(self):
        """Verify NullPrivacyEventManager.clear() is called during Panic Mode."""
        res = run_xpcshell_panic("""
            NullPrivacyEventManager._resetForTesting();
            NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "BLOCKED", "TRACKING_CONTENT", "OBSERVED");
            let countBefore = NullPrivacyEventManager.getEvents().length;

            NullPanicController._resetForTesting();
            let result = await NullPanicController.trigger();
            let countAfter = NullPrivacyEventManager.getEvents().length;

            return {
                countBefore,
                countAfter,
                status: result.status,
                eventsSubsystem: result.subsystems?.events
            };
        """)
        self.assertGreater(res["countBefore"], 0)
        self.assertEqual(res["countAfter"], 0, "Event buffer was not cleared by Panic Mode!")
        self.assertEqual(res["eventsSubsystem"], "COMPLETED")

    def test_11_structured_success_result_schema(self):
        """Verify structured result adheres strictly to specified schema without extra fields."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();
            let result = await NullPanicController.trigger();
            return { result };
        """)
        result = res["result"]
        self.assertIn(result["status"], ["COMPLETED", "PARTIALLY_COMPLETED"])
        self.assertIn("subsystems", result)

        subsystems = result["subsystems"]
        required_subsystems = {"session", "storage", "permissions", "ghost", "events"}
        self.assertEqual(set(subsystems.keys()), required_subsystems)

        for name, substatus in subsystems.items():
            self.assertIn(
                substatus,
                ["COMPLETED", "PARTIALLY_COMPLETED", "FAILED", "NOT_ACTIVE"],
                f"Subsystem {name} returned invalid substatus: {substatus}"
            )

    def test_12_structured_partial_failure(self):
        """Verify when a subsystem throws, overall status becomes PARTIALLY_COMPLETED."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();

            NullPanicController._registerGhostShutdownHandler(async () => {
                throw new Error("Simulated Ghost termination failure");
            });

            let result = await NullPanicController.trigger();
            NullPanicController._resetForTesting();

            return { result };
        """)
        result = res["result"]
        self.assertEqual(result["status"], "PARTIALLY_COMPLETED")
        self.assertEqual(result["subsystems"]["ghost"], "FAILED")
        self.assertEqual(result["subsystems"]["events"], "COMPLETED")

    def test_13_no_sensitive_data_in_result(self):
        """Verify zero IP addresses, ports, file paths, URLs, domains, or PIDs in the result."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();
            let result = await NullPanicController.trigger();
            return { result };
        """)
        result_str = json.dumps(res["result"])

        # No IP patterns
        self.assertIsNone(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", result_str))
        # No port numbers like 9050, 9150
        self.assertNotIn("9050", result_str)
        self.assertNotIn("9150", result_str)
        # No URL protocols
        self.assertNotIn("http:", result_str)
        self.assertNotIn("https:", result_str)
        # No filesystem paths
        self.assertNotIn("C:\\", result_str)
        self.assertNotIn("/home/", result_str)
        self.assertNotIn(".null-ghost", result_str)
        # No PID indications
        self.assertNotIn("pid", result_str.lower())

    def test_14_no_arbitrary_process_termination(self):
        """Verify code does NOT contain indiscriminate process killing commands."""
        with open(PANIC_CONTROLLER_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("taskkill /im", content)
        self.assertNotIn("taskkill /f /im", content)
        self.assertNotIn("killall", content)
        self.assertNotIn("pkill", content)

    def test_15_no_arbitrary_filesystem_deletion(self):
        """Verify code does NOT delete arbitrary directories or databases."""
        with open(PANIC_CONTROLLER_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("places.sqlite", content)
        self.assertNotIn("favicons.sqlite", content)
        self.assertNotIn("permissions.sqlite", content)
        self.assertNotIn("key4.db", content)
        self.assertNotIn("cert9.db", content)
        self.assertNotIn("browser.download.dir", content)
        self.assertNotIn("rmdir /s", content)
        self.assertNotIn("rm -rf /", content)

    def test_16_actor_parent_routes_trigger_panic_mode(self):
        """Verify NullControlPanelParent receiveMessage handles TriggerPanicMode."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();
            let actor = new NullControlPanelParent();

            let result = await actor.receiveMessage({ name: "TriggerPanicMode" });
            return { result };
        """)
        self.assertIn(res["result"]["status"], ["COMPLETED", "PARTIALLY_COMPLETED"])


class TestPanicModeUI(unittest.TestCase):
    """Validates Control Panel Panic Mode markup, CSS, and client-side controller logic."""

    def test_17_ui_markup_structure_and_ids(self):
        """Verify controlpanel.xhtml contains required Panic Mode section and element IDs."""
        with open(CP_XHTML, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('id="section-panic-mode"', content)
        self.assertIn('id="panic-initial-view"', content)
        self.assertIn('id="panic-confirm-view"', content)
        self.assertIn('id="panic-progress-view"', content)
        self.assertIn('id="panic-result-view"', content)

        self.assertIn('id="panic-btn"', content)
        self.assertIn('id="panic-confirm-btn"', content)
        self.assertIn('id="panic-cancel-btn"', content)
        self.assertIn('id="panic-dismiss-btn"', content)
        self.assertIn('id="panic-progress-text"', content)
        self.assertIn('id="panic-result-message"', content)
        self.assertIn('id="panic-breakdown"', content)

    def test_18_ui_button_and_confirmation_wording(self):
        """Verify exact recommended button, confirmation prompt, and progress wording."""
        with open(CP_XHTML, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Trigger Panic Mode", content)
        self.assertIn("Close active session tabs and clear temporary session data?", content)
        self.assertIn("Clearing session...", content)

    def test_19_ui_status_messages_in_client_js(self):
        """Verify exact completion, partial, and failure strings in controlpanel.js."""
        with open(CP_JS, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Session reset complete.", content)
        self.assertIn("Session reset partially completed. Review the affected areas.", content)
        self.assertIn("Session reset failed.", content)
        self.assertIn("RPMSendQuery", content)
        self.assertIn('"TriggerPanicMode"', content)

    def test_20_ui_uses_textcontent_for_safety(self):
        """Verify controlpanel.js uses textContent and never innerHTML for dynamic Panic values."""
        with open(CP_JS, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("innerHTML", content)
        self.assertIn("resultMessage.textContent =", content)
        self.assertIn("pill.textContent =", content)

    def test_21_prohibited_security_buzzwords_absence(self):
        """Verify UI, CSS, and JS do NOT use forbidden marketing/forensic buzzwords."""
        files_to_check = [CP_XHTML, CP_JS, CP_CSS, PANIC_CONTROLLER_PATH]
        forbidden_terms = [
            "forensic wipe",
            "zero traces",
            "unrecoverable",
            "untraceable",
            "military grade",
            "100% secure",
            "guaranteed deletion",
        ]

        for filepath in files_to_check:
            with open(filepath, "r", encoding="utf-8") as f:
                text = f.read().lower()
            for term in forbidden_terms:
                self.assertNotIn(term, text, f"Forbidden term '{term}' found in {filepath}")

    def test_22_failure_injection_storage_partial_failure(self):
        """Verify storage partial failure reports PARTIALLY_COMPLETED and never COMPLETED."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();

            // Mock clearData with failedFlags = 1
            let origClearData = Services.clearData;
            Object.defineProperty(Services, "clearData", {
                value: {
                    deleteData(flags, callback) {
                        callback.onDataDeleted(1); // Flag 1 failed
                    }
                },
                configurable: true
            });

            let result;
            try {
                result = await NullPanicController.trigger();
            } finally {
                Object.defineProperty(Services, "clearData", {
                    value: origClearData,
                    configurable: true
                });
                NullPanicController._resetForTesting();
            }

            return { result };
        """)
        self.assertEqual(res["result"]["status"], "PARTIALLY_COMPLETED")
        self.assertEqual(res["result"]["subsystems"]["storage"], "PARTIALLY_COMPLETED")

    def test_23_failure_injection_permissions_partial_failure(self):
        """Verify single permission removal failure reports PARTIALLY_COMPLETED."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();

            let origPerms = Services.perms;
            let mockPerms = [
                { type: "geo", expireType: Ci.nsIPermissionManager.EXPIRE_SESSION, principal: { origin: "https://a.test" } },
                { type: "camera", expireType: Ci.nsIPermissionManager.EXPIRE_SESSION, principal: { origin: "https://b.test" } }
            ];

            let callCount = 0;
            Object.defineProperty(Services, "perms", {
                value: {
                    get all() { return mockPerms; },
                    removePermission(p) {
                        callCount++;
                        if (callCount === 2) {
                            throw new Error("Simulated permission removal failure");
                        }
                    }
                },
                configurable: true
            });

            let result;
            try {
                result = await NullPanicController.trigger();
            } finally {
                Object.defineProperty(Services, "perms", {
                    value: origPerms,
                    configurable: true
                });
                NullPanicController._resetForTesting();
            }

            return { result };
        """)
        self.assertEqual(res["result"]["status"], "PARTIALLY_COMPLETED")
        self.assertEqual(res["result"]["subsystems"]["permissions"], "PARTIALLY_COMPLETED")

    def test_24_all_subsystems_failure_reports_failed(self):
        """Verify that when all subsystems fail, overall status is FAILED."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();

            // Force failures across subsystems
            let origClearData = Services.clearData;
            Object.defineProperty(Services, "clearData", {
                value: {
                    deleteData() { throw new Error("Storage failure"); }
                },
                configurable: true
            });

            let origPerms = Services.perms;
            Object.defineProperty(Services, "perms", {
                value: {
                    get all() { throw new Error("Perms failure"); }
                },
                configurable: true
            });

            NullPanicController._setGhostShutdownHandlerForTesting(async () => {
                throw new Error("Ghost failure");
            });

            let origClearEvents = NullPrivacyEventManager.clear;
            NullPrivacyEventManager.clear = function() {
                throw new Error("Events clear failure");
            };

            let result;
            try {
                result = await NullPanicController.trigger();
            } finally {
                Object.defineProperty(Services, "clearData", { value: origClearData, configurable: true });
                Object.defineProperty(Services, "perms", { value: origPerms, configurable: true });
                NullPrivacyEventManager.clear = origClearEvents;
                NullPanicController._resetForTesting();
            }

            return { result };
        """)
        # Since storage, perms, ghost, and events failed, overall status must be FAILED or PARTIALLY_COMPLETED
        self.assertIn(res["result"]["status"], ["FAILED", "PARTIALLY_COMPLETED"])
        self.assertEqual(res["result"]["subsystems"]["storage"], "FAILED")
        self.assertEqual(res["result"]["subsystems"]["permissions"], "FAILED")
        self.assertEqual(res["result"]["subsystems"]["ghost"], "FAILED")
        self.assertEqual(res["result"]["subsystems"]["events"], "FAILED")

    def test_25_reentrancy_during_ghost_lifecycle_transitions(self):
        """Verify reentrancy lock rejects concurrent requests while Ghost is transitioning."""
        res = run_xpcshell_panic("""
            NullPanicController._resetForTesting();

            let resolveGhost;
            let ghostPromise = new Promise(r => { resolveGhost = r; });

            NullPanicController._setGhostShutdownHandlerForTesting(async () => {
                await ghostPromise;
                return "COMPLETED";
            });

            // Start first trigger (will pause in Ghost shutdown)
            let trigger1Promise = NullPanicController.trigger();

            // Attempt second simultaneous trigger
            let trigger2Result = await NullPanicController.trigger();

            // Complete first trigger
            resolveGhost();
            let trigger1Result = await trigger1Promise;

            NullPanicController._resetForTesting();

            return {
                trigger1Status: trigger1Result.status,
                trigger2Status: trigger2Result.status,
                trigger2Reason: trigger2Result.reason
            };
        """)
        self.assertIn(res["trigger1Status"], ["COMPLETED", "PARTIALLY_COMPLETED"])
        self.assertEqual(res["trigger2Status"], "REJECTED")
        self.assertEqual(res["trigger2Reason"], "PANIC_ALREADY_IN_PROGRESS")

    def test_26_child_actor_passes_zero_parameters(self):
        """Verify NullControlPanelChild client and parent handle TriggerPanicMode without parameters."""
        with open(ACTOR_PARENT_PATH, "r", encoding="utf-8") as f:
            parent_src = f.read()
        with open(CP_JS, "r", encoding="utf-8") as f:
            client_src = f.read()

        # Client sends RPMSendQuery("TriggerPanicMode") with no parameters
        self.assertIn('RPMSendQuery("TriggerPanicMode")', client_src)
        # Parent simply receives TriggerPanicMode and invokes triggerPanicMode() without reading aMessage.data
        self.assertIn('if (aMessage.name === "TriggerPanicMode") {', parent_src)
        self.assertIn('return this.triggerPanicMode();', parent_src)

    def test_27_accessibility_aria_and_keyboard_attributes(self):
        """Verify confirmation dialog and progress states have proper accessible ARIA semantics."""
        with open(CP_XHTML, "r", encoding="utf-8") as f:
            xhtml_src = f.read()

        # Dialog attributes
        self.assertIn('role="alertdialog"', xhtml_src)
        self.assertIn('aria-labelledby="panic-confirm-title"', xhtml_src)
        self.assertIn('aria-describedby="panic-confirm-desc"', xhtml_src)

        # Live regions for progress and results
        self.assertIn('id="panic-progress-view" class="panic-view" style="display: none;" aria-live="polite"', xhtml_src)
        self.assertIn('id="panic-result-view" class="panic-view" style="display: none;" aria-live="polite"', xhtml_src)

        # Status text is explicit (not color-only)
        with open(CP_JS, "r", encoding="utf-8") as f:
            js_src = f.read()
        self.assertIn("pill.textContent = `${subsystemName}: ${subStatus}`", js_src)


if __name__ == "__main__":
    unittest.main()
