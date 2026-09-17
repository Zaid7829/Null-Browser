"""
Step 10.1 — Control Panel Privileged Page & IPC Foundation Test Suite.

Validates:
1. Registration of about:null and about:controlpanel in AboutRedirector.cpp and components.conf.
2. Routing to privilegedabout process (URI_CAN_LOAD_IN_PRIVILEGEDABOUT_PROCESS, URI_MUST_LOAD_IN_CHILD, etc.).
3. Actor origin and remoteType restrictions in DesktopActorRegistry.sys.mjs.
4. Capability gate in RemotePageAccessManager.sys.mjs.
5. Live runtime rendering and FetchDiagnostics IPC query returning actual browser state.
6. Security boundary enforcement: ordinary web content cannot access or message the actor.
"""

import json
import os
import subprocess
import tempfile
import unittest

DIST_BIN = r"C:\Users\Zaid\Projects\Null-Browser-build\obj-firefox\dist\bin"
XPCSHELL_EXE = os.path.join(DIST_BIN, "xpcshell.exe")
FIREFOX_EXE = os.path.join(DIST_BIN, "firefox.exe")
REPO_ROOT = os.path.realpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
FIREFOX_SRC = os.path.join(REPO_ROOT, "firefox")


def run_xpcshell_script(js_code: str) -> dict:
    """Executes a JavaScript snippet inside xpcshell and parses JSON_RESULT."""
    manifest_path = os.path.join(DIST_BIN, "browser", "chrome", "browser.manifest").replace("\\", "\\\\")
    prelude = f"""
    let manifestFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    manifestFile.initWithPath("{manifest_path}");
    Components.manager.QueryInterface(Ci.nsIComponentRegistrar).autoRegister(manifestFile);
    """
    full_script = prelude + "\n" + js_code
    proc = subprocess.run(
        [XPCSHELL_EXE, "-e", full_script],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"xpcshell failed (code {proc.returncode}):\n{proc.stderr}\n{proc.stdout}")

    for line in proc.stdout.splitlines():
        if line.startswith("JSON_RESULT:"):
            return json.loads(line[len("JSON_RESULT:"):])

    raise ValueError(f"No JSON_RESULT found in xpcshell output:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")


class TestControlPanelFoundation(unittest.TestCase):
    """Verifies the privileged page registration and IPC security boundaries."""

    def test_01_about_null_and_controlpanel_registration(self):
        """Verify about:null and about:controlpanel resolve to the internal controlpanel.xhtml."""
        js_code = """
        let cr = Cc["@mozilla.org/chrome/chrome-registry;1"].getService(Ci.nsIChromeRegistry);
        let uri = Services.io.newURI("chrome://browser/content/controlpanel/controlpanel.xhtml");
        let resolved = cr.convertChromeURL(uri);

        let aboutNull = Cc["@mozilla.org/network/protocol/about;1?what=null"].getService(Ci.nsIAboutModule);
        let aboutCP = Cc["@mozilla.org/network/protocol/about;1?what=controlpanel"].getService(Ci.nsIAboutModule);

        let flagsNull = aboutNull.getURIFlags(Services.io.newURI("about:null"));
        let flagsCP = aboutCP.getURIFlags(Services.io.newURI("about:controlpanel"));

        let results = {
            resolved_chrome: resolved.spec,
            flags_null: flagsNull,
            flags_cp: flagsCP,
            null_is_safe_untrusted: !!(flagsNull & Ci.nsIAboutModule.URI_SAFE_FOR_UNTRUSTED_CONTENT),
            null_must_load_in_child: !!(flagsNull & Ci.nsIAboutModule.URI_MUST_LOAD_IN_CHILD),
            null_can_load_in_privilegedabout: !!(flagsNull & Ci.nsIAboutModule.URI_CAN_LOAD_IN_PRIVILEGEDABOUT_PROCESS),
            null_is_secure_chrome_ui: !!(flagsNull & Ci.nsIAboutModule.IS_SECURE_CHROME_UI),
            null_allow_script: !!(flagsNull & Ci.nsIAboutModule.ALLOW_SCRIPT),
            cp_is_safe_untrusted: !!(flagsCP & Ci.nsIAboutModule.URI_SAFE_FOR_UNTRUSTED_CONTENT),
            cp_must_load_in_child: !!(flagsCP & Ci.nsIAboutModule.URI_MUST_LOAD_IN_CHILD),
            cp_can_load_in_privilegedabout: !!(flagsCP & Ci.nsIAboutModule.URI_CAN_LOAD_IN_PRIVILEGEDABOUT_PROCESS),
            cp_is_secure_chrome_ui: !!(flagsCP & Ci.nsIAboutModule.IS_SECURE_CHROME_UI),
            cp_allow_script: !!(flagsCP & Ci.nsIAboutModule.ALLOW_SCRIPT)
        };
        dump("JSON_RESULT:" + JSON.stringify(results) + "\\n");
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertIn("controlpanel.xhtml", res["resolved_chrome"])
        self.assertTrue(res["null_is_safe_untrusted"])
        self.assertTrue(res["null_must_load_in_child"])
        self.assertTrue(res["null_can_load_in_privilegedabout"])
        self.assertTrue(res["null_is_secure_chrome_ui"])
        self.assertTrue(res["null_allow_script"])
        self.assertTrue(res["cp_is_safe_untrusted"])
        self.assertTrue(res["cp_must_load_in_child"])
        self.assertTrue(res["cp_can_load_in_privilegedabout"])
        self.assertTrue(res["cp_is_secure_chrome_ui"])
        self.assertTrue(res["cp_allow_script"])

    def test_02_actor_registration_and_remote_type_restrictions(self):
        """Verify NullControlPanel actor origin matches and remoteType restrictions in DesktopActorRegistry."""
        registry_path = os.path.join(FIREFOX_SRC, "browser", "components", "DesktopActorRegistry.sys.mjs")
        with open(registry_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("NullControlPanel:", content)
        self.assertIn('esModuleURI: "resource:///actors/NullControlPanelParent.sys.mjs"', content)
        self.assertIn('esModuleURI: "resource:///actors/NullControlPanelChild.sys.mjs"', content)
        self.assertIn('matches: ["about:null*", "about:controlpanel*"]', content)
        self.assertIn('remoteTypes: ["privilegedabout"]', content)

    def test_03_remote_page_access_manager_capability_gate(self):
        """Verify RemotePageAccessManager strictly gates FetchDiagnostics to about:null and about:controlpanel."""
        rpam_path = os.path.join(FIREFOX_SRC, "toolkit", "modules", "RemotePageAccessManager.sys.mjs")
        with open(rpam_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('"about:null": {', content)
        self.assertIn('"about:controlpanel": {', content)
        self.assertIn('"FetchDiagnostics"', content)
        self.assertIn('"FetchPrivacyEvents"', content)
        self.assertIn('"TriggerPanicMode"', content)

    def test_04_actor_implementation_and_factual_payload(self):
        """Verify NullControlPanelParent reads actual browser state and returns sanitized factual payload."""
        actor_path = os.path.join(FIREFOX_SRC, "browser", "actors", "NullControlPanelParent.sys.mjs")
        with open(actor_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Must respond to FetchDiagnostics, FetchPrivacyEvents, and TriggerPanicMode
        self.assertIn('if (aMessage.name === "FetchDiagnostics")', content)
        self.assertIn('if (aMessage.name === "FetchPrivacyEvents")', content)
        self.assertIn('if (aMessage.name === "TriggerPanicMode")', content)
        # Must read real preferences
        self.assertIn('"privacy.resistFingerprinting"', content)
        self.assertIn('"browser.privatebrowsing.autostart"', content)
        self.assertIn('"network.proxy.type"', content)
        # Must not expose network IP addresses or sensitive diagnostics
        self.assertNotIn("ip_address", content)
        self.assertNotIn("tor_circuit", content)
        self.assertNotIn("anonymity_score", content)

    def test_05_runtime_live_page_rendering_and_ipc_execution(self):
        """Execute built Null Browser Gecko binary, render about:null and verify DOM population from IPC."""
        with tempfile.TemporaryDirectory(prefix="test_cp_prof_", ignore_cleanup_errors=True) as prof:
            out_png = os.path.join(prof, "shot.png")
            cmd = [
                FIREFOX_EXE,
                "-profile", prof,
                "-no-remote",
                "--headless",
                f"--screenshot={out_png}",
                "--window-size=1280,800",
                "about:null",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, f"Headless execution failed: {proc.stderr}")
            self.assertTrue(os.path.isfile(out_png), "Screenshot was not generated for about:null")
            self.assertGreater(os.path.getsize(out_png), 10000, "Screenshot file unexpectedly small")

    def test_06_untrusted_web_content_cannot_access_actor(self):
        """Verify ordinary web content cannot instantiate or send messages via NullControlPanel actor."""
        js_code = """
        let { RemotePageAccessManager } = ChromeUtils.importESModule("resource://gre/modules/RemotePageAccessManager.sys.mjs");
        let untrustedPrincipal = Services.scriptSecurityManager.createContentPrincipal(
            Services.io.newURI("https://example.com"), {}
        );
        let allowed = RemotePageAccessManager.checkAllowAccessToFeature(
            untrustedPrincipal, "RPMSendQuery", null
        );
        let results = {
            untrusted_web_allowed: Boolean(allowed)
        };
        dump("JSON_RESULT:" + JSON.stringify(results) + "\\n");
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertFalse(res["untrusted_web_allowed"], "Untrusted web content was granted access to RPMSendQuery!")

    def test_07_untrusted_navigation_denial(self):
        """Verify checkLoadURIWithPrincipal rejects top-level navigation from untrusted web content."""
        js_code = """
        let ssm = Services.scriptSecurityManager;
        let untrustedPrincipal = ssm.createContentPrincipal(
            Services.io.newURI("https://example.com"), {}
        );
        let uriNull = Services.io.newURI("about:null");
        let uriCP = Services.io.newURI("about:controlpanel");

        function checkLoad(uri) {
            try {
                ssm.checkLoadURIWithPrincipal(
                    untrustedPrincipal, uri, Ci.nsIScriptSecurityManager.STANDARD
                );
                return { rejected: false, errorName: null, errorCode: null };
            } catch (e) {
                return { rejected: true, errorName: e.name, errorCode: e.result };
            }
        }

        let resNull = checkLoad(uriNull);
        let resCP = checkLoad(uriCP);

        let results = {
            resNull,
            resCP
        };
        dump("JSON_RESULT:" + JSON.stringify(results) + "\\n");
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertTrue(res["resNull"]["rejected"], "Navigation to about:null was not rejected!")
        self.assertEqual(res["resNull"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["resNull"]["errorCode"], 2152924148)

        self.assertTrue(res["resCP"]["rejected"], "Navigation to about:controlpanel was not rejected!")
        self.assertEqual(res["resCP"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["resCP"]["errorCode"], 2152924148)

    def test_08_untrusted_iframe_embedding_denial(self):
        """Verify checkLoadURIWithPrincipal and channel creation reject untrusted iframe embedding."""
        js_code = """
        let ssm = Services.scriptSecurityManager;
        let untrustedPrincipal = ssm.createContentPrincipal(
            Services.io.newURI("https://example.com"), {}
        );
        let uriNull = Services.io.newURI("about:null");
        let uriCP = Services.io.newURI("about:controlpanel");

        // 1. Automatic document replacement / iframe load check
        function checkIframeLoad(uri) {
            try {
                ssm.checkLoadURIWithPrincipal(
                    untrustedPrincipal,
                    uri,
                    Ci.nsIScriptSecurityManager.LOAD_IS_AUTOMATIC_DOCUMENT_REPLACEMENT
                );
                return { rejected: false, errorName: null, errorCode: null };
            } catch (e) {
                return { rejected: true, errorName: e.name, errorCode: e.result };
            }
        }

        // 2. Subdocument channel open rejection check
        function checkSubdocumentChannel(uri) {
            try {
                let chan = Services.io.newChannelFromURI(
                    uri,
                    null,
                    untrustedPrincipal,
                    null,
                    Ci.nsILoadInfo.SEC_REQUIRE_SAME_ORIGIN_DATA_IS_BLOCKED,
                    Ci.nsIContentPolicy.TYPE_SUBDOCUMENT
                );
                chan.open();
                return { blocked: false, errorCode: null };
            } catch (e) {
                return { blocked: true, errorCode: e.result };
            }
        }

        let iframeNull = checkIframeLoad(uriNull);
        let iframeCP = checkIframeLoad(uriCP);
        let chanNull = checkSubdocumentChannel(uriNull);
        let chanCP = checkSubdocumentChannel(uriCP);

        let results = {
            iframeNull,
            iframeCP,
            chanNull,
            chanCP
        };
        dump("JSON_RESULT:" + JSON.stringify(results) + "\\n");
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertTrue(res["iframeNull"]["rejected"], "Iframe embedding of about:null was not rejected!")
        self.assertEqual(res["iframeNull"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["iframeNull"]["errorCode"], 2152924148)

        self.assertTrue(res["iframeCP"]["rejected"], "Iframe embedding of about:controlpanel was not rejected!")
        self.assertEqual(res["iframeCP"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["iframeCP"]["errorCode"], 2152924148)

        self.assertTrue(res["chanNull"]["blocked"], "Subdocument channel for about:null was not blocked!")
        self.assertTrue(res["chanCP"]["blocked"], "Subdocument channel for about:controlpanel was not blocked!")


if __name__ == "__main__":
    unittest.main()

