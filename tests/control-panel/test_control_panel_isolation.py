"""
Step 10.1B — Control Panel Navigation & Iframe Isolation Test Suite.

Verifies the security isolation boundaries of about:null and about:controlpanel:
1. Untrusted Navigation Denial:
   - Untrusted https://example.com content principal calling checkLoadURIWithPrincipal()
     is strictly rejected with NS_ERROR_DOM_BAD_URI (code 2152924148).
2. Untrusted Iframe Embedding Denial:
   - Untrusted https://example.com content principal attempting subdocument channel or
     LOAD_IS_AUTOMATIC_DOCUMENT_REPLACEMENT is rejected with NS_ERROR_DOM_BAD_URI.
   - Real Firefox ESR 153.4.0 runtime test: An ordinary web origin document attempting
     to embed <iframe src="about:null"> and <iframe src="about:controlpanel"> is blocked
     by Gecko; the iframes remain at about:blank and cannot load or expose any Control Panel UI.
"""

import http.server
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

DIST_BIN = r"C:\Users\Zaid\Projects\Null-Browser-build\obj-firefox\dist\bin"
XPCSHELL_EXE = os.path.join(DIST_BIN, "xpcshell.exe")
FIREFOX_EXE = os.path.join(DIST_BIN, "firefox.exe")


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


class SilentHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


class TestControlPanelIsolation(unittest.TestCase):
    """Regression tests for Step 10.1B: Navigation Denial & Iframe Embedding Denial."""

    def test_01_runtime_untrusted_navigation_denial(self):
        """Verify checkLoadURIWithPrincipal rejects top-level navigation to about:null/controlpanel with NS_ERROR_DOM_BAD_URI."""
        js_code = """
        let ssm = Services.scriptSecurityManager;
        let untrustedPrincipal = ssm.createContentPrincipal(
            Services.io.newURI("https://example.com"), {}
        );
        let uriNull = Services.io.newURI("about:null");
        let uriCP = Services.io.newURI("about:controlpanel");

        function checkLoad(uri, flags) {
            try {
                ssm.checkLoadURIWithPrincipal(untrustedPrincipal, uri, flags);
                return { rejected: false, errorName: null, errorCode: null };
            } catch (e) {
                return { rejected: true, errorName: e.name, errorCode: e.result };
            }
        }

        let stdNull = checkLoad(uriNull, Ci.nsIScriptSecurityManager.STANDARD);
        let stdCP = checkLoad(uriCP, Ci.nsIScriptSecurityManager.STANDARD);
        let disinheritNull = checkLoad(uriNull, Ci.nsIScriptSecurityManager.DISALLOW_INHERIT_PRINCIPAL);
        let disinheritCP = checkLoad(uriCP, Ci.nsIScriptSecurityManager.DISALLOW_INHERIT_PRINCIPAL);

        let results = {
            stdNull,
            stdCP,
            disinheritNull,
            disinheritCP
        };
        dump("JSON_RESULT:" + JSON.stringify(results) + "\\n");
        quit(0);
        """
        res = run_xpcshell_script(js_code)

        # Standard navigation check
        self.assertTrue(res["stdNull"]["rejected"], "Navigation to about:null was not rejected!")
        self.assertEqual(res["stdNull"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["stdNull"]["errorCode"], 2152924148)

        self.assertTrue(res["stdCP"]["rejected"], "Navigation to about:controlpanel was not rejected!")
        self.assertEqual(res["stdCP"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["stdCP"]["errorCode"], 2152924148)

        # Disallow inherit principal check
        self.assertTrue(res["disinheritNull"]["rejected"])
        self.assertEqual(res["disinheritNull"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["disinheritNull"]["errorCode"], 2152924148)

        self.assertTrue(res["disinheritCP"]["rejected"])
        self.assertEqual(res["disinheritCP"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["disinheritCP"]["errorCode"], 2152924148)

    def test_02_runtime_security_manager_iframe_embedding_denial(self):
        """Verify checkLoadURIWithPrincipal and subdocument channel creation reject iframe embedding."""
        js_code = """
        let ssm = Services.scriptSecurityManager;
        let untrustedPrincipal = ssm.createContentPrincipal(
            Services.io.newURI("https://example.com"), {}
        );
        let uriNull = Services.io.newURI("about:null");
        let uriCP = Services.io.newURI("about:controlpanel");

        function checkIframeReplacement(uri) {
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

        let iframeNull = checkIframeReplacement(uriNull);
        let iframeCP = checkIframeReplacement(uriCP);
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

        # Automatic document replacement check
        self.assertTrue(res["iframeNull"]["rejected"], "Iframe embedding of about:null was not rejected!")
        self.assertEqual(res["iframeNull"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["iframeNull"]["errorCode"], 2152924148)

        self.assertTrue(res["iframeCP"]["rejected"], "Iframe embedding of about:controlpanel was not rejected!")
        self.assertEqual(res["iframeCP"]["errorName"], "NS_ERROR_DOM_BAD_URI")
        self.assertEqual(res["iframeCP"]["errorCode"], 2152924148)

        # Subdocument channel open check
        self.assertTrue(res["chanNull"]["blocked"], "Subdocument channel for about:null was not blocked!")
        self.assertTrue(res["chanCP"]["blocked"], "Subdocument channel for about:controlpanel was not blocked!")

    def test_03_real_firefox_runtime_web_document_iframe_embedding_denial(self):
        """Launch real Firefox binary with Marionette, load an ordinary web document with iframes, and verify denial."""
        # Find free ports
        sock1 = socket.socket()
        sock1.bind(("127.0.0.1", 0))
        http_port = sock1.getsockname()[1]
        sock1.close()

        sock2 = socket.socket()
        sock2.bind(("127.0.0.1", 0))
        marionette_port = sock2.getsockname()[1]
        sock2.close()

        temp_dir = tempfile.mkdtemp(prefix="test_cp_embed_")
        try:
            # Create test HTML page
            page_html = """<!DOCTYPE html>
<html>
<head><title>Untrusted Web Page</title></head>
<body>
  <h1>Untrusted Web Embedder</h1>
  <iframe id="iframe_null" src="about:null"></iframe>
  <iframe id="iframe_cp" src="about:controlpanel"></iframe>
</body>
</html>"""
            with open(os.path.join(temp_dir, "embed.html"), "w", encoding="utf-8") as f:
                f.write(page_html)

            # Start local HTTP server
            server = http.server.ThreadingHTTPServer(
                ("127.0.0.1", http_port),
                lambda *args: SilentHTTPHandler(*args, directory=temp_dir)
            )
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()

            # Configure ephemeral profile
            user_js = os.path.join(temp_dir, "user.js")
            with open(user_js, "w", encoding="utf-8") as f:
                f.write('user_pref("marionette.enabled", true);\n')
                f.write(f'user_pref("marionette.port", {marionette_port});\n')
                f.write('user_pref("network.proxy.type", 0);\n')

            # Launch built Firefox binary
            cmd = [FIREFOX_EXE, "--headless", "-no-remote", "-profile", temp_dir, "--marionette"]
            proc = subprocess.Popen(cmd)
            time.sleep(2.5)

            def send_msg(s, data):
                raw = json.dumps(data)
                payload = f"{len(raw)}:{raw}".encode("utf-8")
                s.sendall(payload)

            def recv_msg(s):
                buf = b""
                while b":" not in buf:
                    chunk = s.recv(1)
                    if not chunk:
                        raise EOFError("Socket closed")
                    buf += chunk
                colon = buf.index(b":")
                length = int(buf[:colon].decode("ascii"))
                body = buf[colon+1:]
                while len(body) < length:
                    chunk = s.recv(length - len(body))
                    if not chunk:
                        raise EOFError("Socket closed during body read")
                    body += chunk
                return json.loads(body.decode("utf-8"))

            client_sock = socket.socket()
            client_sock.settimeout(10.0)
            try:
                client_sock.connect(("127.0.0.1", marionette_port))
                recv_msg(client_sock)  # Greeting
                send_msg(client_sock, [0, 1, "WebDriver:NewSession", {}])
                sess = recv_msg(client_sock)
                self.assertIsNotNone(sess[3].get("sessionId"), "Failed to obtain Marionette session")

                # Navigate to the untrusted web document
                web_url = f"http://127.0.0.1:{http_port}/embed.html"
                send_msg(client_sock, [0, 2, "WebDriver:Navigate", {"url": web_url}])
                nav = recv_msg(client_sock)
                self.assertIsNone(nav[2], f"Navigation error: {nav[2]}")

                # Wait for document to settle
                time.sleep(1.0)

                # Inspect iframe embedding security state
                script = """
                    let f1 = document.getElementById('iframe_null');
                    let f2 = document.getElementById('iframe_cp');
                    let f1_loc = 'unreadable';
                    let f2_loc = 'unreadable';
                    try { f1_loc = f1.contentWindow.location.href; } catch(e) { f1_loc = 'DENIED: ' + e.name; }
                    try { f2_loc = f2.contentWindow.location.href; } catch(e) { f2_loc = 'DENIED: ' + e.name; }

                    let f1_has_controlpanel = false;
                    let f2_has_controlpanel = false;
                    try {
                        if (f1.contentDocument && f1.contentDocument.getElementById('control-panel-app')) {
                            f1_has_controlpanel = true;
                        }
                    } catch(e) {}
                    try {
                        if (f2.contentDocument && f2.contentDocument.getElementById('control-panel-app')) {
                            f2_has_controlpanel = true;
                        }
                    } catch(e) {}

                    return {
                        origin: window.origin,
                        f1_src: f1.getAttribute('src'),
                        f2_src: f2.getAttribute('src'),
                        f1_loc: f1_loc,
                        f2_loc: f2_loc,
                        f1_has_controlpanel: f1_has_controlpanel,
                        f2_has_controlpanel: f2_has_controlpanel
                    };
                """
                send_msg(client_sock, [0, 3, "WebDriver:ExecuteScript", {"script": script}])
                eval_res = recv_msg(client_sock)
                data = eval_res[3]["value"]

                # Verifications:
                # 1. Document is an ordinary web HTTP origin
                self.assertTrue(data["origin"].startswith("http://127.0.0.1:"), f"Unexpected origin: {data['origin']}")
                # 2. Both iframes attempted to reference about:null and about:controlpanel
                self.assertEqual(data["f1_src"], "about:null")
                self.assertEqual(data["f2_src"], "about:controlpanel")
                # 3. Neither iframe was permitted to load the privileged page:
                # Both remain at about:blank or produce access denial
                self.assertEqual(data["f1_loc"], "about:blank")
                self.assertEqual(data["f2_loc"], "about:blank")
                # 4. Neither iframe DOM contains the control-panel-app root
                self.assertFalse(data["f1_has_controlpanel"], "about:null was unexpectedly embedded in web document!")
                self.assertFalse(data["f2_has_controlpanel"], "about:controlpanel was unexpectedly embedded in web document!")
            finally:
                client_sock.close()
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
                server.shutdown()
                server.server_close()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
