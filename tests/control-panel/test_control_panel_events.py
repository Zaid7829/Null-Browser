# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Step 10.4A — Live Privacy Event Infrastructure Regression Test Suite.

Validates:
1. Event Schema: Fixed schema keys (id, timestamp, category, action, detail, badge, repeatCount).
2. Controlled Vocabulary: Rejection of unauthorized category, action, detail, or badge.
3. 100-Event Maximum: Bounded buffer capacity invariant.
4. FIFO Eviction: Oldest events shifted out when buffer exceeds capacity.
5. Session-Local IDs: Monotonically increasing sequential IDs.
6. clear(): In-memory buffer clearing preserving sequential IDs.
7. Deduplication: Identical (category, action, detail) within 1s increments repeatCount.
8. Sensitive-Data Rejection: IPs, ports, URLs, paths, query params rejected.
9. Observer Ingestion: System observer topics ingested into factual events.
10. FetchPrivacyEvents IPC: Privileged parent actor query returning cloned array.
11. Webpage IPC Denial: RemotePageAccessManager capability gate isolates query from web.
12. No Persistent Storage: Strictly in-memory; zero disk/pref/database persistence.
13. UI Rendering: Table rows populated safely via textContent with repeat count.
14. Empty-State Rendering: "No privacy events observed." when buffer is empty.
15. Unavailable/Error State: Explicit unavailable state on IPC query failure.
16. No Domain/Origin Leakage: Zero hostnames, origins, or URLs in event schema or UI.
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

MANAGER_PATH = os.path.join(FIREFOX_SRC, "browser", "modules", "NullPrivacyEventManager.sys.mjs")
ACTOR_PARENT_PATH = os.path.join(FIREFOX_SRC, "browser", "actors", "NullControlPanelParent.sys.mjs")
RPAM_PATH = os.path.join(FIREFOX_SRC, "toolkit", "modules", "RemotePageAccessManager.sys.mjs")
CP_XHTML = os.path.join(FIREFOX_SRC, "browser", "components", "controlpanel", "controlpanel.xhtml")
CP_JS = os.path.join(FIREFOX_SRC, "browser", "components", "controlpanel", "controlpanel.js")
CP_CSS = os.path.join(FIREFOX_SRC, "browser", "components", "controlpanel", "controlpanel.css")


def run_xpcshell_events(js_snippet: str) -> dict:
    """Executes a JavaScript snippet in xpcshell with browser app provider and returns parsed JSON_RESULT."""
    manifest_path = os.path.join(BROWSER_DIR, "chrome", "browser.manifest").replace("\\", "\\\\")
    full_script = f"""
    let manifestFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    manifestFile.initWithPath("{manifest_path}");
    Components.manager.QueryInterface(Ci.nsIComponentRegistrar).autoRegister(manifestFile);

    let {{ NullPrivacyEventManager }} = ChromeUtils.importESModule("resource:///modules/NullPrivacyEventManager.sys.mjs");
    let {{ NullControlPanelParent, _resetDiagnosticsStateForTesting }} = ChromeUtils.importESModule("resource:///actors/NullControlPanelParent.sys.mjs");

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
    for (let i = 0; i < 60; i++) {{
        thread.processNextEvent(false);
    }}
    """
    proc = subprocess.run(
        [XPCSHELL_EXE, "-g", DIST_BIN, "-a", BROWSER_DIR, "-e", full_script],
        capture_output=True,
        text=True,
        timeout=15,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("JSON_RESULT:"):
            return json.loads(line[len("JSON_RESULT:"):])

    raise RuntimeError(f"xpcshell failed (code {proc.returncode}):\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")


class TestControlPanelEvents(unittest.TestCase):

    def setUp(self):
        self.assertTrue(os.path.isfile(MANAGER_PATH), f"Missing {MANAGER_PATH}")
        self.assertTrue(os.path.isfile(ACTOR_PARENT_PATH), f"Missing {ACTOR_PARENT_PATH}")
        self.assertTrue(os.path.isfile(CP_XHTML), f"Missing {CP_XHTML}")
        self.assertTrue(os.path.isfile(CP_JS), f"Missing {CP_JS}")

    def test_01_event_schema_and_keys(self):
        """Verify event schema strictly contains approved keys and types."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        let evt = NullPrivacyEventManager.recordEvent("HTTPS_ONLY", "UPGRADED", "HTTPS_UPGRADE_SUCCESS", "OBSERVED");
        let events = NullPrivacyEventManager.getEvents();
        return { evt, eventsLen: events.length, first: events[0] };
        """
        res = run_xpcshell_events(js)
        self.assertEqual(res["eventsLen"], 1)
        evt = res["first"]

        expected_keys = {"id", "timestamp", "category", "action", "detail", "badge", "repeatCount"}
        self.assertEqual(set(evt.keys()), expected_keys)
        self.assertIsInstance(evt["id"], int)
        self.assertIsInstance(evt["timestamp"], (int, float))
        self.assertEqual(evt["category"], "HTTPS_ONLY")
        self.assertEqual(evt["action"], "UPGRADED")
        self.assertEqual(evt["detail"], "HTTPS_UPGRADE_SUCCESS")
        self.assertEqual(evt["badge"], "OBSERVED")
        self.assertEqual(evt["repeatCount"], 1)

    def test_02_controlled_vocabulary_enforcement(self):
        """Verify rejection of unauthorized category, action, detail, or badge strings."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        let r1 = NullPrivacyEventManager.recordEvent("INVALID_CAT", "BLOCKED", "TRACKING_CONTENT", "OBSERVED");
        let r2 = NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "INVALID_ACT", "TRACKING_CONTENT", "OBSERVED");
        let r3 = NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "BLOCKED", "UNKNOWN_DETAIL", "OBSERVED");
        let r4 = NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "BLOCKED", "TRACKING_CONTENT", "INVALID_BADGE");
        let events = NullPrivacyEventManager.getEvents();
        return { r1, r2, r3, r4, count: events.length };
        """
        res = run_xpcshell_events(js)
        self.assertIsNone(res["r1"])
        self.assertIsNone(res["r2"])
        self.assertIsNone(res["r3"])
        self.assertIsNone(res["r4"])
        self.assertEqual(res["count"], 0)

    def test_03_max_capacity_and_fifo_eviction(self):
        """Verify bounded 100-event maximum and FIFO eviction behavior."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        // Insert 120 events using explicit timestamps spaced 2000ms apart to test FIFO eviction
        let details = [
            "TRACKING_CONTENT", "FINGERPRINTING_CONTENT", "CRYPTOMINING_CONTENT",
            "SOCIALTRACKING_CONTENT", "EMAILTRACING_CONTENT", "TRACKER_COOKIE"
        ];
        for (let i = 0; i < 120; i++) {
            let detail = details[i % details.length];
            NullPrivacyEventManager._recordEventForTesting("CONTENT_BLOCK", "BLOCKED", detail, "OBSERVED", (i + 1) * 2000);
        }
        let events = NullPrivacyEventManager.getEvents();
        return {
            count: events.length,
            firstId: events[0].id,
            lastId: events[events.length - 1].id
        };
        """
        res = run_xpcshell_events(js)
        self.assertEqual(res["count"], 100, "Buffer must not exceed 100 events")
        # 120 total recorded, first 20 evicted, oldest remaining is id 21, newest is id 120
        self.assertEqual(res["firstId"], 21)
        self.assertEqual(res["lastId"], 120)

    def test_04_session_local_monotonic_ids(self):
        """Verify event IDs are session-local and monotonically increasing."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        let e1 = NullPrivacyEventManager.recordEvent("HTTPS_ONLY", "UPGRADED", "HTTPS_UPGRADE_SUCCESS", "OBSERVED");
        let e2 = NullPrivacyEventManager.recordEvent("NETWORK_SOCKET", "PREVENTED", "AF_INET6_SOCKET_BLOCKED", "OBSERVED");
        NullPrivacyEventManager.clear();
        let e3 = NullPrivacyEventManager.recordEvent("GHOST_TOR", "STATE_CHANGE", "STATE_READY", "RUNTIME");
        return { id1: e1.id, id2: e2.id, id3: e3.id };
        """
        res = run_xpcshell_events(js)
        self.assertEqual(res["id1"], 1)
        self.assertEqual(res["id2"], 2)
        # Monotonic sequence continues after clear()
        self.assertEqual(res["id3"], 3)

    def test_05_clear_buffer_behavior(self):
        """Verify clear() empties in-memory buffer."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        NullPrivacyEventManager.recordEvent("HTTPS_ONLY", "UPGRADED", "HTTPS_UPGRADE_SUCCESS", "OBSERVED");
        let beforeCount = NullPrivacyEventManager.getEvents().length;
        NullPrivacyEventManager.clear();
        let afterCount = NullPrivacyEventManager.getEvents().length;
        return { beforeCount, afterCount };
        """
        res = run_xpcshell_events(js)
        self.assertEqual(res["beforeCount"], 1)
        self.assertEqual(res["afterCount"], 0)

    def test_06_deduplication_and_repeat_count(self):
        """Verify identical (category, action, detail) within 1 second increments repeatCount."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        let e1 = NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "BLOCKED", "TRACKING_CONTENT", "OBSERVED");
        let e2 = NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "BLOCKED", "TRACKING_CONTENT", "OBSERVED");
        let e3 = NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "BLOCKED", "TRACKING_CONTENT", "OBSERVED");
        let events = NullPrivacyEventManager.getEvents();
        return { count: events.length, repeatCount: events[0].repeatCount };
        """
        res = run_xpcshell_events(js)
        self.assertEqual(res["count"], 1, "Deduplication must collapse bursts within 1 second into 1 event")
        self.assertEqual(res["repeatCount"], 3)

    def test_07_sensitive_data_rejection(self):
        """Verify rejection of strings containing IPv4, IPv6, URLs, paths, or query params."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        let attempts = [
            NullPrivacyEventManager.recordEvent("192.168.1.1", "BLOCKED", "TRACKING_CONTENT", "OBSERVED"),
            NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "http://evil.com", "TRACKING_CONTENT", "OBSERVED"),
            NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "BLOCKED", "/etc/passwd", "OBSERVED"),
            NullPrivacyEventManager.recordEvent("CONTENT_BLOCK", "BLOCKED", "TRACKING?param=1", "OBSERVED"),
        ];
        return { rejected: attempts.every(a => a === null), count: NullPrivacyEventManager.getEvents().length };
        """
        res = run_xpcshell_events(js)
        self.assertTrue(res["rejected"])
        self.assertEqual(res["count"], 0)

    def test_08_observer_ingestion(self):
        """Verify system observers are converted into generic factual events."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        NullPrivacyEventManager.ensureObservers();

        Services.obs.notifyObservers(null, "nullbrowser-https-upgraded", "https://leak.example.com/target");
        Services.obs.notifyObservers(null, "nullbrowser-blocked-ipv6", null);
        Services.obs.notifyObservers(null, "nullbrowser-ghost-state-changed", "TOR_BOOTSTRAPPING");
        Services.obs.notifyObservers(null, "perm-changed", "cleared");

        let events = NullPrivacyEventManager.getEvents();
        return {
            count: events.length,
            events: events.map(e => ({ cat: e.category, act: e.action, det: e.detail, badge: e.badge }))
        };
        """
        res = run_xpcshell_events(js)
        self.assertEqual(res["count"], 4)
        expected = [
            {"cat": "HTTPS_ONLY", "act": "UPGRADED", "det": "HTTPS_UPGRADE_SUCCESS", "badge": "OBSERVED"},
            {"cat": "NETWORK_SOCKET", "act": "PREVENTED", "det": "AF_INET6_SOCKET_BLOCKED", "badge": "OBSERVED"},
            {"cat": "GHOST_TOR", "act": "STATE_CHANGE", "det": "STATE_TOR_BOOTSTRAPPING", "badge": "RUNTIME"},
            {"cat": "PERMISSION", "act": "MODIFIED", "det": "PERMISSIONS_CLEARED", "badge": "RUNTIME"},
        ]
        self.assertEqual(res["events"], expected)

    def test_09_content_blocking_flags_ingestion(self):
        """Verify content blocking bitflags map to appropriate factual detail records."""
        js = """
        NullPrivacyEventManager._resetForTesting();

        // Simulate progress listener callback with multiple flags
        // 0x1000 = TRACKING_CONTENT, 0x40 = FINGERPRINTING_CONTENT
        NullPrivacyEventManager.onContentBlockingEvent(0x1000 | 0x40);

        let events = NullPrivacyEventManager.getEvents();
        return {
            count: events.length,
            details: events.map(e => e.detail)
        };
        """
        res = run_xpcshell_events(js)
        self.assertEqual(res["count"], 2)
        self.assertIn("TRACKING_CONTENT", res["details"])
        self.assertIn("FINGERPRINTING_CONTENT", res["details"])

    def test_10_fetch_privacy_events_ipc_query(self):
        """Verify FetchPrivacyEvents IPC query on parent actor returns cloned event stream."""
        js = """
        NullPrivacyEventManager._resetForTesting();
        NullPrivacyEventManager.recordEvent("HTTPS_ONLY", "UPGRADED", "HTTPS_UPGRADE_SUCCESS", "OBSERVED");

        let parentActor = new NullControlPanelParent();
        let events = await parentActor.receiveMessage({ name: "FetchPrivacyEvents" });

        let unauthorizedError = null;
        try {
            await parentActor.receiveMessage({ name: "MaliciousQuery" });
        } catch (e) {
            unauthorizedError = e.message;
        }

        return {
            eventsLen: events.length,
            detail: events[0].detail,
            unauthorizedBlocked: unauthorizedError?.includes("Unauthorized message")
        };
        """
        res = run_xpcshell_events(js)
        self.assertEqual(res["eventsLen"], 1)
        self.assertEqual(res["detail"], "HTTPS_UPGRADE_SUCCESS")
        self.assertTrue(res["unauthorizedBlocked"])

    def test_11_untrusted_web_content_ipc_denial(self):
        """Verify FetchPrivacyEvents is gated by RemotePageAccessManager to about:null/controlpanel only."""
        with open(RPAM_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        # Must appear under about:null and about:controlpanel
        self.assertIn('"about:null": {', content)
        self.assertIn('"about:controlpanel": {', content)

        # Count occurrences of FetchPrivacyEvents in RPAM - must be strictly 2
        occurrences = content.count('"FetchPrivacyEvents"')
        self.assertEqual(occurrences, 2, "FetchPrivacyEvents must only be allowed for about:null and about:controlpanel")

    def test_12_no_persistent_storage(self):
        """Verify NullPrivacyEventManager has zero persistent disk, pref, or database storage."""
        with open(MANAGER_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        forbidden_apis = [
            "Services.prefs.set",
            "IndexedDB",
            "indexedDB",
            "localStorage",
            "sessionStorage",
            "Sqlite",
            "OS.File",
            "IOUtils.write",
            "Services.sessionstore",
        ]
        for api in forbidden_apis:
            self.assertNotIn(api, content, f"Forbidden persistent storage API detected: {api}")

    def test_13_ui_rendering_table_rows(self):
        """Verify Control Panel client JS renders table rows via textContent with repeat count."""
        with open(CP_JS, "r", encoding="utf-8") as f:
            js_src = f.read()

        # Check DOM element rendering in xpcshell
        mock_js = f"""
        let bodyChildren = [];
        let elements = {{
            "privacy-events-empty": {{ textContent: "", style: {{ display: "block" }} }},
            "privacy-events-table-wrap": {{ style: {{ display: "none" }} }},
            "privacy-events-body": {{
                get children() {{ return bodyChildren; }},
                set textContent(v) {{ if (v === "") bodyChildren = []; }},
                appendChild(c) {{ bodyChildren.push(c); }}
            }}
        }};

        let document = {{
            getElementById(id) {{ return elements[id] || null; }},
            createElement(tag) {{
                return {{
                    tagName: tag,
                    className: "",
                    _tc: "",
                    get textContent() {{
                        if (this._tc) return this._tc;
                        if (this.children.length > 0) return this.children.map(c => c.textContent).join("");
                        return "";
                    }},
                    set textContent(v) {{ this._tc = v; }},
                    children: [],
                    appendChild(c) {{ this.children.push(c); }}
                }};
            }},
            readyState: "complete",
            addEventListener() {{}}
        }};

        let mockEvents = [
            {{
                id: 1,
                timestamp: 1726585200000,
                category: "CONTENT_BLOCK",
                action: "BLOCKED",
                detail: "TRACKING_CONTENT",
                badge: "OBSERVED",
                repeatCount: 5
            }}
        ];

        async function RPMSendQuery(query) {{
            if (query === "FetchPrivacyEvents") return mockEvents;
            throw new Error("Unknown query");
        }}

        {js_src}

        await fetchAndRenderPrivacyEvents();

        let row = elements["privacy-events-body"].children[0];
        let cells = row.children.map(c => c.textContent);
        return {{
            emptyDisplay: elements["privacy-events-empty"].style.display,
            tableDisplay: elements["privacy-events-table-wrap"].style.display,
            rowCount: elements["privacy-events-body"].children.length,
            category: cells[1],
            action: cells[2],
            detail: cells[3],
            badge: cells[4],
            count: cells[5]
        }};
        """
        res = run_xpcshell_events(mock_js)
        self.assertEqual(res["emptyDisplay"], "none")
        self.assertEqual(res["tableDisplay"], "block")
        self.assertEqual(res["rowCount"], 1)
        self.assertEqual(res["category"], "CONTENT_BLOCK")
        self.assertEqual(res["action"], "BLOCKED")
        self.assertEqual(res["detail"], "TRACKING_CONTENT")
        self.assertEqual(res["badge"], "OBSERVED")
        self.assertTrue(res["count"].endswith("5"))
        self.assertGreaterEqual(len(res["count"]), 2)

    def test_14_ui_empty_state_rendering(self):
        """Verify Control Panel client JS displays 'No privacy events observed.' when empty."""
        with open(CP_JS, "r", encoding="utf-8") as f:
            js_src = f.read()

        mock_js = f"""
        let elements = {{
            "privacy-events-empty": {{ textContent: "", style: {{ display: "none" }} }},
            "privacy-events-table-wrap": {{ style: {{ display: "block" }} }},
            "privacy-events-body": {{ textContent: "", children: [], appendChild() {{}} }}
        }};

        let document = {{
            getElementById(id) {{ return elements[id] || null; }},
            createElement(tag) {{ return {{}}; }},
            readyState: "complete",
            addEventListener() {{}}
        }};

        async function RPMSendQuery(query) {{
            if (query === "FetchPrivacyEvents") return [];
            throw new Error("Unknown query");
        }}

        {js_src}

        await fetchAndRenderPrivacyEvents();

        return {{
            emptyDisplay: elements["privacy-events-empty"].style.display,
            tableDisplay: elements["privacy-events-table-wrap"].style.display,
            emptyText: elements["privacy-events-empty"].textContent
        }};
        """
        res = run_xpcshell_events(mock_js)
        self.assertEqual(res["emptyDisplay"], "block")
        self.assertEqual(res["tableDisplay"], "none")
        self.assertEqual(res["emptyText"], "No privacy events observed.")

    def test_15_ui_unavailable_error_state(self):
        """Verify Control Panel client JS displays unavailable state upon IPC failure."""
        with open(CP_JS, "r", encoding="utf-8") as f:
            js_src = f.read()

        mock_js = f"""
        let elements = {{
            "privacy-events-empty": {{ textContent: "", style: {{ display: "none" }} }},
            "privacy-events-table-wrap": {{ style: {{ display: "block" }} }},
            "privacy-events-body": {{ textContent: "", children: [], appendChild() {{}} }}
        }};

        let document = {{
            getElementById(id) {{ return elements[id] || null; }},
            createElement(tag) {{ return {{}}; }},
            readyState: "complete",
            addEventListener() {{}}
        }};

        async function RPMSendQuery(query) {{
            throw new Error("IPC disconnected");
        }}

        {js_src}

        await fetchAndRenderPrivacyEvents();

        return {{
            emptyDisplay: elements["privacy-events-empty"].style.display,
            tableDisplay: elements["privacy-events-table-wrap"].style.display,
            emptyText: elements["privacy-events-empty"].textContent
        }};
        """
        res = run_xpcshell_events(mock_js)
        self.assertEqual(res["emptyDisplay"], "block")
        self.assertEqual(res["tableDisplay"], "none")
        self.assertIn("unavailable", res["emptyText"].lower())

    def test_16_zero_domain_origin_leakage(self):
        """Verify zero domain, hostname, or URL patterns exist across privacy events implementation."""
        with open(MANAGER_PATH, "r", encoding="utf-8") as f:
            manager_content = f.read()

        # In observer callback for https-upgraded, the data (URL) must NOT be recorded
        self.assertNotIn("recordEvent(\"HTTPS_ONLY\", \"UPGRADED\", data", manager_content)
        self.assertNotIn("recordEvent(\"HTTPS_ONLY\", \"UPGRADED\", aData", manager_content)
        self.assertNotIn("aWebProgress.currentURI", manager_content)
        self.assertNotIn("aRequest.name", manager_content)

        # Check XHTML for memory persistence disclaimer
        with open(CP_XHTML, "r", encoding="utf-8") as f:
            xhtml_content = f.read()
        self.assertIn("Events are held in memory for this browser session and are not persisted.", xhtml_content)
        self.assertIn("Session Events", xhtml_content)
        self.assertIn("No privacy events observed.", xhtml_content)


if __name__ == "__main__":
    unittest.main()
