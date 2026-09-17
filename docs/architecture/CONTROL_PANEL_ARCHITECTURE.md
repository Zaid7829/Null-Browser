# Null Browser Control Panel — Implementation Architecture & Audit

## 1. Overview & Architectural Principles

The Null Browser Control Panel provides users with an internal, factual, transparent view of the browser's privacy, security, networking, and Tor isolation state.

### Core Invariants
- **Browser-Internal & Privileged**: Hosted exclusively at `about:null` (with alias `about:controlpanel`).
- **Read-Only Initially**: Step 10 focuses strictly on inspecting and displaying real state. No toggles or state-altering commands in the initial phase.
- **Strictly Grounded in Real Browser State**: Displays actual runtime preferences, XPCOM service states, and real network/circuit statuses. Under zero circumstances will it display fake metrics, "100% protected" badges, "anonymity scores", or synthetic security meters.
- **Zero Telemetry**: No pings, analytics, remote diagnostic reporting, or third-party phone-homes.
- **Process & Security Boundaries**: Rendered in a restricted Gecko child process (`privilegedabout` process) or chrome process. Under no circumstances may ordinary web content access `about:null`, message the Control Panel actor, or inspect internal diagnostic telemetry.
- **Private Mode & Ghost Mode Compatible**: Operates cleanly in Null Browser's default ephemeral Private Browsing mode and reflects optional Ghost Mode daemon/circuit state without compromising isolation.

---

## 2. Process Architecture & IPC Isolation

```
 +-------------------------------------------------------------------------+
 |                            PARENT PROCESS                               |
 |                                                                         |
 |  +-------------------------------------------------------------------+  |
 |  | NullControlPanelParent (JSWindowActorParent)                      |  |
 |  | - Registered in DesktopActorRegistry.sys.mjs                      |  |
 |  | - Restricted to matches: ["about:null*", "about:controlpanel*"]   |  |
 |  | - Restricted to remoteTypes: ["privilegedabout"]                  |  |
 |  +---------------------------------+---------------------------------+  |
 |                                    |                                    |
 |           Direct XPCOM / C++ Query | Observer Notifications             |
 |                                    | (nullbrowser-blocked-ipv6, etc.)   |
 |                                    v                                    |
 |  +-------------------------------------------------------------------+  |
 |  | Authoritative Gecko Services & Subsystems:                        |  |
 |  | - Services.prefs (Network, TRR, WebRTC, RFP, Privacy)             |  |
 |  | - Services.perms (nsIPermissionManager - Ephemeral Session Perms) |  |
 |  | - Services.cookies (nsICookieManager - Total Cookie Protection)   |  |
 |  | - TrackingDBService (nsITrackingDBService - Blocked trackers)    |  |
 |  | - nsIDNSService / TRRService (DoH status & TRR mode)              |  |
 |  | - TorSupervisor / GhostModeManager (Daemon, SOCKS5, Circuits)     |  |
 |  +-------------------------------------------------------------------+  |
 +------------------------------------+------------------------------------+
                                      ^
               Async Query / Response | JSWindowActor IPC Boundary
               (Structured JSON Data) | (RemotePageChild / Parent)
                                      v
 +-------------------------------------------------------------------------+
 |             PRIVILEGED ABOUT PROCESS (remoteType: privilegedabout)      |
 |                                                                         |
 |  +-------------------------------------------------------------------+  |
 |  | NullControlPanelChild (JSWindowActorChild : RemotePageChild)      |  |
 |  | - Receives structured diagnostic payload from Parent              |  |
 |  | - Exposes read-only RPC interface to page content script          |  |
 |  +---------------------------------+---------------------------------+  |
 |                                    | Structured Clone                   |
 |  +---------------------------------v---------------------------------+  |
 |  | about:null DOM Context                                            |  |
 |  | - chrome://browser/content/controlpanel/controlpanel.xhtml        |  |
 |  | - Read-only reactive rendering of browser status                  |  |
 |  | - Isolated from normal web content & origins                      |  |
 |  +-------------------------------------------------------------------+  |
 +-------------------------------------------------------------------------+
```

### Security Boundary Guarantees:
1. **URI Registration Flags in `AboutRedirector.cpp`**:
   - `URI_SAFE_FOR_UNTRUSTED_CONTENT`: Prevents arbitrary chrome-level execution vulnerabilities.
   - `URI_MUST_LOAD_IN_CHILD`: Isolates the page DOM from the main parent chrome UI thread.
   - `URI_CAN_LOAD_IN_PRIVILEGEDABOUT_PROCESS`: Ensures execution inside the hardened `privilegedabout` child process rather than a standard untrusted web content process.
   - `IS_SECURE_CHROME_UI`: Marks the page as trusted Null Browser chrome interface.
   - `ALLOW_SCRIPT`: Permits page logic to execute.
2. **Actor Scoping in `DesktopActorRegistry.sys.mjs`**:
   - `matches: ["about:null*", "about:controlpanel*"]` ensures `NullControlPanel` actors are never instantiated for arbitrary web origins.
   - `remoteTypes: ["privilegedabout"]` ensures ordinary web processes cannot instantiate the actor or send messages to `NullControlPanelParent`.
3. **Data Sanitization**:
   - Web pages have no access to the `JSWindowActor` messaging layer.
   - IP diagnostics and Tor circuit paths are maintained in the parent process and exposed exclusively through the internal page.

---

## 3. Subsystem Audit: Data Sources & Safe IPC Boundaries

| # | Subsystem | Authoritative Source / API | Status | Instrumentation Needed? | Safe IPC Boundary | Required Tests |
|---|---|---|---|---|---|---|
| 1 | **Network / Proxy / Tor State** | `Services.prefs` (`network.proxy.*`), `TorSupervisor.get_status()`, `Ci.nsIProtocolProxyService` | **VERIFIED** | No for prefs/daemon; query wrapper needed in parent actor | Parent queries prefs & `TorSupervisor`, sends serialized snapshot to child | Pref verification, SOCKS5 fail-closed test, proxy state reporting |
| 2 | **DNS / TRR State** | `Services.prefs` (`network.trr.*`), `Ci.nsIDNSService` (`currentTrrURI`, `trrMode`), observers `network:trr-*` | **VERIFIED** | No (authoritative XPCOM APIs exist) | Parent reads `nsIDNSService` & prefs; emits to child actor | TRR mode 3 verification, DoH endpoint reporting test |
| 3 | **IPv6 Policy & Blocked Attempts** | `Services.prefs` (`network.dns.disableIPv6`), C++ guard in `nsSocketTransport2.cpp` (`nullbrowser-blocked-ipv6` observer) | **VERIFIED** | Already implemented in C++ `nsSocketTransport2.cpp` | Parent listens to `nullbrowser-blocked-ipv6` observer, buffers recent blocked count, passes to child actor | Blocked literal attempt test, observer emission test |
| 4 | **WebRTC Protection** | `Services.prefs` (`media.peerconnection.*`), `PeerConnectionImpl.cpp` ICE candidate obfuscation | **VERIFIED** | No (prefs and C++ obfuscation verified) | Parent reads WebRTC prefs & state; passes read-only summary to child | WebRTC host address leak test, proxy-only verification |
| 5 | **Content-Blocking / Anti-Tracking** | `Ci.nsITrackingDBService` (`sumAllEvents()`, `getEventsByDateRange()`), `gBrowser.selectedBrowser.getContentBlockingLog()` | **VERIFIED** | No (standard Gecko tracking DB and per-tab logs exist) | Parent actor queries `TrackingDBService` / tab log; returns structured tracker counts to child | Tracker count accuracy test, PBM isolation test |
| 6 | **Cookies / Storage State** | `Services.prefs` (`network.cookie.*`), `Ci.nsICookieManager`, `browser.cache.disk.enable` | **VERIFIED** | No | Parent queries cookieBehavior (=5 dFPI), disk cache (=false), returns storage policy | dFPI isolation test, ephemeral storage verification |
| 7 | **Fingerprint / RFP State** | `Services.prefs` (`privacy.resistFingerprinting*`, `privacy.spoof_english`, `layout.css.font-visibility.*`) | **VERIFIED** | No | Parent reads RFP static & dynamic prefs; provides state breakdown to child | RFP active verification, spoof English verification |
| 8 | **Geolocation & Permissions** | `Services.prefs` (`geo.enabled`, `permissions.default.geo`), `Ci.nsIPermissionManager` (`Services.perms`) | **VERIFIED** | No | Parent queries `Services.perms.getAllWithTypePrefix("geo")`; passes permission entries | Geolocation denial test, permission listing test |
| 9 | **Temporary Session Permissions** | `Ci.nsIPermissionManager` (`permission.expireType == Ci.nsIPermissionManager.EXPIRE_SESSION`) | **VERIFIED** | No | Parent filters active permissions by `EXPIRE_SESSION` | Ephemeral permission lifecycle test |
| 10 | **Ghost Mode Lifecycle** | `GhostModeManager` / `GhostLifecycleStateMachine` (`ghost-mode/manager.py`), observer `nullbrowser-ghost-state-changed` | **PROPOSED** | Add XPCOM/Observer bridge for Python/Gecko daemon state | Parent queries supervisor / receives state broadcast; serializes status | Ghost lifecycle state transition test, daemon status test |
| 11 | **Site-Specific Protection State** | `ContentBlockingAllowList.sys.mjs` (`includes()`), `gBrowser.selectedBrowser.getContentBlockingLog()` | **VERIFIED** | No | Parent checks selected browser tab's principal against `ContentBlockingAllowList` | Exception list test, site protection state test |
| 12 | **Live Privacy / Security Events** | `Services.obs` topics: `nullbrowser-blocked-ipv6`, `nullbrowser-https-upgraded`, `cookie-rejected`, `perm-changed` | **VERIFIED** | Already partially instrumented; add event ring buffer in parent actor | Parent maintains in-memory circular buffer (max 50 events) of live privacy events | Live event propagation test, buffer overflow clamp test |

---

## 4. Firefox Source Modifications Required (for Step 10.1+)

When transitioning to implementation in Step 10.1, the following concrete modifications will be introduced:

1. **`firefox/browser/components/about/AboutRedirector.cpp`**:
   - Add `"null"` entry to `kRedirMap` pointing to `"chrome://browser/content/controlpanel/controlpanel.xhtml"`.
   - Flags: `nsIAboutModule::URI_SAFE_FOR_UNTRUSTED_CONTENT | nsIAboutModule::URI_MUST_LOAD_IN_CHILD | nsIAboutModule::ALLOW_SCRIPT | nsIAboutModule::URI_CAN_LOAD_IN_PRIVILEGEDABOUT_PROCESS | nsIAboutModule::IS_SECURE_CHROME_UI`.
2. **`firefox/browser/components/about/components.conf`**:
   - Append `'null'` to `pages` list for the `AboutRedirector` contract IDs.
3. **`firefox/browser/components/DesktopActorRegistry.sys.mjs`**:
   - Register `NullControlPanel` actor with parent `resource:///actors/NullControlPanelParent.sys.mjs`, child `resource:///actors/NullControlPanelChild.sys.mjs`, matching `about:null*` and restricted to `privilegedabout`.
4. **`firefox/browser/actors/NullControlPanelParent.sys.mjs` & `NullControlPanelChild.sys.mjs`**:
   - Implement the safe query handlers for the 12 subsystems, wrapping `Services.prefs`, `Services.perms`, `TrackingDBService`, and observer notifications.
5. **`firefox/browser/components/controlpanel/` (HTML/CSS/JS)**:
   - Packaging via `jar.mn` into `chrome://browser/content/controlpanel/`.
   - Pure read-only UI displaying verified browser state.

---

## 5. Required Test Coverage Plan

1. **Internal Page URL & Protocol Test**:
   - Verify `about:null` resolves only through internal `AboutRedirector`.
   - Verify untrusted websites cannot navigate or embed `about:null` in an iframe.
2. **Process & RemoteType Security Test**:
   - Verify `about:null` loads exclusively in `privilegedabout` or chrome process.
   - Verify normal content processes cannot acquire or send messages via `NullControlPanel` actor.
3. **Factual Diagnostic Invariant Test**:
   - Verify all displayed fields correspond 1:1 with real preferences and XPCOM service responses.
   - Assert zero synthetic scores, fake "protection levels", or telemetry pings.
4. **Subsystem Diagnostic Accuracy Tests**:
   - Network/proxy: verify proxy host/port matches active configuration.
   - DNS: verify TRR mode 3 and custom DoH URL reporting.
   - IPv6: verify blocked connection count matches observer dispatches.
   - WebRTC: verify ICE obfuscation and proxy enforcement reporting.
   - Content blocking: verify tracking counts match `TrackingDBService`.
   - Ghost Mode: verify Tor daemon PID, SOCKS5 listener, and circuit status reporting.
