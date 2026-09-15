// =============================================================================
// Null Browser - Default Privacy & Security Policy Configuration
// Step 5: Authoritative Default Preferences
// Target Engine: Firefox ESR 153.4.0
// =============================================================================

// -----------------------------------------------------------------------------
// 1. Default Private Browsing Mode
// Enforce temporary in-memory session lifetime across all windows.
// -----------------------------------------------------------------------------
pref("browser.privatebrowsing.autostart", true);
pref("browser.privatebrowsing.forceMediaMemoryCache", true);

// -----------------------------------------------------------------------------
// 2. Browsing History Suppression
// Prevent persistence of visited URLs, form data, and session restore data.
// -----------------------------------------------------------------------------
pref("places.history.enabled", false);
pref("browser.formfill.enable", false);
pref("browser.sessionstore.privacy_level", 2);
pref("browser.sessionstore.resume_from_crash", false);
pref("browser.places.speculativeConnect.enabled", false);

// -----------------------------------------------------------------------------
// 3. Password Saving Prevention
// Eliminate automatic capturing, autofill, and storage of credentials.
// -----------------------------------------------------------------------------
pref("signon.rememberSignons", false);
pref("signon.autofillForms", false);
pref("signon.generation.enabled", false);
pref("signon.formlessCapture.enabled", false);
pref("signon.privateBrowsingCapture.enabled", false);
pref("signon.capture.inputChanges.enabled", false);
pref("signon.formRemovalCapture.enabled", false);
pref("signon.storeWhenAutocompleteOff", false);
pref("signon.userInputRequiredToCapture.enabled", true);

// -----------------------------------------------------------------------------
// 4. Cookie & Storage Isolation (Total Cookie Protection / dFPI)
// Prevent persistent cross-site tracking; disk caches disabled in favor of RAM.
// -----------------------------------------------------------------------------
pref("network.cookie.cookieBehavior", 5);
pref("network.cookie.cookieBehavior.pbmode", 5);
pref("browser.cache.disk.enable", false);
pref("browser.cache.disk_cache_ssl", false);
pref("browser.cache.memory.enable", true);

// -----------------------------------------------------------------------------
// 5. HTTPS-Only Enforcement
// Strictly upgrade all navigations and subresources; suppress plaintext fallbacks.
// -----------------------------------------------------------------------------
pref("dom.security.https_only_mode", true);
pref("dom.security.https_only_mode_pbm", true);
pref("dom.security.https_only_mode_error_page_user_suggestions", false);
pref("dom.security.https_only_mode_send_http_background_request", false);
pref("security.mixed_content.block_active_content", true);
pref("security.mixed_content.block_display_content", true);
pref("security.cert_pinning.enforcement_level", 2);

// -----------------------------------------------------------------------------
// 6. TRR Mode 3 (DNS-over-HTTPS Fail-Closed)
// DoH strictly required; zero unencrypted native OS DNS fallback permitted.
// -----------------------------------------------------------------------------
pref("network.trr.mode", 3);
pref("network.trr.uri", "https://mozilla.cloudflare-dns.com/dns-query");
pref("network.trr.default_provider_uri", "https://mozilla.cloudflare-dns.com/dns-query");
pref("network.trr.fallback-on-zero-response", false);

// -----------------------------------------------------------------------------
// 7. IPv6 DNS AAAA Query Suppression
// Prevent IPv6 DNS leakage at the host resolver level.
// -----------------------------------------------------------------------------
pref("network.dns.disableIPv6", true);
pref("network.dns.preferIPv6", false);
pref("network.connectivity-service.enabled", false);
pref("network.captive-portal-service.enabled", false);
pref("network.dns.disablePrefetch", true);
pref("network.dns.disablePrefetchFromHTTPS", true);
pref("network.http.speculative-parallel-limit", 0);

// -----------------------------------------------------------------------------
// 8. WebRTC Host-Address & Candidate Protection
// Strip local host IPs and restrict candidate gathering.
// -----------------------------------------------------------------------------
pref("media.peerconnection.ice.no_host", true);
pref("media.peerconnection.ice.default_address_only", true);
pref("media.peerconnection.ice.proxy_only", true);
pref("media.peerconnection.ice.proxy_only_if_pbmode", true);
pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
pref("media.peerconnection.ice.obfuscate_host_addresses", true);

// -----------------------------------------------------------------------------
// 9. Resist Fingerprinting (RFP)
// Enable fingerprint quantization, uniform timezone/locale, and target masks.
// -----------------------------------------------------------------------------
pref("privacy.resistFingerprinting", true);
pref("privacy.resistFingerprinting.pbmode", true);
pref("privacy.resistFingerprinting.block_mozAddonManager", true);
pref("privacy.resistFingerprinting.exemptedDomains", "");
pref("privacy.trackingprotection.enabled", true);
pref("privacy.trackingprotection.pbmode.enabled", true);

// -----------------------------------------------------------------------------
// 10. Real Device Geolocation Denial
// Hard-disable hardware geolocation sensors and system location providers.
// -----------------------------------------------------------------------------
pref("geo.enabled", false);
pref("geo.provider.ms-windows-location", false);
pref("geo.provider.network.url", "");

// -----------------------------------------------------------------------------
// 11. Telemetry, Analytics & Diagnostic Upload Elimination
// Shut down all background reporting pings, pingsender, and study mechanisms.
// -----------------------------------------------------------------------------
pref("datareporting.policy.dataSubmissionEnabled", false);
pref("datareporting.healthreport.uploadEnabled", false);
pref("toolkit.telemetry.unified", false);
pref("toolkit.telemetry.archive.enabled", false);
pref("toolkit.telemetry.shutdownPingSender.enabled", false);
pref("toolkit.telemetry.firstShutdownPing.enabled", false);
pref("toolkit.telemetry.newProfilePing.enabled", false);
pref("toolkit.telemetry.updatePing.enabled", false);
pref("toolkit.telemetry.bhrPing.enabled", false);
pref("browser.newtabpage.activity-stream.telemetry.privatePing.enabled", false);
pref("browser.search.serpEventTelemetryCategorization.enabled", false);
pref("identity.fxaccounts.telemetry.clientAssociationPing.enabled", false);
pref("app.shield.optoutstudies.enabled", false);
pref("app.normandy.enabled", false);
pref("app.normandy.api_url", "");
pref("breakpad.reportURL", "");
pref("browser.tabs.crashReporting.sendReport", false);
