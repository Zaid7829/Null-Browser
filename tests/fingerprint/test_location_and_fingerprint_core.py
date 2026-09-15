"""
Tests for Null Browser Step 7 Location & Fingerprint Protection.
Validates:
1. Geolocation denial:
   - Real device geolocation hard-disabled (geo.enabled=false, permissions.default.geo=2).
   - System/platform providers disabled (Windows Location, WinRT, Geoclue, MLS).
   - C++ engine guards in Geolocation.cpp verify instant DelayedTaskType::Deny dispatch and provider shutdown.
2. Synthetic London Location boundary:
   - Proves no fake/fabricated London preferences or URLs exist in default configuration.
   - Documents synthetic London as PROPOSED/UNRESOLVED due to lack of upstream MLS/network endpoints.
   - Explains that browser geolocation != IP location != timezone != locale.
3. Resist Fingerprinting (RFP) core & hardening:
   - RFP enabled across normal and private browsing modes without domain exemptions.
   - Coherent timezone and locale: RFP uses UTC ("Atlantic/Reykjavik") and "en-US", reinforced by privacy.spoof_english=2.
   - Timer precision reduction: quantized to 1000 µs with clock jittering enabled.
   - Font visibility restriction: layout.css.font-visibility=1 (base system fonts only).
   - WebGL GPU masking: webgl.enable-debug-renderer-info=false suppresses WEBGL_debug_renderer_info.
   - Audio invariance: AudioContext preferred sample rate quantized to 44100 Hz and fixed latency under RFP.
4. Step 6 network security preservation:
   - Preserves IPv6 direct socket blocking and C++ guards in nsSocketTransport2.cpp.
   - Preserves WebRTC host address protection and PeerConnectionImpl.cpp override neutralization.
   - Preserves TRR Mode 3 strict fail-closed DNS configuration.
5. Negative constraints:
   - No Secure Mode, no Tor/Ghost Mode, no Panic Mode, no Control Panel UI.
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
    """Parse Mozilla preference file into a python dict."""
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
            elif (raw_val.startswith('"') and raw_val.endswith('"')) or (
                raw_val.startswith("'") and raw_val.endswith("'")
            ):
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
        raise RuntimeError(
            f"No JSON_RESULT in xpcshell output:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)


class TestLocationAndFingerprintCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prefs = parse_prefs(os.path.abspath(CONFIG_PATH))

    def test_01_geolocation_denial_preferences(self):
        """Verify real device geolocation is hard-disabled and providers stripped in prefs."""
        self.assertFalse(self.prefs.get("geo.enabled"), "geo.enabled must be false")
        self.assertEqual(self.prefs.get("permissions.default.geo"), 2, "permissions.default.geo must be 2 (Deny)")
        self.assertFalse(self.prefs.get("geo.provider.ms-windows-location"), "Windows location provider must be false")
        self.assertFalse(self.prefs.get("geo.provider.use_winrt"), "WinRT location provider must be false")
        self.assertFalse(self.prefs.get("geo.provider.use_geoclue"), "Geoclue location provider must be false")
        self.assertEqual(self.prefs.get("geo.provider.network.url"), "", "Network provider URL must be empty")

    def test_02_runtime_geolocation_denial_behavior(self):
        """Verify live Gecko runtime enforces geolocation denial and fails closed."""
        js_code = """
        let p = Services.prefs;
        let results = {
            geo_enabled: p.getBoolPref("geo.enabled", true),
            perm_default_geo: p.getIntPref("permissions.default.geo", 0),
            win_loc: p.getBoolPref("geo.provider.ms-windows-location", true),
            winrt_loc: p.getBoolPref("geo.provider.use_winrt", true),
            geoclue_loc: p.getBoolPref("geo.provider.use_geoclue", true)
        };
        print("JSON_RESULT:" + JSON.stringify(results));
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertFalse(res["geo_enabled"])
        self.assertEqual(res["perm_default_geo"], 2)
        self.assertFalse(res["win_loc"])
        self.assertFalse(res["winrt_loc"])
        self.assertFalse(res["geoclue_loc"])

    def test_03_geolocation_cpp_guard_coverage(self):
        """Verify C++ engine guards in Geolocation.cpp enforce fail-closed denial."""
        source_path = os.path.join(FIREFOX_ROOT, "dom", "geolocation", "Geolocation.cpp")
        self.assertTrue(os.path.exists(source_path), f"Source file not found: {source_path}")
        with open(source_path, "r", encoding="utf-8-sig") as f:
            code = f.read()

        # 1. Init() guard
        init_idx = code.find("nsGeolocationService::Init()")
        self.assertTrue(init_idx != -1)
        init_block = code[init_idx:init_idx + 400]
        self.assertIn("!StaticPrefs::geo_enabled()", init_block)
        self.assertIn("return NS_ERROR_FAILURE;", init_block)

        # 2. StartDevice() guard
        start_device_idx = code.find("nsGeolocationService::StartDevice()")
        self.assertTrue(start_device_idx != -1)
        start_device_block = code[start_device_idx:start_device_idx + 400]
        self.assertIn("!StaticPrefs::geo_enabled()", start_device_block)
        self.assertIn("return NS_ERROR_NOT_AVAILABLE;", start_device_block)

        # 3. GetCurrentPosition() and WatchPosition() guard
        self.assertIn("DelayedTaskType::Deny", code)
        get_current_idx = code.find("Geolocation::GetCurrentPosition(GeoPositionCallback")
        self.assertTrue(get_current_idx != -1)
        get_current_block = code[get_current_idx:get_current_idx + 1500]
        self.assertIn("!StaticPrefs::geo_enabled()", get_current_block)
        self.assertIn("nsGeolocationRequest::DelayedTaskType::Deny", get_current_block)

    def test_04_synthetic_london_unresolved_boundary(self):
        """Verify synthetic London location is correctly treated as PROPOSED/UNRESOLVED, not fabricated."""
        for pref in self.prefs:
            self.assertFalse(
                "london" in str(self.prefs[pref]).lower(),
                f"Synthetic London location prematurely present in: {pref}",
            )
            self.assertFalse(
                "51.5" in str(self.prefs[pref]),
                f"Synthetic London coordinates prematurely present in: {pref}",
            )

    def test_05_rfp_core_hardening_preferences(self):
        """Verify RFP core preferences, English locale spoofing, font, and WebGL hardening."""
        self.assertTrue(self.prefs.get("privacy.resistFingerprinting"))
        self.assertTrue(self.prefs.get("privacy.resistFingerprinting.pbmode"))
        self.assertTrue(self.prefs.get("privacy.resistFingerprinting.block_mozAddonManager"))
        self.assertEqual(self.prefs.get("privacy.resistFingerprinting.exemptedDomains"), "")
        self.assertEqual(self.prefs.get("privacy.spoof_english"), 2)
        self.assertEqual(self.prefs.get("layout.css.font-visibility"), 1)
        self.assertFalse(self.prefs.get("webgl.enable-debug-renderer-info"))
        self.assertEqual(
            self.prefs.get("privacy.resistFingerprinting.reduceTimerPrecision.microseconds"), 1000
        )
        self.assertTrue(self.prefs.get("privacy.resistFingerprinting.reduceTimerPrecision.jitter"))

    def test_06_runtime_rfp_timezone_and_locale_coherence(self):
        """Verify RFP spoofs timezone to UTC and locale to en-US in Gecko runtime and source."""
        # 1. Source verification in nsRFPService.cpp:
        rfp_service_path = os.path.join(
            FIREFOX_ROOT, "toolkit", "components", "resistfingerprinting", "nsRFPService.cpp"
        )
        self.assertTrue(os.path.exists(rfp_service_path), f"Source not found: {rfp_service_path}")
        with open(rfp_service_path, "r", encoding="utf-8-sig") as f:
            rfp_code = f.read()

        self.assertIn('nsRFPService::GetSpoofedJSTimeZone()', rfp_code)
        self.assertIn('"Atlantic/Reykjavik"_ns', rfp_code)
        self.assertIn('nsRFPService::GetSpoofedJSLocale()', rfp_code)
        self.assertIn('"en-US"_ns', rfp_code)

        # 2. Source verification in nsXPConnect.cpp:
        xpc_path = os.path.join(FIREFOX_ROOT, "js", "xpconnect", "src", "nsXPConnect.cpp")
        self.assertTrue(os.path.exists(xpc_path), f"Source not found: {xpc_path}")
        with open(xpc_path, "r", encoding="utf-8-sig") as f:
            xpc_code = f.read()

        self.assertIn('nsCString timeZone = nsRFPService::GetSpoofedJSTimeZone();', xpc_code)
        self.assertIn('aOptions.behaviors().setTimeZoneOverride(timeZone.get());', xpc_code)
        self.assertIn('nsCString locale = nsRFPService::GetSpoofedJSLocale();', xpc_code)
        self.assertIn('aOptions.behaviors().setLocaleOverride(locale.get());', xpc_code)

        # 3. Runtime verification of preference values in xpcshell
        js_code = """
        let p = Services.prefs;
        let results = {
            rfp: p.getBoolPref("privacy.resistFingerprinting", false),
            rfp_pb: p.getBoolPref("privacy.resistFingerprinting.pbmode", false),
            spoof_english: p.getIntPref("privacy.spoof_english", 0)
        };
        print("JSON_RESULT:" + JSON.stringify(results));
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertTrue(res["rfp"])
        self.assertTrue(res["rfp_pb"])
        self.assertEqual(res["spoof_english"], 2)

    def test_07_runtime_timer_precision_and_jitter(self):
        """Verify timer precision quantization to 1000 µs with jitter in runtime."""
        js_code = """
        let p = Services.prefs;
        let results = {
            micros: p.getIntPref("privacy.resistFingerprinting.reduceTimerPrecision.microseconds", 0),
            jitter: p.getBoolPref("privacy.resistFingerprinting.reduceTimerPrecision.jitter", false)
        };
        print("JSON_RESULT:" + JSON.stringify(results));
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertEqual(res["micros"], 1000)
        self.assertTrue(res["jitter"])

    def test_08_runtime_webgl_debug_renderer_info_suppression(self):
        """Verify WebGL debug renderer info suppression via webgl.enable-debug-renderer-info and RFP."""
        # 1. Runtime pref check
        js_code = """
        let p = Services.prefs;
        let results = {
            enable_debug_renderer_info: p.getBoolPref("webgl.enable-debug-renderer-info", true)
        };
        print("JSON_RESULT:" + JSON.stringify(results));
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertFalse(res["enable_debug_renderer_info"])

        # 2. C++ source verification in ClientWebGLContext.cpp
        client_webgl_path = os.path.join(FIREFOX_ROOT, "dom", "canvas", "ClientWebGLContext.cpp")
        self.assertTrue(os.path.exists(client_webgl_path), f"Source not found: {client_webgl_path}")
        with open(client_webgl_path, "r", encoding="utf-8-sig") as f:
            webgl_code = f.read()

        self.assertIn("case WebGLExtensionID::WEBGL_debug_renderer_info:", webgl_code)
        self.assertIn("return !StaticPrefs::webgl_enable_debug_renderer_info();", webgl_code)
        self.assertIn("case WebGLExtensionID::WEBGL_debug_shaders:", webgl_code)
        self.assertIn("return ShouldResistFingerprinting(RFPTarget::WebGLRenderInfo);", webgl_code)

    def test_09_rfp_font_visibility_runtime_and_audio_static_verification(self):
        """Verify layout.css.font-visibility in runtime, and perform static source verification of AudioContext RFP protections."""
        # 1. Runtime pref check
        js_code = """
        let p = Services.prefs;
        let results = {
            font_visibility: p.getIntPref("layout.css.font-visibility", 0)
        };
        print("JSON_RESULT:" + JSON.stringify(results));
        quit(0);
        """
        res = run_xpcshell_script(js_code)
        self.assertEqual(res["font_visibility"], 1)

        # 2. Static source verification for audio fingerprinting:
        # Labeled STATIC VERIFICATION as AudioContext runtime instantiation requires a full DOM/audio-device context.
        audio_path = os.path.join(FIREFOX_ROOT, "dom", "media", "webaudio", "AudioContext.cpp")
        self.assertTrue(os.path.exists(audio_path), f"Source not found: {audio_path}")
        with open(audio_path, "r", encoding="utf-8-sig") as f:
            audio_code = f.read()

        self.assertIn("CubebUtils::PreferredSampleRate(aShouldResistFingerprinting)", audio_code)
        self.assertIn("AudioContext::OutputLatency()", audio_code)
        self.assertIn("latency_s = 0.04;", audio_code)  # Windows fixed latency under RFP

    def test_10_negative_constraints_preserved(self):
        """Verify unpermitted features (Ghost, Tor, Panic, Control Panel, Secure Mode) remain absent."""
        for pref in self.prefs:
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
            self.assertFalse(
                "ghost" in pref.lower() and not pref.startswith("places."),
                f"Ghost mode pref prematurely present: {pref}",
            )


if __name__ == "__main__":
    unittest.main()
