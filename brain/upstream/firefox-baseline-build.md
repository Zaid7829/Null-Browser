# Firefox ESR 153 Baseline Build

## Source
- **Repository**: `https://github.com/mozilla-firefox/firefox.git`
- **Branch**: `esr153`
- **Commit**: `22ecfc5e7cf58364a529219d419f375ecdb81ec8`
- **Version**: `153.4.0`

## Host
- **Windows**: Microsoft Windows 11 Home Single Language (Build 26200, 64-bit)
- **CPU**: AMD Ryzen 7 4800H with Radeon Graphics (8 Cores, 16 Logical Processors)
- **RAM**: 15.42 GB Total (~16 GB)
- **C: free space**: ~211.29 GB free (post-build)

## Toolchain
- **MozillaBuild**: 4.2.1 (`C:\mozilla-build`)
- **Visual Studio**: Visual Studio Community 2022 v17.14 (`17.14.37628.2`), MSVC toolset 14.44.35207
- **Windows SDK**: Windows 10/11 SDK (`10.0.26100.0` / `10.0.19041.0`)
- **Rust**: `rustc 1.98.1` (`x86_64-pc-windows-msvc`), `cargo 1.98.1`
- **Git**: 2.55.0.windows.5 / MozillaBuild MinGW git 2.49.0.windows.1

## Build
- **Object directory**: `C:/Users/Zaid/Projects/Null-Browser-build/obj-firefox`
- **Configuration**: Standard unmodified desktop Firefox build configured via `mach configure --enable-bootstrap` with object directory isolated outside source tree.
- **Exact command**:
  ```bash
  export MOZ_OBJDIR=/c/Users/Zaid/Projects/Null-Browser-build/obj-firefox
  ./mach build
  ```
- **Start time**: 2026-09-15 04:29:08 +05:30
- **End time**: 2026-09-15 07:50:48 +05:30 (Wall time: 12,077s / ~201m)
- **Result**: Successful (Exit code: 0)

## Smoke Test
- **Browser launch**: PASSED (`firefox.exe` launched and initialized multi-process architecture)
- **New window**: PASSED (Window created and restored in session state)
- **New tab**: PASSED (New tab navigation components active)
- **HTTPS navigation**: PASSED (Navigated to `https://example.com`)
- **Page load**: PASSED (Network transaction complete, `SiteSecurityServiceState.bin`, `places.sqlite`, `cookies.sqlite`, and `cache2` populated)
- **Shutdown**: PASSED (Clean termination and exit)

## Source Integrity
- **Firefox Git status**: `On branch esr153`, `Your branch is up to date with 'origin/esr153'`, `nothing to commit, working tree clean`
- **Firefox Git diff**: Clean (0 modified lines)

## Problems
- Windows Kits header non-portable path case warning (`[-Wnonportable-include-path]`).
- Minor pragma pack warning in `libwebrtc` third-party module (`[-Wpragma-pack]`).
- Zero blocking compiler errors or failures.

## Final Status

**BASELINE BUILD PASSED**
