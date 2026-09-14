# Upstream Firefox ESR 153 Baseline

## Upstream Repository Details

- **Upstream Repository**: `https://github.com/mozilla-firefox/firefox.git`
- **Branch**: `esr153`
- **Exact Commit Hash**: `22ecfc5e7cf58364a529219d419f375ecdb81ec8`
- **Source Version**: `153.4.0` (from `firefox/browser/config/version.txt` and `firefox/config/milestone.txt`)
- **Acquisition Date**: 2026-09-14 / 2026-09-15
- **Acquisition Method**: Single-branch shallow Git clone (`git clone --depth 1 --branch esr153 --single-branch https://github.com/mozilla-firefox/firefox.git firefox`) followed by complete working tree checkout and verification.

## Source Verification & Integrity

1. **Genuine Tree Verification**: Contains complete Mozilla Gecko, SpiderMonkey (`js/src/`), Necko (`netwerk/`), NSS (`security/nss/`), and Toolkit source trees (468,662 files).
2. **Build System Entry Points**:
   - `firefox/mach` (Mozilla build and execution driver)
   - `firefox/moz.configure` and `firefox/moz.build` root configurations
   - `firefox/client.py` and `firefox/configure.py`
3. **No Skeleton / Mock**: Fully realized upstream C++, Rust, Python, and JavaScript sources.
4. **Working Tree State**: Clean (`git status` indicates `nothing to commit, working tree clean`).
5. **Modifications to Firefox Source**: **None**. Zero source modifications have been made to any file in `firefox/`.

## Relationship Between Upstream Firefox and Null Browser Code

- **Upstream Engine Directory (`firefox/`)**:
  - Contains untouched, pristine Mozilla Firefox ESR 153 source.
  - Ignored in Null Browser's root `.gitignore` to prevent repository bloat and submodule confusion.
  - Serves as the authoritative Gecko runtime engine for building Null Browser.

- **Null Browser Project Root & Subsystems**:
  - `brain/`: Threat models, architecture definitions, specifications, and upstream tracking documentation.
  - `browser/`: Null Browser application-level branding, shell overrides, and UI assets.
  - `privacy-core/`, `security-core/`, `network-core/`, `fingerprint-core/`, `location-core/`, `storage-core/`: Policy enforcements, defense specifications, and integration hooks.
  - `ghost-mode/`: Tor integration and ephemeral private profile architecture.
  - `config/`: Target mozconfig configurations and platform build profiles.
  - `tools/`, `scripts/`: Build helpers, audit scripts, and automated verification test harnesses.
  - `tests/`: Leak tests, fingerprint resistance tests, and security regression suites.

## Rules for Upstream Updates

1. Upstream code must remain cleanly demarcated in `firefox/`.
2. All modifications to Mozilla source must be documented as targeted patches or overlay mechanisms rather than untracked in-place edits.
3. Upstream security updates from the Mozilla ESR 153 channel must be tracked and audited before applying.
4. Before any upstream update, ensure automated leak and regression suites pass against the current baseline.
5. Every modification must respect the Master Rules in `brain/MASTER_RULES.md`.

## Demarcation: Upstream vs. Null Browser Files

### Considered Upstream:
- All files residing within `firefox/` (`dom/`, `netwerk/`, `layout/`, `js/`, `browser/`, `toolkit/`, etc.).

### Considered Null Browser:
- All repository files outside `firefox/`:
  - `AGENT_INSTRUCTIONS.md`
  - `README.md`, `PRIVACY.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
  - `brain/**`
  - `browser/**`
  - `config/**`
  - `diagnostics/**`
  - `docs/**`
  - `extensions/**`
  - `fingerprint-core/**`
  - `ghost-mode/**`
  - `legal/**`
  - `location-core/**`
  - `network-core/**`
  - `privacy-core/**`
  - `scripts/**`
  - `security-core/**`
  - `storage-core/**`
  - `tests/**`
  - `tools/**`
