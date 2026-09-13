# Null Browser — Agent Entry Point

Before implementation:

1. Read `brain/ai/SYSTEM_PROMPT.md`.
2. Read `brain/PROJECT_CONTEXT.md`.
3. Read `brain/MASTER_RULES.md`.
4. Read `brain/THREAT_MODEL.md`.
5. Read `brain/SECURITY_MODEL.md`.
6. Read `brain/PRIVACY_MODEL.md`.
7. Read `brain/NETWORK_MODEL.md`.
8. Read `brain/FINGERPRINT_MODEL.md`.
9. Read `brain/CONTROL_PANEL_MODEL.md`.
10. Read `brain/ROADMAP.md`.

Do not immediately generate large amounts of code.

First inspect the actual Firefox/Gecko source tree and verify exact files, preferences, APIs, and build assumptions.

Never fabricate source paths, APIs, test results, or security guarantees.

For security-sensitive features:
- identify the threat
- identify the trust boundary
- define the failure behavior
- define tests
- make the smallest safe change
- run tests
- inspect the diff
- document the decision

