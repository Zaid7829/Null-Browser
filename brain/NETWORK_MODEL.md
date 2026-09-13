# Network Model

## Default policy

IPv6:
- browser traffic must not bypass the configured privacy path/policy
- default project posture is to prevent IPv6 leakage

DNS:
- protected resolver path must be explicit
- no silent downgrade to an uncontrolled resolver when protection is required
- DNS state must be visible in the Control Panel

WebRTC:
- must not expose protected network addresses
- must have regression tests for direct/ICE-related exposure

HTTPS:
- use HTTPS-only/security features where appropriate

Speculative networking:
- review prefetch, preconnect, DNS prefetch, speculative connections, captive portal behavior, and similar features for policy bypasses.

Ghost Mode:
- protected browsing is routed through Tor
- direct bypass paths must be prevented or clearly documented

