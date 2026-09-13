# Null Browser — Threat Model

## Protect against

- advertising trackers
- cross-site tracking
- excessive browser storage
- local browsing traces
- DNS leakage
- IPv6 bypasses
- WebRTC network address exposure
- unsolicited location exposure
- intrusive permissions
- fingerprinting
- browser-generated telemetry
- identity mixing between ordinary and Ghost sessions
- direct network bypass around intended privacy routing

## Ghost Mode threat model

Ghost Mode provides a stronger anonymity posture using Tor.

It does not guarantee:
- protection from malware
- protection from a compromised OS
- protection from global traffic correlation
- protection from user-identifying actions
- protection from compromised online accounts
- complete forensic protection
- universal protection against every side channel

## Principle

A privacy control is only considered effective to the extent demonstrated by tests and source-level understanding.

