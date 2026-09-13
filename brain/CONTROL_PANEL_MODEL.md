# Live Control Panel

The Live Control Panel is a signature Null Browser subsystem.

## Goals

Show the user what Null is actually doing in real time.

## Core panels

- Overview
- Network
- Public IP state
- IPv6 state
- DNS
- WebRTC
- Trackers
- Ads
- Cookies
- Storage
- Fingerprint
- Location
- Permissions
- Tor
- Live Events
- Site Privacy Report

## Event stream

Examples:
- tracker blocked
- ad blocked
- cookie isolated
- storage write isolated
- location request intercepted
- permission request denied
- DNS resolution completed
- network connection created
- WebRTC policy applied
- Tor bootstrap completed
- Tor circuit changed

## Trust model

The Control Panel is local browser UI.

Web content must not be able to read the detailed Control Panel state.

## Visual principle

Futuristic should come from:
- information hierarchy
- live topology
- precise motion
- clear status states
- technical typography
- subtle transitions

Avoid:
- meaningless neon
- decorative cyberpunk graphics
- giant gradients
- fake 100% security meters
- AI-looking generic dashboards

## Truth rule

Never display a security status that was not measured or derived from known browser state.

