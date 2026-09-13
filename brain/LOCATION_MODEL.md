# Location Model

## Default

Do not expose the device's real browser geolocation by default.

## Site geolocation request

When a site requests browser geolocation:
- intercept the request
- apply the configured privacy location
- do not silently expose the actual device location

Initial product default:
London, United Kingdom

## Location consistency

Location is not just GPS.

Review:
- IP-derived location
- browser geolocation
- timezone
- language
- locale
- other location signals

Avoid contradictory values that create an obvious privacy fingerprint.

