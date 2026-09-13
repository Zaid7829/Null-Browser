# Fingerprint Model

Target surfaces:
- canvas
- WebGL
- audio
- fonts
- screen metrics
- hardware APIs
- navigator properties
- client hints
- timezone
- locale
- language
- media capabilities

## Rules

Do not create a stable artificial fingerprint ID.

Do not continuously randomize values.

Use internally consistent values and controlled reductions where technically justified.

Every fingerprint mitigation must document:
- what is hidden/normalized
- what websites can still observe
- compatibility cost
- test method

