# Language, Locale, and Timezone

## UI

Default interface language:
English

## Website language

Default preference:
English

## Locale

Do not continuously randomize locale.

If a privacy session selects a locale variant, keep it coherent and stable for the required session scope.

The selection strategy must be designed to avoid increasing uniqueness.

## Timezone

The product requirement is to present a US timezone.

Do not choose a timezone implementation merely because it looks plausible.
Define and test a consistent policy across:
- JavaScript timezone APIs
- Intl APIs
- HTTP language/locale signals
- browser settings
- date formatting
- locale behavior

The exact default US timezone must be an explicit product decision before implementation.

