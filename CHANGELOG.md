# Changelog

## Unreleased

- Refuse a DMARC report that redeclares a predefined entity such as `lt`
- Count escapes as well as tags toward a DMARC report's 25,000 ceiling
- Read counts and timestamps in base ten and refuse ones longer than 18 digits
- Refuse a TLS-RPT datetime longer than 40 characters
- Return nil rather than raise on a Zip64 offset too large to seek to
- Refuse a TLS-RPT report of more than 25,000 objects and arrays
- Read a TLS-RPT field that is not a string as nil
- Read only the chosen zip entry's local header

## 0.5.0

- Initial public release.