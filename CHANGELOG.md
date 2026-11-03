# Changelog

## Unreleased

- Refuse a DMARC report that redeclares a predefined entity such as `lt`
- Count escapes as well as tags toward a DMARC report's 25,000 ceiling
- Read counts and timestamps in base ten and refuse ones longer than 18 digits
- Refuse a TLS-RPT datetime longer than 40 characters
- Return nil rather than raise on a Zip64 offset too large to seek to

## 0.5.0

- Initial public release.