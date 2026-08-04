# mailreport

📧 DMARC report parsing for Ruby.

**mailreport** reads the reports receivers send back about your domain — how your mail performed on their end.

For domain owners monitoring their own authentication: DMARC deployments watching for spoofing or misconfigured senders before tightening policy, TLS rollouts confirming receivers are actually seeing the certificate they expect, anyone who published a `rua`/`ruf` address and now has to read what arrives at it.

**mailreport** handles:

- DMARC aggregate reports (RFC 7489 §7.2), gzipped, zipped, or bare
- SMTP TLS reports (RFC 8460), gzipped, zipped, or bare
- Bounded against hostile input, since the address these arrive at is published in DNS

> A report is only as truthful as the receiver that filed it. This library reports what a document says, not whether it is true.

## Contents

- [Installation](#installation)
- [DMARC Aggregate Reports](#dmarc-aggregate-reports)
- [SMTP TLS Reports](#smtp-tls-reports)
- [What Is Not Filled In](#what-is-not-filled-in)
- [Unreadable Documents](#unreadable-documents)
- [Testing](#testing)
- [History](#history)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Installation

Add this line to your application's Gemfile:

```ruby
gem "mailreport"
```

Requires Ruby >= 3.4

## DMARC Aggregate Reports

A domain asks for these with the `rua` tag of its DMARC record, and they arrive as attachments to ordinary mail. Hand over the attachment as it came:

```ruby
report = MailReport::Dmarc.parse(attachment_bytes)

report.organization   # => "google.com"
report.report_id      # => "14054835605949254452"
report.range          # => 2026-07-27 00:00:00 UTC..2026-07-27 23:59:59 UTC

report.policy.domain  # => "example.com"
report.policy.p       # => "reject"
```

Each record is one sending address over the window, with the count of messages it sent:

```ruby
report.records.each do |record|
  record.source_ip    # => "203.0.113.9"
  record.count        # => 42
  record.disposition  # => "none" - what the receiver did
  record.dkim         # => "pass" - aligned, as DMARC judged it
  record.spf          # => "pass"
end
```

`record.dkim` and `record.spf` are the **aligned** verdicts DMARC reached. Whether the checks themselves passed is a different question, and it's in `auth_results`:

```ruby
record.auth_results.dkim  # => [#<DkimAuthResult domain: "example.com", selector: "s1", result: "pass", ...>]
record.auth_results.spf   # => [#<SpfAuthResult domain: "example.com", scope: "mfrom", result: "pass">]
```

A message can carry a valid signature from a domain that doesn't align, and that pair is where it shows.

Where a receiver applied something milder than the published policy, it says why:

```ruby
record.reasons  # => [#<Reason type: "forwarded", comment: "looks forwarded">]
```

Worth reading before concluding anything from a `fail` - forwarding breaks SPF and often DKIM, and a receiver that noticed will say so here.

## SMTP TLS Reports

RFC 8460 reports arrive the same way. Parse the attachment bytes:

```ruby
report = MailReport::TlsRpt.parse(attachment_bytes)

report.organization  # => "Company-X"
report.report_id     # => "5065427c-23d3-47ca-b6e0-946ea0e8c4be"
report.range         # => 2016-04-01 00:00:00 UTC..2016-04-01 23:59:59 UTC

report.policies.each do |policy|
  policy.type       # => "sts"
  policy.domain     # => "company-y.example"
  policy.successes  # => 5326
  policy.failures   # => 303
end
```

## What Is Not Filled In

Elements the sender omitted come back `nil`, including ones the RFC gives defaults for:

```ruby
report.policy.adkim  # => nil, where the sender said nothing
```

"The sender omitted `adkim`" and "the sender asked for relaxed alignment" are different facts, and only the first is in the document. Applying the RFC's defaults is left to the reader.

For the same reason, nothing here counts. Totals, alignment rates, and what counts as alarming are a consumer's to compute.

## Unreadable Documents

Nothing raises. A document that can't be read is `nil`:

```ruby
MailReport::Dmarc.parse(garbage)  # => nil
```

This is deliberately different from a report carrying no records - that one is a receiver saying it saw no mail, and comes back as a report with an empty `records`.

A `rua` address is published in DNS, so anyone can send anything to it, and the limits assume as much:

- **Entity declarations are refused.** A report has none of its own, so the expansion bomb is refused with them. Escapes a real document needs (`&amp;`, `&#233;`) still read.
- **Decompression stops at 2 MB** rather than running to completion.

```ruby
MailReport::Archive.open(bytes, max_size: 1024 * 1024)
```

- **A document of more than 25,000 tags is refused**, however few bytes it spends on them. Tags cost time and memory to read whatever their size, so the count is bounded to 500 records.
- **External references are never resolved** - no document reads a file, a URL, or a DNS name.
- **A zip entry is bounded as it inflates**, not on the size it claims.

Where an archive holds several entries, DMARC prefers a `.xml` name and TLS a `.json` name; otherwise the first non-empty file is read. Directories and empty placeholders are skipped.

## Testing

```sh
bundle install
rake
```

## History

View the [changelog](CHANGELOG.md).

## Contributing

Everyone is encouraged to help improve this project:

- [Report bugs](https://github.com/mailpiece/mailreport/issues)
- Fix bugs and submit pull requests
- Write, clarify, or fix documentation
- Suggest or add new features

## Acknowledgments

View the [acknowledgments](ACKNOWLEDGMENTS.md).

## License

MIT. See [LICENSE](LICENSE).