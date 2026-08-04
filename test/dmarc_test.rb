require "test_helper"

class MailReport::DmarcTest < MailReport::TestCase
  # Metadata

  def test_the_reporting_organization_is_read
    report = parse("aggregate.xml")

    assert_equal "google.com", report.organization
    assert_equal "noreply-dmarc-support@google.com", report.email
    assert_equal "https://support.google.com/a/answer/2466580", report.extra_contact_info
    assert_equal "14054835605949254452", report.report_id
  end

  def test_the_date_range_is_read_as_a_range_of_utc_times
    report = parse("aggregate.xml")

    assert_equal Time.at(1785196800).utc, report.range.begin
    assert_equal Time.at(1785283199).utc, report.range.end
  end

  def test_an_absent_optional_element_reads_as_nil
    report = parse("minimal.xml")

    assert_nil report.extra_contact_info
  end

  # Published policy

  def test_the_published_policy_is_read
    policy = parse("aggregate.xml").policy

    assert_equal "example.com", policy.domain
    assert_equal "reject", policy.p
    assert_equal "quarantine", policy.sp
    assert_equal "r", policy.adkim
    assert_equal "r", policy.aspf
    assert_equal 100, policy.pct
    assert_equal "1", policy.fo
  end

  # Omitted tags stay nil; RFC defaults are the reader's to apply.
  def test_policy_tags_the_sender_omitted_are_not_filled_in
    policy = parse("minimal.xml").policy

    assert_equal "none", policy.p
    assert_nil policy.adkim
    assert_nil policy.aspf
    assert_nil policy.sp
    assert_nil policy.pct
  end

  # Records

  def test_every_record_is_read
    assert_equal 3, parse("aggregate.xml").records.size
  end

  def test_a_record_carries_its_source_count_and_disposition
    record = parse("aggregate.xml").records.first

    assert_equal "203.0.113.9", record.source_ip
    assert_equal 42, record.count
    assert_equal "none", record.disposition
  end

  def test_a_count_that_names_no_number_of_messages_reads_as_none
    assert_equal 0, counting("-5").records.first.count
    assert_equal 0, counting("1.5").records.first.count
  end

  # "The sender saw no messages" is a finding; "the sender did not say" is not.
  def test_a_count_the_sender_omitted_is_not_a_count_of_zero
    omitted = parsing("<record><row><source_ip>203.0.113.9</source_ip></row></record>")

    assert_nil omitted.records.first.count
    assert_equal 0, counting("0").records.first.count
  end

  def test_a_record_carries_the_evaluated_alignment
    record = parse("aggregate.xml").records.first

    assert_equal "pass", record.dkim
    assert_equal "pass", record.spf
  end

  def test_an_ipv6_source_is_read_unchanged
    assert_equal "2001:db8::1", parse("aggregate.xml").records.last.source_ip
  end

  def test_identifiers_are_read_and_absent_ones_are_nil
    first, second = parse("aggregate.xml").records

    assert_equal "example.com", first.identifiers.header_from
    assert_equal "example.com", first.identifiers.envelope_from
    assert_nil first.identifiers.envelope_to

    assert_equal "someone@receiver.example", second.identifiers.envelope_to
  end

  def test_one_record_reads_as_a_collection
    records = parse("minimal.xml").records

    assert_equal 1, records.size
    assert_equal "203.0.113.9", records.first.source_ip
  end

  # Auth results

  def test_several_signatures_on_one_record_are_all_reported
    results = parse("aggregate.xml").records.first.auth_results

    assert_equal %w[ example.com bounces.example.com ], results.dkim.map(&:domain)
    assert_equal %w[ pass fail ], results.dkim.map(&:result)
    assert_equal %w[ postrider s1 ], results.dkim.map(&:selector)
    assert_equal "body hash did not verify", results.dkim.last.human_result
  end

  def test_spf_results_carry_their_scope
    spf = parse("aggregate.xml").records.first.auth_results.spf.first

    assert_equal "example.com", spf.domain
    assert_equal "mfrom", spf.scope
    assert_equal "pass", spf.result
  end

  def test_a_record_with_no_auth_results_reports_none_rather_than_failing
    results = parse("aggregate.xml").records.last.auth_results

    assert_empty results.dkim
    assert_empty results.spf
  end

  def test_a_record_with_only_spf_reports_no_dkim
    results = parse("aggregate.xml").records[1].auth_results

    assert_empty results.dkim
    assert_equal "softfail", results.spf.first.result
  end

  # Reasons

  def test_an_override_reason_is_reported
    reason = parse("aggregate.xml").records[1].reasons.first

    assert_equal "forwarded", reason.type
    assert_equal "looks forwarded", reason.comment
  end

  def test_a_record_without_a_reason_has_none
    assert_empty parse("aggregate.xml").records.first.reasons
  end

  def test_a_report_with_no_records_is_still_a_report
    report = parse("empty.xml")

    assert_equal "receiver.example", report.organization
    assert_empty report.records
  end

  # Compression

  def test_a_gzipped_report_reads_the_same_as_a_bare_one
    assert_equal parse("aggregate.xml"), parse("aggregate.xml.gz")
  end

  # Unreadable input

  def test_a_truncated_document_is_no_report
    assert_nil parse("malformed.xml")
  end

  def test_bytes_that_are_not_xml_are_no_report
    assert_nil MailReport::Dmarc.parse("not xml at all")
  end

  def test_xml_that_is_not_a_report_is_no_report
    assert_nil MailReport::Dmarc.parse("<html><body>hello</body></html>")
  end

  def test_nothing_at_all_is_no_report
    assert_nil MailReport::Dmarc.parse(nil)
    assert_nil MailReport::Dmarc.parse("")
  end

  def test_an_error_carrying_only_spaces_is_not_an_error_reported
    report = parsing(<<~XML)
      <report_metadata><org_name>x</org_name><error>  </error><error>real trouble</error></report_metadata>
    XML

    assert_equal [ "real trouble" ], report.errors
  end

  def test_a_range_that_ends_before_it_begins_is_dropped
    report = parsing(<<~XML)
      <report_metadata><date_range><begin>1785283199</begin><end>1785196800</end></date_range></report_metadata>
    XML

    assert_nil report.range
  end

  def test_a_doctype_declaring_no_entities_still_reads
    report = MailReport::Dmarc.parse(<<~XML)
      <?xml version="1.0"?>
      <!DOCTYPE feedback>
      <feedback><report_metadata><org_name>example.net</org_name></report_metadata></feedback>
    XML

    assert_equal "example.net", report.organization
  end

  # REXML bombs raise RuntimeError; our own must not be swallowed as unreadable.
  def test_a_failure_of_our_own_is_not_mistaken_for_a_bad_document
    document = Class.new(MailReport::Dmarc::Document) do
      def build(*)
        raise "a mistake of ours"
      end
    end.new(fixture("aggregate.xml"))

    assert_raises(RuntimeError, "a mistake of ours") { document.report }
  end

  private
    def parse(name)
      MailReport::Dmarc.parse(fixture(name))
    end

    def parsing(metadata)
      MailReport::Dmarc.parse("<feedback>#{metadata}</feedback>")
    end

    def counting(count)
      parsing("<record><row><source_ip>203.0.113.9</source_ip><count>#{count}</count></row></record>")
    end
end
