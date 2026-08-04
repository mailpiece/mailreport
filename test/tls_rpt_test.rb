require "test_helper"

class MailReport::TlsRptTest < MailReport::TestCase
  def test_the_rfc_8460_example_reports_its_own_particulars
    report = parse("tls-rpt-rfc8460.json")

    assert_equal "Company-X", report.organization
    assert_equal "5065427c-23d3-47ca-b6e0-946ea0e8c4be", report.report_id
    assert_equal "sts-reporting@company-x.example", report.contact
    assert_equal Time.utc(2016, 4, 1), report.started_at
    assert_equal Time.utc(2016, 4, 1, 23, 59, 59), report.ended_at
    assert_equal report.started_at..report.ended_at, report.range
  end

  def test_a_policy_carries_the_sessions_it_governed
    policy = parse("tls-rpt-rfc8460.json").policies.first

    assert_equal "sts", policy.type
    assert_equal "company-y.example", policy.domain
    assert_equal [ "*.mail.company-y.example" ], policy.mx_hosts
    assert_equal 5326, policy.successes
    assert_equal 303, policy.failures
    assert_includes policy.policy_string, "mode: testing"
  end

  def test_every_failure_type_is_reported_separately
    failures = parse("tls-rpt-rfc8460.json").policies.first.failure_details

    assert_equal %w[ certificate-expired starttls-not-supported validation-failure ], failures.map(&:result_type)
    assert_equal [ 100, 200, 3 ], failures.map(&:count)
  end

  def test_a_failure_reports_the_hosts_and_addresses_it_names
    expired, unsupported, invalid = parse("tls-rpt-rfc8460.json").policies.first.failure_details

    assert_equal "2001:db8:abcd:0012::1", expired.sending_mta_ip
    assert_equal "mx1.mail.company-y.example", expired.receiving_mx_hostname
    assert_equal "203.0.113.56", unsupported.receiving_ip
    assert_match %r{^https://reports\.company-x\.example/}, unsupported.additional_information
    assert_equal "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED", invalid.failure_reason_code
  end

  # §4.4 optional fields; absent in the RFC example's first failure.
  def test_an_absent_optional_field_is_absent_rather_than_missing
    expired = parse("tls-rpt-rfc8460.json").policies.first.failure_details.first

    assert_nil expired.receiving_ip
    assert_nil expired.receiving_mx_helo
    assert_nil expired.additional_information
    assert_nil expired.failure_reason_code
  end

  def test_a_report_carries_every_policy_it_covers
    enforced, unpoliced = parse("tls-rpt-multi-policy.json").policies

    assert_equal "sts", enforced.type
    assert_equal %w[ mx1.relay.example mx2.relay.example ], enforced.mx_hosts
    assert_equal "no-policy-found", unpoliced.type
    assert_equal "legacy.example", unpoliced.domain
  end

  def test_a_policy_without_failures_reports_none_rather_than_nothing
    unpoliced = parse("tls-rpt-multi-policy.json").policies.last

    assert_equal 87, unpoliced.successes
    assert_equal 0, unpoliced.failures
    assert_empty unpoliced.failure_details
    assert_empty unpoliced.mx_hosts
  end

  def test_a_result_type_is_reported_as_it_arrived
    failure = parse("tls-rpt-multi-policy.json").policies.first.failure_details.first

    assert_equal "sts-webpki-invalid", failure.result_type
    assert_equal "mx2.relay.example", failure.receiving_mx_helo
  end

  def test_a_gzipped_report_reads_as_the_bytes_it_compresses
    assert_equal parse("tls-rpt-rfc8460.json"), parse("tls-rpt-rfc8460.json.gz")
  end

  def test_a_wrapping_that_will_not_open_is_no_report
    assert_nil MailReport::TlsRpt.parse("\x1f\x8bnot really gzip")
    assert_nil MailReport::TlsRpt.parse("PK\x03\x04a zip this gem cannot read")
  end

  def test_a_truncated_gzip_stream_is_no_report
    assert_nil MailReport::TlsRpt.parse(fixture("tls-rpt-rfc8460.json.gz").byteslice(0..-4))
  end

  def test_malformed_json_is_no_report
    assert_nil parse("tls-rpt-malformed.json")
  end

  def test_json_that_is_not_a_report_is_no_report
    assert_nil MailReport::TlsRpt.parse("[]")
    assert_nil MailReport::TlsRpt.parse("")
    assert_nil MailReport::TlsRpt.parse(nil)
  end

  def test_a_report_whose_window_will_not_parse_still_reports_the_rest
    report = MailReport::TlsRpt.parse(<<~JSON)
      { "organization-name": "Company-X", "date-range": { "start-datetime": "yesterday" }, "policies": [] }
    JSON

    assert_equal "Company-X", report.organization
    assert_nil report.started_at
    assert_nil report.range
  end

  def test_a_window_closing_before_it_opens_spans_nothing
    report = MailReport::TlsRpt.parse(<<~JSON)
      { "date-range": { "start-datetime": "2026-06-01T00:00:00Z", "end-datetime": "2026-01-01T00:00:00Z" } }
    JSON

    assert_nil report.range
    assert_equal Time.utc(2026, 6, 1), report.started_at
    assert_equal Time.utc(2026, 1, 1), report.ended_at
  end

  def test_a_policy_that_is_not_an_object_is_left_out
    report = MailReport::TlsRpt.parse(%({"policies": ["nonsense", {"policy": {"policy-type": "tlsa"}}]}))

    assert_equal [ "tlsa" ], report.policies.map(&:type)
  end

  def test_a_count_that_is_not_a_number_counts_as_none
    report = MailReport::TlsRpt.parse(<<~JSON)
      { "policies": [{ "summary": { "total-successful-session-count": "many" } }] }
    JSON

    assert_equal 0, report.policies.first.successes
  end

  # "The sender saw no sessions" is a finding; "the sender did not say" is not.
  def test_a_count_the_sender_omitted_is_not_a_count_of_zero
    omitted = parsing(policies: policy("summary" => {}))
    zero = parsing(policies: policy("summary" => {
      "total-successful-session-count" => 0, "total-failure-session-count" => 0
    }))

    assert_nil omitted.policies.first.successes
    assert_nil omitted.policies.first.failures
    assert_equal 0, zero.policies.first.successes
    assert_equal 0, zero.policies.first.failures
  end

  def test_a_summary_the_sender_left_out_entirely_names_no_counts
    report = parsing(policies: policy.except("summary"))

    assert_nil report.policies.first.successes
    assert_nil report.policies.first.failures
  end

  def test_a_lone_policy_reads_as_a_list_of_one
    report = parsing(policies: policy)

    assert_equal 1, report.policies.length
    assert_equal "sts", report.policies.first.type
    assert_equal 5, report.policies.first.failures
  end

  def test_a_lone_failure_reads_as_a_list_of_one
    detail = { "result-type" => "certificate-expired", "failed-session-count" => 5 }
    failures = parsing(policies: policy("failure-details" => detail)).policies.first.failure_details

    assert_equal 1, failures.length
    assert_equal "certificate-expired", failures.first.result_type
  end

  def test_a_fractional_count_is_refused_rather_than_rounded
    summary = { "total-successful-session-count" => 3.9, "total-failure-session-count" => 1 }

    assert_equal 0, parsing(policies: policy("summary" => summary)).policies.first.successes
  end

  def test_a_count_below_zero_is_refused_like_a_fraction
    summary = { "total-successful-session-count" => -5, "total-failure-session-count" => -1 }
    reported = parsing(policies: policy("summary" => summary)).policies.first

    assert_equal 0, reported.successes
    assert_equal 0, reported.failures
  end

  private
    def parse(name)
      MailReport::TlsRpt.parse(fixture(name))
    end

    def parsing(document)
      MailReport::TlsRpt.parse(JSON.generate({ "organization-name" => "Company-X" }.merge(document)))
    end

    def policy(overrides = {})
      {
        "policy" => { "policy-type" => "sts", "policy-domain" => "company-y.example" },
        "summary" => { "total-successful-session-count" => 10, "total-failure-session-count" => 5 }
      }.merge(overrides)
    end
end
