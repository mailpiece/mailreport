require "json"
require "time"

require "mailreport/archive"

module MailReport
  # RFC 8460.
  module TlsRpt
    REPORT_NAME = /\.json\z/i

    # Objects and arrays bound as well as size, as DMARC bounds tags.
    MAX_OBJECTS = 25_000

    # Base ten and under 2**63, as DMARC's; a bignum takes seconds to print.
    NUMBER = /\A\d{1,18}\z/
    MAX_COUNT = 10**18 - 1

    # Room for nanoseconds and an offset; a long fraction takes seconds to inspect.
    MAX_DATETIME = 40

    # §4.4.
    Failure = Data.define(:result_type, :count, :sending_mta_ip, :receiving_mx_hostname,
      :receiving_mx_helo, :receiving_ip, :additional_information, :failure_reason_code) do
      def initialize(result_type: nil, count: nil, sending_mta_ip: nil, receiving_mx_hostname: nil,
        receiving_mx_helo: nil, receiving_ip: nil, additional_information: nil, failure_reason_code: nil)
        super
      end
    end

    Policy = Data.define(:type, :domain, :mx_hosts, :policy_string, :successes, :failures, :failure_details) do
      def initialize(type: nil, domain: nil, mx_hosts: [], policy_string: [], successes: nil, failures: nil,
        failure_details: [])
        super
      end
    end

    Report = Data.define(:organization, :report_id, :contact, :started_at, :ended_at, :policies) do
      def initialize(organization: nil, report_id: nil, contact: nil, started_at: nil, ended_at: nil, policies: [])
        super
      end

      def range
        started_at..ended_at if started_at && ended_at && started_at <= ended_at
      end
    end

    class << self
      def parse(bytes)
        json = Archive.open(bytes, name: REPORT_NAME)&.force_encoding(Encoding::UTF_8)

        # A report is JSON, and JSON is UTF-8 (RFC 8460 §3, RFC 8259 §8.1).
        document = JSON.parse(json) if json&.valid_encoding? && countable?(json)

        report_from(document) if document.is_a?(Hash)
      rescue JSON::ParserError
        nil
      end

      private
        # Over-counts brackets in strings, which refuses in the direction we want.
        def countable?(json)
          json.count("{[") <= MAX_OBJECTS
        end

        def report_from(document)
          window = hash_at(document, "date-range")

          Report.new(
            organization: document["organization-name"],
            report_id: document["report-id"],
            contact: document["contact-info"],
            started_at: time_at(window["start-datetime"]),
            ended_at: time_at(window["end-datetime"]),
            policies: array_at(document, "policies").filter_map { |entry| policy_from(entry) }
          )
        end

        def policy_from(entry)
          if entry.is_a?(Hash)
            policy, summary = hash_at(entry, "policy"), hash_at(entry, "summary")

            Policy.new(
              type: policy["policy-type"],
              domain: policy["policy-domain"],
              mx_hosts: listed(policy["mx-host"]),
              policy_string: listed(policy["policy-string"]),
              successes: count_at(summary, "total-successful-session-count"),
              failures: count_at(summary, "total-failure-session-count"),
              failure_details: array_at(entry, "failure-details").filter_map { |failure| failure_from(failure) }
            )
          end
        end

        def failure_from(entry)
          if entry.is_a?(Hash)
            Failure.new(
              result_type: entry["result-type"],
              count: count_at(entry, "failed-session-count"),
              sending_mta_ip: entry["sending-mta-ip"],
              receiving_mx_hostname: entry["receiving-mx-hostname"],
              receiving_mx_helo: entry["receiving-mx-helo"],
              receiving_ip: entry["receiving-ip"],
              additional_information: entry["additional-information"],
              failure_reason_code: entry["failure-reason-code"]
            )
          end
        end

        # Scalar or array — reporters send either.
        def listed(value)
          case value
          when Array then value
          when nil then []
          else [ value ]
          end
        end

        def hash_at(document, key)
          document[key].is_a?(Hash) ? document[key] : {}
        end

        def array_at(document, key)
          listed(document[key])
        end

        # Omitted count is nil, not zero — only the sender can report "none".
        def count_at(document, key)
          counted(document[key]) if document.key?(key)
        end

        def counted(given)
          case given
          when Integer then given if given.between?(0, MAX_COUNT)
          when String then Integer(given, 10) if given.match?(NUMBER)
          end || 0
        end

        def time_at(value)
          Time.iso8601(value) if value.is_a?(String) && value.length <= MAX_DATETIME
        rescue ArgumentError
          nil
        end
    end
  end
end
