require "rexml/document"

require "mailreport/dmarc/report"

module MailReport
  module Dmarc
    # RFC 7489 Appendix C.
    class Document
      ROOT = "feedback"

      PREDEFINED_ENTITIES = %w[ lt gt amp quot apos ].freeze

      # Tag count bound as well as size; room for ~500 records.
      MAX_TAGS = 25_000

      # REXML raises bare RuntimeError when expansion limits trip.
      EXPANSION_ABANDONED = /entity expansions exceeded|entity expansion has grown too large/

      def initialize(xml)
        @xml = xml
      end

      def report
        if root = feedback
          build(root)
        end
      rescue REXML::ParseException
        nil
      rescue RuntimeError => error
        if error.message.match?(EXPANSION_ABANDONED)
          nil
        else
          raise
        end
      end

      private
        def feedback
          if countable?
            document = REXML::Document.new(@xml)

            document.root if readable?(document) && document.root&.name == ROOT
          end
        end

        # Over-counts `<` in text/comments — refuses in the direction we want.
        def countable?
          @xml.to_s.count("<") <= MAX_TAGS
        end

        # Refuse any declared entity before text is read (expansion timing).
        def readable?(document)
          declared_entities(document).empty?
        end

        def declared_entities(document)
          document.doctype&.entities&.keys.to_a - PREDEFINED_ENTITIES
        end

        def build(root)
          metadata = child(root, "report_metadata")

          Report.new(
            organization: text(metadata, "org_name"),
            email: text(metadata, "email"),
            extra_contact_info: text(metadata, "extra_contact_info"),
            report_id: text(metadata, "report_id"),
            range: range(metadata),
            errors: errors(metadata),
            policy: policy(child(root, "policy_published")),
            records: records(root)
          )
        end

        def errors(metadata)
          elements(metadata, "error").filter_map { |element| text_of(element) }
        end

        # Epoch seconds (§7.2), as UTC.
        def range(metadata)
          dates = child(metadata, "date_range")
          starts, ends = integer(dates, "begin"), integer(dates, "end")

          Time.at(starts).utc..Time.at(ends).utc if starts && ends && starts <= ends
        end

        def policy(element)
          Policy.new(
            domain: text(element, "domain"),
            adkim: text(element, "adkim"),
            aspf: text(element, "aspf"),
            p: text(element, "p"),
            sp: text(element, "sp"),
            pct: counted(element, "pct"),
            fo: text(element, "fo")
          )
        end

        def records(root)
          elements(root, "record").map { |element| record(element) }
        end

        def record(element)
          row = child(element, "row")
          evaluated = child(row, "policy_evaluated")

          Record.new(
            source_ip: text(row, "source_ip"),
            count: count_of(row),
            disposition: text(evaluated, "disposition"),
            dkim: text(evaluated, "dkim"),
            spf: text(evaluated, "spf"),
            reasons: reasons(evaluated),
            identifiers: identifiers(child(element, "identifiers")),
            auth_results: auth_results(child(element, "auth_results"))
          )
        end

        def reasons(evaluated)
          elements(evaluated, "reason").map do |element|
            Reason.new(type: text(element, "type"), comment: text(element, "comment"))
          end
        end

        def identifiers(element)
          Identifiers.new(
            header_from: text(element, "header_from"),
            envelope_from: text(element, "envelope_from"),
            envelope_to: text(element, "envelope_to")
          )
        end

        def auth_results(element)
          AuthResults.new(dkim: dkim_results(element), spf: spf_results(element))
        end

        def dkim_results(element)
          elements(element, "dkim").map do |dkim|
            DkimAuthResult.new(domain: text(dkim, "domain"), selector: text(dkim, "selector"),
              result: text(dkim, "result"), human_result: text(dkim, "human_result"))
          end
        end

        def spf_results(element)
          elements(element, "spf").map do |spf|
            SpfAuthResult.new(domain: text(spf, "domain"), scope: text(spf, "scope"), result: text(spf, "result"))
          end
        end

        def child(element, name)
          element.elements[name] if element
        end

        def elements(element, name)
          if element
            element.get_elements(name)
          else
            []
          end
        end

        def text(element, name)
          text_of(child(element, name))
        end

        def text_of(element)
          value = element&.text.to_s.strip

          value unless value.empty?
        end

        def integer(element, name)
          Integer(text(element, name), exception: false)
        end

        def counted(element, name)
          value = integer(element, name)

          value unless value.nil? || value.negative?
        end

        # Omitted count is nil, not zero — only the sender can report "none".
        def count_of(row)
          counted(row, "count") || 0 if text(row, "count")
        end
    end
  end
end
