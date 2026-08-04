module MailReport
  module Dmarc
    # Named as RFC 7489 Appendix C.

    DkimAuthResult = Data.define(:domain, :selector, :result, :human_result) do
      def initialize(domain: nil, selector: nil, result: nil, human_result: nil)
        super
      end
    end

    SpfAuthResult = Data.define(:domain, :scope, :result) do
      def initialize(domain: nil, scope: nil, result: nil)
        super
      end
    end

    AuthResults = Data.define(:dkim, :spf) do
      def initialize(dkim: [], spf: [])
        super
      end
    end

    Identifiers = Data.define(:header_from, :envelope_from, :envelope_to) do
      def initialize(header_from: nil, envelope_from: nil, envelope_to: nil)
        super
      end
    end

    # Override reasons from §7.2 (`forwarded`, `mailing_list`, …).
    Reason = Data.define(:type, :comment) do
      def initialize(type: nil, comment: nil)
        super
      end
    end

    # `dkim` / `spf` are DMARC aligned verdicts; check results are in auth_results.
    Record = Data.define(:source_ip, :count, :disposition, :dkim, :spf, :reasons, :identifiers, :auth_results) do
      def initialize(source_ip: nil, count: nil, disposition: nil, dkim: nil, spf: nil,
                     reasons: [], identifiers: Identifiers.new, auth_results: AuthResults.new)
        super
      end
    end

    Policy = Data.define(:domain, :adkim, :aspf, :p, :sp, :pct, :fo) do
      def initialize(domain: nil, adkim: nil, aspf: nil, p: nil, sp: nil, pct: nil, fo: nil)
        super
      end
    end

    Report = Data.define(:organization, :email, :extra_contact_info, :report_id, :range, :errors, :policy, :records) do
      def initialize(organization: nil, email: nil, extra_contact_info: nil, report_id: nil,
                     range: nil, errors: [], policy: Policy.new, records: [])
        super
      end
    end
  end
end
