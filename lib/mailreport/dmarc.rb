require "mailreport/archive"
require "mailreport/dmarc/document"
require "mailreport/dmarc/report"

module MailReport
  # RFC 7489 §7.2 aggregate reports.
  module Dmarc
    REPORT_NAME = /\.xml\z/i

    def self.parse(bytes)
      if xml = Archive.open(bytes, name: REPORT_NAME)
        Document.new(xml).report
      end
    end
  end
end
