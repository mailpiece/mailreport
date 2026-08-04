$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "mailreport"

module MailReport
  class TestCase < Minitest::Test
    FIXTURES = File.expand_path("fixtures", __dir__)

    private
      def fixture(name)
        File.binread(File.join(FIXTURES, name))
      end
  end
end
