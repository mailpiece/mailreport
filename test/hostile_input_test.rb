require "test_helper"

# Hostile input: the rua/rua-like address is published in DNS.
class MailReport::HostileInputTest < MailReport::TestCase
  def test_an_entity_bomb_yields_no_report_rather_than_expanding
    assert_nil MailReport::Dmarc.parse(fixture("bomb.xml"))
  end

  def test_an_entity_bomb_is_refused_promptly
    bomb = fixture("bomb.xml")

    elapsed = Time.now
    MailReport::Dmarc.parse(bomb)

    assert_operator Time.now - elapsed, :<, 1, "expansion was attempted rather than refused"
  end

  def test_a_document_declaring_an_external_entity_is_refused
    assert_nil MailReport::Dmarc.parse(fixture("external_entity.xml"))
  end

  def test_the_escapes_a_legitimate_report_uses_still_read
    report = MailReport::Dmarc.parse(fixture("escaped.xml"))

    assert_equal "Smith & Jones <mail>", report.organization
    assert_equal "café.example", report.policy.domain
  end

  def test_a_document_over_the_ceiling_is_refused
    oversized = "<feedback>#{" " * MailReport::Archive::MAX_SIZE}</feedback>"

    assert_nil MailReport::Archive.open(oversized)
  end

  def test_a_gzip_bomb_is_refused_without_being_spent
    inflated = MailReport::Archive::MAX_SIZE * 4
    bomb = gzipped("\0" * inflated)

    assert_operator inflated / bomb.bytesize, :>, 100, "fixture does not expand enough to be a bomb"
    assert_nil MailReport::Archive.open(bomb)
  end

  def test_the_ceiling_is_the_callers_to_lower
    assert_nil MailReport::Archive.open(gzipped("x" * 100), max_size: 10)
    assert_equal "x" * 100, MailReport::Archive.open(gzipped("x" * 100), max_size: 100)
  end

  def test_a_report_under_the_ceiling_still_reads
    assert MailReport::Dmarc.parse(fixture("aggregate.xml.gz"))
  end

  def test_a_malformed_zip_yields_no_report
    assert_nil MailReport::Archive.open("PK\x03\x04rest of a zip")
  end

  def test_corrupt_compression_yields_no_report
    corrupt = gzipped("<feedback/>").byteslice(0, 12)

    assert_nil MailReport::Archive.open(corrupt)
  end

  def test_a_deflate_stream_that_stops_early_yields_no_report
    assert_nil MailReport::Archive.open(truncated_zip)
  end

  def test_a_stored_entry_cut_short_yields_no_report
    assert_nil MailReport::Archive.open(truncated(stored("x" * 60_000)))
  end

  def test_a_stored_entry_declaring_bytes_the_archive_does_not_hold_yields_no_report
    assert_nil MailReport::Archive.open(overstating(stored("x" * 500), as: 5_000))
  end

  # Assert allocation, not only nil — spending the bomb then refusing looks the same.
  def test_a_zip_bomb_is_refused_without_being_inflated
    bomb = zipped("\0" * 20_000_000)

    GC.start
    before = allocated
    refused = MailReport::Archive.open(bomb, max_size: 1_000)

    assert_nil refused
    assert_operator allocated - before, :<, 5 * 1024 * 1024, "the bomb was inflated before it was refused"
  end

  def test_a_zip_entry_larger_than_it_declares_is_still_refused
    liar = understating(zipped("x" * 5_000), as: 50)

    assert_nil MailReport::Archive.open(liar, max_size: 1_000)
  end

  def test_a_stored_entry_is_held_to_the_ceiling_like_any_other
    assert_nil MailReport::Archive.open(stored("x" * 5_000), max_size: 1_000)
    assert_equal "x" * 500, MailReport::Archive.open(stored("x" * 500), max_size: 1_000)
  end

  def test_a_report_behind_a_directory_entry_still_reads
    report = MailReport::Dmarc.parse(zipped(fixture("aggregate.xml"), behind: "reports/"))

    assert_equal "google.com", report.organization
  end

  def test_a_zipped_report_still_reads
    report = MailReport::Dmarc.parse(zipped(fixture("aggregate.xml")))

    assert_equal "google.com", report.organization
  end

  def test_a_report_sorted_behind_a_readme_still_reads
    report = MailReport::Dmarc.parse(zipped(fixture("aggregate.xml"), beside: "README.txt"))

    assert_equal "google.com", report.organization
  end

  def test_a_json_report_is_named_as_readily_as_an_xml_one
    report = MailReport::TlsRpt.parse(zipped(fixture("tls-rpt-rfc8460.json"), name: "report.json", beside: "README.txt"))

    assert_equal "Company-X", report.organization
  end

  def test_an_extension_in_capitals_names_a_report_all_the_same
    report = MailReport::Dmarc.parse(zipped(fixture("aggregate.xml"), name: "REPORT.XML", beside: "README.txt"))

    assert_equal "google.com", report.organization
  end

  def test_a_dmarc_report_is_chosen_over_a_json_entry_listed_first
    archive = zipped(fixture("aggregate.xml"), name: "report.xml", beside: "report.json")

    assert_equal "google.com", MailReport::Dmarc.parse(archive).organization
  end

  def test_a_tls_report_is_chosen_over_an_xml_entry_listed_first
    archive = zipped(fixture("tls-rpt-rfc8460.json"), name: "report.json", beside: "report.xml")

    assert_equal "Company-X", MailReport::TlsRpt.parse(archive).organization
  end

  def test_a_json_report_with_invalid_utf8_yields_no_report
    assert_nil MailReport::TlsRpt.parse(%({"organization-name": "Evil\xFFCorp"}).b)
  end

  def test_a_json_report_in_multibyte_utf8_still_reads
    report = MailReport::TlsRpt.parse(%({"organization-name": "Café & Søn"}).b)

    assert_equal "Café & Søn", report.organization
  end

  def test_nothing_at_all_opens_as_no_bytes
    assert_nil MailReport::Archive.open(nil)
    assert_nil MailReport::Archive.open("")
  end

  def test_an_archive_naming_nothing_like_a_report_reads_the_first_entry
    assert_equal "beside", MailReport::Archive.open(zipped("second", name: "notes", beside: "readme"))
  end

  # Dense tags cost more per byte than a normal report; byte ceiling alone isn't enough.
  def test_a_document_of_more_tags_than_a_report_holds_is_refused
    dense = "<feedback>#{"<x/>" * MailReport::Dmarc::Document::MAX_TAGS}</feedback>"

    assert_operator dense.bytesize, :<, MailReport::Archive::MAX_SIZE
    assert_nil MailReport::Dmarc.parse(dense)
  end

  # The ceiling is only worth having if it clears a real report by a distance.
  def test_the_ceiling_leaves_room_for_more_records_than_a_sender_reports
    assert_operator with_records(300).count("<"), :<, MailReport::Dmarc::Document::MAX_TAGS
  end

  # Hold the whole archive to the ceiling, not only its entries.
  def test_an_archive_over_the_ceiling_is_refused_though_its_entries_would_fit
    assert_nil MailReport::Archive.open(zipped("x", beside: "README.txt"), max_size: 100)
  end

  private
    def gzipped(content)
      StringIO.new.binmode.tap { |buffer|
        Zlib::GzipWriter.wrap(buffer) { |gzip| gzip.write(content) }
      }.string
    end

    # Incompressible (random) so half the stream still yields output.
    def truncated_zip
      random = Random.new(42)

      truncated(zipped(Array.new(60_000) { random.rand(256).chr }.join.b))
    end

    # Drop half the entry data; central directory still declares full size.
    def truncated(zip)
      entry = ZipKit::FileReader.read_zip_structure(io: StringIO.new(zip)).first
      kept = entry.compressed_size / 2

      spliced(zip, entry.compressed_data_offset + kept, entry.compressed_size - kept)
    end

    def spliced(zip, from, dropped)
      spliced = (zip.byteslice(0, from) + zip.byteslice(from + dropped..)).b
      record = spliced.rindex("PK\x05\x06".b)
      directory = spliced.byteslice(record + 16, 4).unpack1("V")

      spliced.tap { |patched| patched[record + 16, 4] = [ directory - dropped ].pack("V") }
    end

    def zipped(content, name: "report.xml", behind: nil, beside: nil)
      StringIO.new.binmode.tap { |buffer|
        ZipKit::Streamer.open(buffer) do |zip|
          zip.write_stored_file(behind) { |sink| sink << "" } if behind
          zip.write_deflated_file(beside) { |sink| sink << "beside" } if beside
          zip.write_deflated_file(name) { |sink| sink << content }
        end
      }.string
    end

    def with_records(count)
      document = fixture("aggregate.xml")
      every = document[/\s*<record>.*<\/record>/m]
      one = every[/\s*<record>.*?<\/record>/m]

      document.sub(every, one * count)
    end

    def stored(content, name: "report.xml")
      StringIO.new.binmode.tap { |buffer|
        ZipKit::Streamer.open(buffer) { |zip| zip.write_stored_file(name) { |sink| sink << content } }
      }.string
    end

    def allocated
      GC.stat(:malloc_increase_bytes) + GC.stat(:oldmalloc_increase_bytes)
    end

    # Central-directory uncompressed size is 4 bytes at offset 24 from PK\x01\x02.
    def understating(archive, as:)
      directory = archive.index("PK\x01\x02".b)

      archive.dup.tap { |forged| forged[directory + 24, 4] = [ as ].pack("V") }
    end

    # Central-directory compressed size is 4 bytes at offset 20 from PK\x01\x02.
    def overstating(archive, as:)
      directory = archive.index("PK\x01\x02".b)

      archive.dup.tap { |forged| forged[directory + 20, 4] = [ as ].pack("V") }
    end
end
