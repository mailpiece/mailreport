require "stringio"
require "zip_kit"
require "zlib"

module MailReport
  # Attachment wrapping per RFC 7489 §7.2.1.1 / RFC 8460 §3 (magic bytes, not filename).
  module Archive
    GZIP = "\x1f\x8b".b
    ZIP = "PK".b

    # Headroom over real reports (KBs); every byte is parse cost before refuse.
    MAX_SIZE = 2 * 1024 * 1024
    CHUNK_SIZE = 64 * 1024
    STORED = 0

    UNREADABLE = [
      ZipKit::FileReader::ReadError, ZipKit::FileReader::MissingEOCD,
      ZipKit::FileReader::UnsupportedFeature, Zlib::Error, Zlib::GzipFile::Error
    ].freeze

    class << self
      # `name` prefers a zip entry whose filename matches (e.g. /\.xml\z/i).
      def open(bytes, max_size: MAX_SIZE, name: nil)
        bytes = bytes.to_s.b

        # Refuse oversized containers before walking a zip's central directory.
        if bytes.empty?
          nil
        elsif bytes.bytesize > max_size
          nil
        elsif gzipped?(bytes)
          inflated(bytes, max_size)
        elsif zipped?(bytes)
          unzipped(bytes, max_size, name)
        else
          bytes
        end
      rescue *UNREADABLE
        nil
      end

      private
        def gzipped?(bytes)
          bytes.start_with?(GZIP)
        end

        def inflated(bytes, max_size)
          Zlib::GzipReader.wrap(StringIO.new(bytes)) do |gzip|
            inflated = gzip.read(max_size + 1)

            inflated if inflated && inflated.bytesize <= max_size
          end
        end

        def zipped?(bytes)
          bytes.start_with?(ZIP)
        end

        def unzipped(bytes, max_size, name)
          archive = StringIO.new(bytes)

          if entry = document_entry(archive, name)
            archive.seek(entry.compressed_data_offset)
            content(entry, archive, max_size)
          end
        end

        # Prefer a name match when given; else first non-empty file.
        def document_entry(archive, name)
          entries = ZipKit::FileReader.read_zip_structure(io: archive).select do |entry|
            !entry.filename.end_with?("/") && entry.uncompressed_size.positive?
          end

          if name
            entries.find { |entry| entry.filename.match?(name) } || entries.first
          else
            entries.first
          end
        end

        def content(entry, archive, max_size)
          if entry.storage_mode == STORED
            stored(entry, archive, max_size)
          else
            deflated(archive, max_size)
          end
        end

        # Require the declared byte count so a truncated entry is not taken as complete.
        def stored(entry, archive, max_size)
          read = archive.read([ entry.compressed_size, max_size + 1 ].min)

          read if read && read.bytesize == entry.compressed_size && read.bytesize <= max_size
        end

        # Raw deflate, bounded; require finished? so a truncated stream isn't
        # taken as complete. Left unclosed: closing it mid-stream on the
        # bomb path would make zlib warn on stderr, and raw deflate has no
        # footer to verify, so there's nothing correctness-relevant to lose.
        def deflated(archive, max_size)
          inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
          inflated = +"".b

          catch(:full) do
            until inflater.finished?
              piece = archive.read(CHUNK_SIZE) or break

              inflater.inflate(piece) do |chunk|
                inflated << chunk
                throw :full if inflated.bytesize > max_size
              end
            end
          end

          inflated if inflater.finished? && inflated.bytesize <= max_size
        end
    end
  end
end
