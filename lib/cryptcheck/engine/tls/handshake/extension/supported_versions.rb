module Cryptcheck::Engine
  module Tls
    class Handshake
      class Extension
        class SupportedVersions
          ID = :supported_versions

          def self.read(io)
            versions = io.collect :uint8 do
              tmp     = io.read_uint16
              version = VERSIONS[tmp]
              raise ProtocolError, 'Unknown version 0x%04X' % tmp unless version
              version
            end
            self.new versions
          end

          def write(io)
            io2 = StringIO.new
            @versions.each do |version|
              id = VERSIONS.inverse version
              io2.write_uint16 id
            end

            io.write_uint8 io2.size
            io.write io2.string
          end

          attr_reader :versions

          def initialize(versions)
            @versions = versions
          end

          def self.build(*versions)
            self.new versions
          end
        end
      end
    end
  end
end
