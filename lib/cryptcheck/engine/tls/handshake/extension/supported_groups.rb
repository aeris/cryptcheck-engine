module Cryptcheck::Engine
  module Tls
    class Handshake
      class Extension
        class SupportedGroups
          ID = :supported_groups

          def self.read(io)
            groups = Tls.read_groups io
            self.new groups
          end

          def write(io)
            Tls.write_groups io, @groups
          end

          attr_reader :groups

          def initialize(groups)
            @groups = groups
          end

          def self.build(*curves)
            self.new curves
          end
        end
      end
    end
  end
end
