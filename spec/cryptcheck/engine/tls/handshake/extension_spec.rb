module Cryptcheck::Engine
	module Tls
		class Handshake
			RSpec.describe Extension do
				let!(:io) { MockIO.new }

				let!(:server_name_packet) { '0000 0012 0010 00 000d 6372797074636865636b2e6672' }
				let!(:server_name_names) { [{ type: :hostname, hostname: 'cryptcheck.fr' }] }

				let!(:raw_id) { 'ffff'.to_i 16 }
				let!(:raw_data) { '001000000d6372797074636865636b2e6672' }
				let!(:raw_packet) { ('%04x' % raw_id) + '0012' + raw_data }

				describe '::read' do
					it 'must read supported record' do
						io.init server_name_packet
						read, extension = Extension.read io
						expect(read).to be 22
						expect(extension).to be_a Extension::ServerName
					end

					it 'must read unsupported record' do
						io.init raw_packet
						read, extension = Extension.read io
						expect(read).to be 22
						expect(extension).to be_a Extension
						expect(extension.id).to eq raw_id
						expect(extension.data).to eq_hex raw_data
					end
				end

				describe '#write' do
					it 'must write supported record' do
						extension = Extension::ServerName.new server_name_names
						written = Extension.write io, extension
						expect(written).to be 22
						expect(io.string).to eq_hex server_name_packet
					end

					it 'must write unsupported record' do
						extension = Extension.new raw_id, raw_data.from_hex
						written = Extension.write io, extension
						expect(written).to be 22
						expect(io.string).to eq_hex raw_packet
					end
				end
			end
		end
	end
end
