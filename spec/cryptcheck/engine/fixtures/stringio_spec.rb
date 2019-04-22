RSpec.describe StringIO do
	describe '#read_data' do
		it 'must read nil' do
			s          = StringIO.new '00'.from_hex
			read, data = s.read_data :uint8
			expect(read).to eq 1
			expect(data).to be_nil
		end
	end

	describe '#write_data' do
		it 'must write nil' do
			s       = StringIO.new
			written = s.write_data :uint8, nil
			expect(written).to eq 1
			expect(s.string).to eq_hex '00'
		end
	end
end
