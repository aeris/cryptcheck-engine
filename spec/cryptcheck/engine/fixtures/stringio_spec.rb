RSpec.describe StringIO do
	describe '#read_uint' do
		it 'must read uint' do
			s     = klass.new '000328'.from_hex
			value = s.read_uint 3
			expect(value).to eq 808
		end
	end

	describe '#write_uint' do
		it 'must write uint' do
			s = klass.new
			s.write_uint 3, 808
			expect(s.string).to eq_hex '000328'
		end
	end

	describe '#read_data' do
		it 'must read from type' do
			s    = klass.new '00050102030405'.from_hex
			data = s.read_data :uint16
			expect(data).to eq_hex '0102030405'
		end

		it 'must read from size' do
			s    = klass.new '00050102030405'.from_hex
			data = s.read_data 2
			expect(data).to eq_hex '0102030405'
		end

		it 'must read nil' do
			s    = klass.new '00'.from_hex
			data = s.read_data :uint8
			expect(data).to be_nil
		end
	end

	describe '#write_data' do
		it 'must write from type' do
			s = klass.new
			s.write_data :uint16, '0102030405'.from_hex
			expect(s.string).to eq_hex '00050102030405'
		end

		it 'must write from size' do
			s = klass.new
			s.write_data 2, '0102030405'.from_hex
			expect(s.string).to eq_hex '00050102030405'
		end

		it 'must write nil' do
			s = klass.new
			s.write_data :uint8, nil
			expect(s.string).to eq_hex '00'
		end
	end
end
