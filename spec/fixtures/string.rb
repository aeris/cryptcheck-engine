class String
	def from_hex
		self.b.gsub(/\s/, '').scan(/../).collect { |h| h.hex.chr }.join.b
	end

	def to_hex
		self.b.each_byte.map { |b| "%02x" % b.ord }.join.upcase
	end
end
