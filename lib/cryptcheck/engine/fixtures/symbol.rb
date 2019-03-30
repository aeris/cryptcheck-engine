class Symbol
	# From https://api.rubyonrails.org/classes/ActiveSupport/Inflector.html#method-i-camelize
	def camelize
		self.to_s.sub(/^[a-z\d]*/) { |m| m.capitalize }
				.gsub(/(?:_|(\/))([a-z\d]*)/i) { "#{$1}#{$2.capitalize}" }
				.gsub('/', '::')
	end

	def constantize
		self.camelize.constantize
	end
end
