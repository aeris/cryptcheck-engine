require 'socket'

class Socket < BasicSocket
	def connect(addr, **kwargs)
		timeout = kwargs.delete :timeout
		retried = false
		begin
			self.connect_nonblock addr, **kwargs
		rescue IO::WaitReadable
			IO.select [self], nil, nil, timeout
			retried = true
			retry
		rescue IO::WaitWritable
			IO.select nil, [self], nil, timeout
			retried = true
			retry
		rescue Errno::EALREADY
			# First call to `#connect_nonblock` can also raise this
			# But if it's not after a retry, this is a real error,
			# not a timeout related one
			raise unless retried
			raise Errno::ETIMEDOUT
		rescue Errno::EISCONN
			# First call to `#connect_nonblock` can also raise this
			# Will be raised by `#connect_nonblock` after a retry in case of success
			raise unless retried
		end
	end
end
