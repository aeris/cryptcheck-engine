require 'socket'

class BasicSocket < IO
	def recvmsg_timeout(timeout, *args, **kwargs)
		begin
			self.recvmsg_nonblock *args, **kwargs
		rescue IO::WaitReadable
			IO.select [self], nil, nil, timeout
			retry
		end
	end

	def sendmsg_timeout(timeout, *args, **kwargs)
		begin
			self.sendmsg_nonblock *args, **kwargs
		rescue Errno::EINPROGRESS
			IO.select nil, [self], nil, timeout
			retry
		end
	end
end
