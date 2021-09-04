helper = Module.new do
  def do_in_background(process)
    threads = []

    mutex   = Mutex.new
    started = ConditionVariable.new

    threads << Thread.start do
      mutex.synchronize { started.signal }
      process.call
    end

    mutex.synchronize { started.wait mutex }
    begin
      yield if block_given?
    ensure
      threads.each &:join
    end
  end

  def do_in_server(process, before = nil, &block)
    server = TCPServer.new '127.0.0.1', 0
    before.call server if before
    accept = -> do
      # while ($stderr.puts '[srv] Wait accept'; socket = server.accept)
      while socket = server.accept
        Thread.new socket do |socket|
          process.call socket
        end
      end
    rescue IOError
    end
    do_in_background(accept) do
      block.call server
    ensure
      server.close
    end
  end

  def echo_server(*args, &block)
    echo = -> (socket) do
      loop do
        # $stderr.puts '[echo] Wait line'
        line = socket.readline.chomp
        # $stderr.puts "[echo] Received \"#{line.colorize :yellow}\""
        # $stderr.puts "[echo] Send \"#{line.colorize :yellow}\""
        socket.puts line
        # $stderr.puts "[echo] Sent \"#{line.colorize :yellow}\""
      end
    rescue IOError
    end
    do_in_server echo, *args, &block
  end
end

RSpec.configure { |c| c.include helper }
