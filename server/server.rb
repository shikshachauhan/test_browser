require 'socket' # Provides TCPServer and TCPSocket classes
require 'digest/sha1'
require 'byebug'
require 'pty'

server = TCPServer.new('localhost', 2345)

def send_response(response, socket)
  STDERR.puts "Sending response: #{ response.inspect }"
  output = [0b10000001, response.size, response]
  socket.write output.pack("CCA#{ response.size }")
end

sockets = []

loop do

  # Wait for a connection
  socket = server.accept

  STDERR.puts "Incoming Request"

  # Read the HTTP request. We know it's finished when we see a line with nothing but \r\n
  http_request = ""
  while (line = socket.gets) && (line != "\r\n")
    http_request += line
  end

  # Grab the security key from the headers. If one isn't present, close the connection.
  if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/)
    websocket_key = matches[1]
    STDERR.puts "Websocket handshake detected with key: #{ websocket_key }"
  else
    STDERR.puts "Aborting non-websocket connection"
    socket.close
    next
  end


  response_key = Digest::SHA1.base64digest([websocket_key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].join)
  STDERR.puts "Responding to handshake with key: #{ response_key }"

  socket.write <<-eos
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: #{ response_key }

  eos

  STDERR.puts "Handshake completed. Starting to parse the websocket frame."

  first_byte = socket.getbyte
  fin = first_byte & 0b10000000
  opcode = first_byte & 0b00001111

  raise "We don't support continuations" unless fin
  raise "We only support opcode 1" unless opcode == 1

  second_byte = socket.getbyte
  is_masked = second_byte & 0b10000000
  payload_size = second_byte & 0b01111111

  raise "All incoming frames should be masked according to the websocket spec" unless is_masked
  raise "We only support payloads < 126 bytes in length" unless payload_size < 126

  STDERR.puts "Payload size: #{ payload_size } bytes"

  mask = 4.times.map { socket.getbyte }
  STDERR.puts "Got mask: #{ mask.inspect }"

  data = payload_size.times.map { socket.getbyte }
  STDERR.puts "Got masked data: #{ data.inspect }"

  unmasked_data = data.each_with_index.map { |byte, i| byte ^ mask[i % 4] }
  STDERR.puts "Unmasked the data: #{ unmasked_data.inspect }"

  STDERR.puts "Converted to a string: #{ unmasked_data.pack('C*').force_encoding('utf-8').inspect }"


  sockets.push(socket)
######################################

  # debugger
  # cmd = "tail -f ../log.log"
  # begin
  #   PTY.spawn( cmd ) do |stdout, stdin, pid|
  #     begin
  #       # Do stuff with the output here. Just printing to show it works

  #       stdout.each { |line| send_response(line, socket) }
  #     rescue Errno::EIO
  #       puts "Errno:EIO error, but this probably just means " +
  #             "that the process has finished giving output"
  #     end
  #   end
  # rescue PTY::ChildExited
  #   puts "The child process exited!"
  # end



  ##############################################

  # File.open("../log.log") do |file|
  #
  # end
  # file.close



  # socket.close
end

file_last_updated_at = File.mtime("../log.log")
loop do

  sleep(1)
  file_last_updated_at_temp = File.mtime("../log.log")
  if file_last_updated_at_temp > file_last_updated_at
    file_last_updated_at = file_last_updated_at_temp
  end

end


arr = Array.new(10)
File.open("../log.log") do |file|
  file.readlines.each do |l|
    arr.shift
    arr.push(l)
  end
end


file = File.open("log.txt", 'r')
while !file.eof?
   line = file.readline
   arr.shift
   arr.push(line)
end

def read(filename, num_lines = 1)
  output = ''

  File.readlines(filename).last(num_lines).each do |line|
    output << line
  end

  output
end
