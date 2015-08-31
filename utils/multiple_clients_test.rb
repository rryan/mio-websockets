require 'faye/websocket'
require 'eventmachine'
require 'base64'

PORT         = ARGV[0].to_i
CLIENT_COUNT = ARGV[1].to_i

$count = 0
EM.run {
  for i in 0...10
    ws = Faye::WebSocket::Client.new("ws://localhost:#{PORT}", nil, {:ping => 5})

    ws.on :open do |event|
      ws.send("Hello World")
    end
  end
}
