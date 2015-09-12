# Rust websockets on mio
### Example Echo Server
```RUST
extern crate mio_websockets as mws;

use std::thread;

fn main() {
    let (mut server, mut reader, mut writer) = mws::WebSocketServer::new("0.0.0.0", 10000);

    thread::spawn(move || {
        loop {
            match reader.bread() {
                mws::InternalMessage::NewClient{token} => {
                    println!("New Client: {:?}", token);
                },
                mws::InternalMessage::TextData{token, data} => {
                    println!("Message: {}", data);
                    writer.write(mws::InternalMessage::TextData{token: token, data: data});
                },
                _ => {},
            }
        }
    });

    server.start();
}
```

### ToDo
+ get more autobahn tests to pass
+ send multiframe messages
+ send PING from server
+ handle weirdness (casting) when payload is larger than u16
+ remove HACKy sleeps from testing

### Sources
+ Nathan Sizemore: https://github.com/nathansizemore/websocket-stream
+ Nikita Baksalyar: http://nbaksalyar.github.io/2015/07/10/writing-chat-in-rust.html
  + https://github.com/nbaksalyar/rust-chat
