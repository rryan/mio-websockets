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
