extern crate mio_websockets as mws;

use std::thread;

fn main() {
    let (mut server, mut reader, mut writer) = mws::WebSocketServer::new("0.0.0.0", 9001);

    thread::spawn(move || {
        loop {
            let m = reader.bread();
            match m {
                mws::InternalMessage::NewClient{token} => {
                    println!("New Client: {:?}", token);
                },
                mws::InternalMessage::TextData{token: _, data: _} => {
                    writer.write(m);
                },
                mws::InternalMessage::BinaryData{token: _, data: _} => {
                    writer.write(m);
                },
                _ => {},
            }
        }
    });

    server.start();
}
