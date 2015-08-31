extern crate mio_websockets as mws;
extern crate mio;
extern crate websocket;

use std::thread;
use websocket::ws::sender::Sender;
use websocket::ws::receiver::Receiver;

#[test]
fn it_works() {
    let (mut server, mut reader, mut writer) = mws::WebSocketServer::new("0.0.0.0", 10000);

    let text_string = String::from("Hello World"); let text_string2 = text_string.clone();
    let bin_vec = vec![20, 30, 40, 55]; let bin_vec2 = bin_vec.clone();
    let glyphs = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut med_text_string : String = String::new();
    for _ in 0..(2000/glyphs.len()) {
        med_text_string.push_str(glyphs);
    }
    let med_text_string2 = med_text_string.clone();
    thread::spawn(move || {
        // Wait for new client
        match reader.bread() {
            mws::InternalMessage::NewClient{token} => assert!(token == mio::Token(2)),
            _ => assert!(false),
        };

        // read small text message
        match reader.bread() {
            mws::InternalMessage::TextData{token: _, data} => assert!(data == text_string),
            _ => assert!(false),
        };

        // read small binary message
        match reader.bread() {
            mws::InternalMessage::BinaryData{token: _, data} => assert!(data == bin_vec),
            _ => assert!(false),
        };

        // read medium text message
        match reader.bread() {
            mws::InternalMessage::TextData{token: _, data} => assert!(data == med_text_string),
            _ => assert!(false),
        };


        // write small text message
        writer.write(mws::InternalMessage::TextData{token: mio::Token(2), data: text_string});

        // write small binary message
        writer.write(mws::InternalMessage::BinaryData{token: mio::Token(2), data: bin_vec});

        // write medium text message
        writer.write(mws::InternalMessage::TextData{token: mio::Token(2), data: med_text_string});

        match reader.bread() {
            mws::InternalMessage::CloseClient{token: mio::Token(2)} => {},
            _ => assert!(false),
        }

        writer.write(mws::InternalMessage::Shutdown);
    });

    thread::spawn(move || {
        thread::sleep_ms(1000);
        let url      = websocket::client::request::Url::parse("ws://0.0.0.0:10000").unwrap();
        let request  = websocket::Client::connect(url).unwrap(); 
        let response = request.send().unwrap();
        response.validate().unwrap();
        let (mut sender, mut receiver) = response.begin().split();

        sender.send_message(websocket::message::Message::Text(text_string2.clone())).unwrap();
        sender.send_message(websocket::message::Message::Binary(bin_vec2.clone())).unwrap();
        sender.send_message(websocket::message::Message::Text(med_text_string2.clone())).unwrap();

        match receiver.recv_message().unwrap() {
            websocket::message::Message::Text(data) => assert!(data == text_string2),
            _ => assert!(false),
        }

        match receiver.recv_message().unwrap() {
            websocket::message::Message::Binary(data) => assert!(data == bin_vec2),
            _ => assert!(false),
        }

        match receiver.recv_message().unwrap() {
            websocket::message::Message::Text(data) => assert!(data == med_text_string2),
            _ => assert!(false),
        }
    });

    server.start();
}
