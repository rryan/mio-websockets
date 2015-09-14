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
        let client_token = mio::Token(1);
        // Wait for new client
        match reader.bread() {
            mws::InternalMessage::NewClient{token} => assert!(token == client_token),
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
        writer.write(mws::InternalMessage::TextData{token: client_token, data: text_string});

        // write small binary message
        writer.write(mws::InternalMessage::BinaryData{token: client_token, data: bin_vec});

        // write medium text message
        writer.write(mws::InternalMessage::TextData{token: client_token, data: med_text_string});

        match reader.bread() {
            mws::InternalMessage::CloseClient{token: mio::Token(1)} => {},
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

#[test]
fn multiple_clients() {
    let (mut server, mut reader, mut writer) = mws::WebSocketServer::new("0.0.0.0", 10001);
    let text_string = String::from("Hello World");
    const CLIENT_COUNT : usize = 10;

    thread::spawn(move || {
        let mut connected = 0;
        let mut messages  = 0;
        while messages < CLIENT_COUNT {
            match reader.bread() {
                mws::InternalMessage::NewClient{token} => {
                    assert!(token == mio::Token(connected + 1));
                    connected += 1;
                },
                mws::InternalMessage::TextData{token, data} => {
                    assert!(token.as_usize() < connected + 1);
                    assert!(data == text_string);
                    messages += 1;
                },
                _ => assert!(false),
            }
        }

        assert!(connected == CLIENT_COUNT);
        assert!(messages  == CLIENT_COUNT);

        for i in 0..CLIENT_COUNT {
            writer.write(mws::InternalMessage::CloseClient{token: mio::Token(i+2)});
        }

        thread::sleep_ms(1000);

        writer.write(mws::InternalMessage::Shutdown);
    });

    thread::spawn(|| {
        std::process::Command::new("ruby")
            .arg("utils/multiple_clients_test.rb")
            .arg("10001")
            .arg(format!("{}", CLIENT_COUNT))
            .output()
            .unwrap();
    });

    server.start();
}
