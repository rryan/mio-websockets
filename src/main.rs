/*
 * TODO
 * + handle errors, don't unwrap everything
 * + handle multiframe messages
 * + send PING from server
 */
extern crate mio;
extern crate http_muncher;
extern crate sha1;
extern crate rustc_serialize;
extern crate byteorder;

use std::collections::HashMap;
use std::collections::LinkedList;
use std::cell::RefCell;
use std::rc::Rc;
use std::fmt;
use std::sync::mpsc;
use std::thread;
use std::str::FromStr;
use std::io::Read;
use std::io::Write;

use mio::*;
use mio::tcp::*;
use http_muncher::{Parser, ParserHandler};
use rustc_serialize::base64::{ToBase64, STANDARD};

enum ReadError {
    Fatal,
    Incomplete,
}

enum InternalMessage {
    NewClient{token: Token},
    CloseClient{token: Token},
    TextData{token: Token, data: String},
    BinaryData{token: Token, data: Vec<u8>},
    Ping{token: Token},
    Pong{token: Token},
}

fn im_from_wire(token: Token, opcode: OpCode, data: Vec<u8>) -> Option<InternalMessage> {
    let msg = match opcode {
        OpCode::Text =>
            InternalMessage::TextData{
                token: token,
                data: String::from_utf8(data).unwrap()
            },
        OpCode::Binary => InternalMessage::BinaryData{token: token, data: data},
        OpCode::Close => InternalMessage::CloseClient{token: token},
        OpCode::Ping => InternalMessage::Ping{token: token},
        OpCode::Pong => InternalMessage::Pong{token: token},
        OpCode::Continuation => unreachable!(),
    };

    Some(msg)
}

pub const OP_CODE_MASK: u8 = 0b0000_1111;
pub const FINAL_FRAME_MASK: u8 = 0b1000_0000;
pub const MASKING_MASK: u8 = 0b1000_0000;
pub const PAYLOAD_KEY_UN_MASK: u8 = 0b0111_1111;

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

pub enum OpCode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            OpCode::Continuation => "Continuation".fmt(f),
            OpCode::Text => "Text".fmt(f),
            OpCode::Binary => "Binary".fmt(f),
            OpCode::Close => "Close".fmt(f),
            OpCode::Ping => "Ping".fmt(f),
            OpCode::Pong => "Pong".fmt(f),
        }
    }
}

fn gen_key(key: &String) -> String {
    let mut m = sha1::Sha1::new();
    let mut buf = [0u8; 20];

    m.update(key.as_bytes());
    m.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11".as_bytes());

    m.output(&mut buf);

    return buf.to_base64(STANDARD);
}

struct HttpParser {
    current_key: Option<String>,
    headers: Rc<RefCell<HashMap<String, String>>>
}

impl ParserHandler for HttpParser {
    fn on_header_field(&mut self, s: &[u8]) -> bool {
        self.current_key = Some(std::str::from_utf8(s).unwrap().to_string());
        true
    }

    fn on_header_value(&mut self, s: &[u8]) -> bool {
        self.headers.borrow_mut()
            .insert(self.current_key.clone().unwrap(),
                    std::str::from_utf8(s).unwrap().to_string());
        true
    }

    fn on_headers_complete(&mut self) -> bool {
        false
    }
}

#[derive(PartialEq)]
#[derive(Debug)]
enum CStates {
    AwaitingHandshake,
    HandshakeResponse,
    Open,
    ReceivedClose,
    SentClose,
}

struct ClientState {
    state: CStates,
}

impl ClientState {
    fn new() -> ClientState {
        ClientState{
            state: CStates::AwaitingHandshake,
        }
    }

    fn update_handshake_response(&mut self) {
        assert!(self.state == CStates::AwaitingHandshake);
        self.state = CStates::HandshakeResponse;
    }

    fn update_open(&mut self) {
        assert!(self.state == CStates::HandshakeResponse);
        self.state = CStates::Open;
    }

    fn update_received_close(&mut self) {
        assert!(self.state == CStates::Open);
        self.state = CStates::ReceivedClose;
    }

    fn update_sent_close(&mut self) {
        assert!(self.state == CStates::Open);
        self.state = CStates::SentClose;
    }

    fn interest(&self, outgoing: bool) -> EventSet {
        let mut interest = EventSet::none();

        match self.state {
            CStates::AwaitingHandshake => unreachable!(),
            CStates::HandshakeResponse => interest.insert(EventSet::writable()),
            CStates::Open => {
                interest.insert(EventSet::readable());
                if outgoing {
                    interest.insert(EventSet::writable());
                }
            },
            CStates::ReceivedClose => interest.insert(EventSet::writable()),
            CStates::SentClose => interest.insert(EventSet::readable()),
        }

        interest
    }
}

struct WebSocketClient {
    socket: TcpStream,
    headers: Rc<RefCell<HashMap<String, String>>>,
    http_parser: Parser<HttpParser>,
    state: ClientState,
    outgoing_messages: std::collections::LinkedList<InternalMessage>,
}

impl WebSocketClient {
    fn new(socket: TcpStream) -> WebSocketClient {
        let headers = Rc::new(RefCell::new(HashMap::new()));

        WebSocketClient {
            socket: socket,
            headers: headers.clone(),
            http_parser: Parser::request(HttpParser {
                current_key: None,
                headers: headers.clone()
            }),
            state: ClientState::new(),
            outgoing_messages: std::collections::LinkedList::new(),
        }
    }

    fn interest(&mut self) -> EventSet {
        self.state.interest(self.outgoing_messages.len() > 0)
    }

    // /////////////////////
    //   Writing to Client
    // /////////////////////
    fn handshake_response(&mut self) {
        let headers      = self.headers.borrow();
        let response_key = gen_key(&headers.get("Sec-WebSocket-Key").unwrap());
        let response     = fmt::format(
            format_args!("HTTP/1.1 101 Switching Protocols\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {}\r\n\
                         Upgrade: websocket\r\n\r\n", response_key));
        self.socket.try_write(response.as_bytes()).unwrap();
        self.state.update_open();
    }

    fn write_message(&mut self, op: OpCode, payload: &mut Vec<u8>) {
        let mut out_buf: Vec<u8> = Vec::with_capacity(payload.len() + 9);

        self.set_op_code(&op, &mut out_buf);
        self.set_payload_info(payload.len(), &mut out_buf);

        // TODO - Fix with Vec.append() once stable
        // out_buf.append(payload);
        for byte in payload.iter() {
            out_buf.push(*byte);
        }

        self.socket.try_write(&out_buf).unwrap();
    }

    fn set_op_code(&self, op: &OpCode, buf: &mut Vec<u8>) {
        let op_code = match *op {
            OpCode::Continuation    => OP_CONTINUATION,
            OpCode::Text            => OP_TEXT,
            OpCode::Binary          => OP_BINARY,
            OpCode::Close           => OP_CLOSE,
            OpCode::Ping            => OP_PING,
            OpCode::Pong            => OP_PONG
        };
        buf.push(op_code | MASKING_MASK);
    }

    fn set_payload_info(&self, len: usize, buf: &mut Vec<u8>) {
        if len <= 125 {
            buf.push(len as u8);
        } else if len <= 65535 {
            let mut len_buf = [0u8; 2];
            len_buf[0] = (len as u16 & 0b1111_1111u16 << 8) as u8;
            len_buf[1] = (len as u16 & 0b1111_1111 as u16) as u8;

            buf.push(126u8); // 16 bit prelude
            buf.push(len_buf[0]);
            buf.push(len_buf[1]);
        } else {
            let mut len_buf = [0u8; 8];
            len_buf[0] = (len as u64 & 0b1111_1111u64 << 56) as u8;
            len_buf[1] = (len as u64 & 0b1111_1111u64 << 48) as u8;
            len_buf[2] = (len as u64 & 0b1111_1111u64 << 40) as u8;
            len_buf[3] = (len as u64 & 0b1111_1111u64 << 32) as u8;
            len_buf[4] = (len as u64 & 0b1111_1111u64 << 24) as u8;
            len_buf[5] = (len as u64 & 0b1111_1111u64 << 16) as u8;
            len_buf[6] = (len as u64 & 0b1111_1111u64 << 8) as u8;
            len_buf[7] = (len as u64 & 0b1111_1111u64) as u8;

            buf.push(127u8); // 64 bit prelude
            buf.push(len_buf[0]);
            buf.push(len_buf[1]);
            buf.push(len_buf[2]);
            buf.push(len_buf[3]);
            buf.push(len_buf[4]);
            buf.push(len_buf[5]);
            buf.push(len_buf[6]);
            buf.push(len_buf[7]);
        }
    }

    // /////////////////////
    //  Reading from Client
    // /////////////////////
    fn handshake_request(&mut self) {
        loop {
            let mut buf = [0; 2048];
            match self.socket.try_read(&mut buf) {
                Err(e) => {
                    panic!("Error while reading socket: {:?}", e);
                },
                Ok(None) =>
                    // Socket buffer has got no more bytes.
                    panic!("handle this"),
                Ok(Some(_len)) => {
                    self.http_parser.parse(&buf);
                    if self.http_parser.is_upgrade() {
                        self.state.update_handshake_response();
                        return;
                    }
                }
            }
        }
    }

    fn read_message(&mut self) -> Result<(OpCode, Vec<u8>), ReadError> {
        let (opcode, final_frame) : (OpCode, bool) = match self.read_op_code() {
            None => {
                println!("bad opcode");
                return Err(ReadError::Fatal);
            }
            Some((o, ff)) => (o, ff)
        };

        if false == final_frame {
            println!("multiframe messages unsupported");
            return Err(ReadError::Incomplete);
        }

        let (payload_len,masking):(u64,bool) = match self.read_payload_length_and_masking_bit() {
            None => {
                println!("bad payload length or masking bit");
                return Err(ReadError::Fatal);
            }
            Some((len, masking)) => (len, masking)
        };

        let masking_key = match masking {
            true  => self.read_masking_key(),
            false => None,
        };

        // XXX: read extension data

        // XXX
        if payload_len > (usize::max_value() as u64) {
            println!("payload length too large");
            return Err(ReadError::Fatal);
        }

        let payload_len = payload_len as usize;
        let app_data = match self.read_application_data(payload_len) {
            None => {
                println!("bad application data");
                return Err(ReadError::Fatal);
            }
            Some(data) => data
        };
        assert!(app_data.len() == payload_len);

        if masking_key.is_none() {
            return Ok((opcode, app_data));
        }
        let masking_key = masking_key.unwrap();

        let mut output = Vec::<u8>::with_capacity(payload_len);
        for i in 0..payload_len {
            output.push(app_data[i] ^ masking_key[i % 4]);
        }

        return Ok((opcode, output))
    }

    fn read_op_code(&mut self) -> Option<(OpCode, bool)> {
        let mut buff = Vec::new();
        match std::io::Read::by_ref(&mut self.socket).take(1).read_to_end(&mut buff) {
            Ok(1)  => {},
            Ok(_)  => return None,
            Err(_) => return None,
        }

        let op = match buff[0] & OP_CODE_MASK {
            OP_CONTINUATION => OpCode::Continuation,
            OP_TEXT         => OpCode::Text,
            OP_BINARY       => OpCode::Binary,
            OP_CLOSE        => OpCode::Close,
            OP_PING         => OpCode::Ping,
            OP_PONG         => OpCode::Pong,
            _               => return None,
        };

        Some((op, (buff[0] & FINAL_FRAME_MASK) == FINAL_FRAME_MASK))
    }

    fn read_payload_length_and_masking_bit(&mut self) -> Option<(u64, bool)> {
        use byteorder::ReadBytesExt;

        let mut buff = Vec::new();
        std::io::Read::by_ref(&mut self.socket).take(1).read_to_end(&mut buff).unwrap();
        let masking : bool = (buff[0] & MASKING_MASK) == MASKING_MASK;
        let key     : u8   = buff[0] & PAYLOAD_KEY_UN_MASK;

        // network byte order (big endian)
        let len = match key {
            0 ... 125 => key as u64,
            126  => {
                // self.socket.by_ref().take(2).read_to_end(&buff);
                self.socket.read_u16::<byteorder::BigEndian>().unwrap() as u64
            },
            127  => {
                self.socket.read_u64::<byteorder::BigEndian>().unwrap()
            },
            _ => unreachable!(),
        };

        Some((len, masking))
    }

    fn read_masking_key(&mut self) -> Option<Vec<u8>> {
        let mut buff = Vec::new();
        std::io::Read::by_ref(&mut self.socket).take(4).read_to_end(&mut buff).unwrap();
        return Some(buff);
    }

    fn read_application_data(&mut self, len : usize) -> Option<Vec<u8>> {
        let mut buff = Vec::new();
        std::io::Read::by_ref(&mut self.socket).take(len as u64).read_to_end(&mut buff).unwrap();
        return Some(buff);
    }
}

struct Counter {
    value: usize,
}

impl Counter {
    fn new() -> Counter {
        Counter{value:0}
    }

    fn next(&mut self) -> Token {
        self.value += 1;
        return Token(self.value - 1);
    }
}

struct InternalReader {
    event_buffer: LinkedList<InternalMessage>,
    output_rx: mpsc::Receiver<InternalMessage>,
}

impl InternalReader {
    fn new(output_rx: mpsc::Receiver<InternalMessage>) -> InternalReader {
        InternalReader {
            event_buffer: LinkedList::new(),
            output_rx: output_rx,
        }
    }

    fn bread(&mut self) -> InternalMessage {
        if self.event_buffer.len() == 0 {
            match self.output_rx.recv() {
                Ok(m)  => self.event_buffer.push_back(m),
                Err(_) => panic!("whattodo"),
            }
        }
        return self.event_buffer.pop_front().unwrap();
    }

    fn read(&mut self) -> Option<InternalMessage> {
        match self.output_rx.try_recv() {
            Ok(m)  => self.event_buffer.push_back(m),
            Err(_) => {},
        }

        self.event_buffer.pop_front()
    }
}

struct InternalWriter {
    pipe_writer: unix::PipeWriter,
    input_tx: mpsc::Sender<InternalMessage>,
}

impl InternalWriter {
    fn new(pipe_writer: unix::PipeWriter,
           input_tx: mpsc::Sender<InternalMessage>) -> InternalWriter {
        InternalWriter {
            input_tx    : input_tx,
            pipe_writer : pipe_writer,
        }
    }

    fn write(&mut self, msg: InternalMessage) {
        // FIXME: correct way to handle `poke`?
        let poke = "a";
        self.pipe_writer.write(poke.to_string().as_bytes()).unwrap();
        self.pipe_writer.flush().unwrap();
        self.input_tx.send(msg).unwrap();
    }
}

struct WebSocketServer {
    counter: Counter,
    socket: TcpListener,
    clients: HashMap<Token, WebSocketClient>,
    input_rx: mpsc::Receiver<InternalMessage>,
    output_tx: mpsc::Sender<InternalMessage>,
    server_token: Token,
    pipe_token: Token,
    pipe_reader: unix::PipeReader,
}

impl WebSocketServer {
    fn new(_ip: &str, _port: u32) -> (WebSocketServer, InternalReader, InternalWriter) {
        // i/o wrt to the event loop
        let (p_reader, p_writer)   = unix::pipe().unwrap();
        let (input_tx,  input_rx)  = mpsc::channel();
        let (output_tx, output_rx) = mpsc::channel();

        // FIXME: use ip + port
        let server_socket = TcpSocket::v4().unwrap();
        let address = FromStr::from_str("0.0.0.0:10000").unwrap();
        server_socket.bind(&address).unwrap();
        let server_socket = server_socket.listen(256).unwrap();

        let mut counter = Counter::new();

        (WebSocketServer {
            clients:        HashMap::new(),
            socket:         server_socket,
            input_rx:       input_rx,
            output_tx:      output_tx,
            server_token:   counter.next(),
            pipe_token:     counter.next(),
            counter:        counter,
            pipe_reader:    p_reader,
        },
        InternalReader::new(output_rx),
        InternalWriter::new(p_writer, input_tx))
    }

    fn start(&mut self) {
        let mut event_loop = EventLoop::new().unwrap();
        event_loop.register_opt(&self.socket,
                                self.server_token,
                                EventSet::readable(),
                                PollOpt::edge()).unwrap();
        event_loop.register_opt(&self.pipe_reader,
                                self.pipe_token,
                                EventSet::readable(),
                                PollOpt::edge()).unwrap();
        event_loop.run(self).unwrap();
    }

    fn close_connection(&mut self, token : Token) {
        self.clients.remove(&token);
        self.output_tx.send(InternalMessage::CloseClient{token: token}).unwrap();
    }
}

impl Handler for WebSocketServer {
    type Timeout = usize;
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<WebSocketServer>,
             token: Token, events: EventSet) {
        if token == self.server_token {
            assert!(events.is_readable());
            let client_socket = match self.socket.accept() {
                Ok(Some(sock)) => sock,
                Ok(None) => unreachable!(),
                Err(e) => {
                    println!("Accept error: {}", e);
                    return;
                }
            };

            let new_token = self.counter.next();
            self.clients.insert(new_token, WebSocketClient::new(client_socket));

            event_loop.register_opt(&self.clients[&new_token].socket,
                                    new_token, EventSet::readable(),
                                    PollOpt::edge() | PollOpt::oneshot()).unwrap();
            return;
        }

        // -----------------------------
        // -----------------------------

        let updated_token : Token;
        if token == self.pipe_token {
            assert!(events.is_readable());
            // FIXME: handle a broken pipe (ie, reads zero bytes)
            self.pipe_reader.by_ref().take(1).read_to_end(&mut Vec::new()).unwrap();
            let msg = self.input_rx.recv();
            match msg {
                Err(_e) => {return;},
                Ok(InternalMessage::NewClient{token: _}) => {return;},
                Ok(InternalMessage::CloseClient{token}) |
                        Ok(InternalMessage::TextData{token, data: _}) |
                        Ok(InternalMessage::BinaryData{token, data: _}) |
                        Ok(InternalMessage::Ping{token}) |
                        Ok(InternalMessage::Pong{token}) => {
                    let client = self.clients.get_mut(&token);
                    if client.is_none() {
                        println!("tried sending message to non-existent client!");
                        return;
                    }

                    let client = client.unwrap();
                    if client.state.state != CStates::Open {
                        println!("wrong client state for sending piped stuff!");
                        return;
                    }

                    client.outgoing_messages.push_back(msg.unwrap());
                    updated_token = token;
                },
            }
        } else {
            if events.is_readable() && self.clients.contains_key(&token) {
                match self.clients.get_mut(&token).unwrap().state.state {
                    CStates::AwaitingHandshake => {
                        self.clients.get_mut(&token).unwrap().handshake_request();
                    },
                    CStates::HandshakeResponse => unreachable!(),
                    CStates::Open => {
                        println!("GOT MSG");
                        match self.clients.get_mut(&token).unwrap().read_message() {
                            Ok((opcode, data)) => {
                                let mut client = self.clients.get_mut(&token).unwrap();
                                match im_from_wire(token, opcode, data) {
                                    Some(InternalMessage::Ping{token}) => {
                                        client.outgoing_messages.push_back(InternalMessage::Pong{token: token});
                                    },
                                    Some(InternalMessage::Pong{token: _}) => {},
                                    Some(InternalMessage::CloseClient{token: _}) => {
                                        client.state.update_received_close();
                                    },
                                    Some(InternalMessage::NewClient{token: _}) => unreachable!(),
                                    Some(m) => {self.output_tx.send(m).unwrap();},
                                    None => {},
                                }
                            },
                            Err(_) => self.close_connection(token),
                        }
                    },
                    CStates::ReceivedClose => unreachable!(),
                    CStates::SentClose => {
                        let msg = self.clients.get_mut(&token).unwrap().read_message();
                        match msg {
                            Ok((opcode, data)) => {
                                match im_from_wire(token, opcode, data) {
                                    Some(InternalMessage::CloseClient{token}) => {
                                        self.close_connection(token);
                                    },
                                    _ => {},
                                }
                            },
                            Err(_) => self.close_connection(token),
                        }
                    }
                }
            }

            // We may have deleted the client in the 'readable' block
            if events.is_writable() && self.clients.contains_key(&token) {
                match self.clients.get_mut(&token).unwrap().state.state {
                    CStates::AwaitingHandshake => unreachable!(),
                    CStates::HandshakeResponse => {
                        self.clients.get_mut(&token).unwrap().handshake_response();
                        self.output_tx.send(InternalMessage::NewClient{token: token}).unwrap();
                    },
                    CStates::Open => {
                        let client = self.clients.get_mut(&token).unwrap();
                        assert!(client.outgoing_messages.len() > 0);
                        match client.outgoing_messages.pop_front().unwrap() {
                            InternalMessage::TextData{token: _token, data} => {
                                client.write_message(OpCode::Text, &mut data.into_bytes());
                            },
                            InternalMessage::BinaryData{token: _token, mut data} => {
                                client.write_message(OpCode::Binary, &mut data);
                            },
                            InternalMessage::CloseClient{token: _} => {
                                client.write_message(OpCode::Close, &mut vec!());
                                client.state.update_sent_close();
                            },
                            InternalMessage::Ping{token: _} => {
                                client.write_message(OpCode::Ping, &mut vec!());
                            },
                            InternalMessage::Pong{token: _} => {
                                client.write_message(OpCode::Pong, &mut vec!());
                            },
                            InternalMessage::NewClient{token: _} => unreachable!(),
                        }
                    },
                    CStates::ReceivedClose => {
                        {
                            let client = self.clients.get_mut(&token).unwrap();
                            client.write_message(OpCode::Close, &mut vec!());
                        }
                        self.close_connection(token);
                    },
                    CStates::SentClose => unreachable!(),
                }
            }

            updated_token = token;
        }

        // We may have just closed the connection
        match self.clients.get_mut(&updated_token) {
            Some(client) => {
                let interest = client.interest();
                event_loop.reregister(&client.socket, updated_token, interest,
                              PollOpt::edge() | PollOpt::oneshot()).unwrap();
            },
            None => {},
        };
    }
}

fn main() {
    let (mut server, mut reader, mut writer) = WebSocketServer::new("0.0.0.0", 10000);

    thread::spawn(move || {
        // Wait for new client
        match reader.bread() {
            InternalMessage::NewClient{token} => {
                println!("New Client: {:?}", token);
            },
            _ => panic!("123"),
        }

        for _ in 1..2 {
            // Receive
            match reader.bread() {
                InternalMessage::NewClient{token} => {
                    println!("New Client: {:?}", token);
                },
                InternalMessage::CloseClient{token} => {
                    println!("Close Client: {:?}", token);
                },
                InternalMessage::BinaryData{token: _, data} => {
                    println!("Binary Data: {:?}", data);
                },
                InternalMessage::TextData{token: _, data} => {
                    println!("Text Data: {:?}", data);
                },
                _ => {},
            }
        }

        writer.write(InternalMessage::TextData{token: Token(2), data: String::from("Yeah!")});

        // disconnect
        // writer.write(InternalMessage::CloseClient{token: Token(2)});

        loop {}
    });

    server.start();
}
