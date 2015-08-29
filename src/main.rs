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

enum InternalMessage {
    NewClient{client_token: Token},
    CloseClient{client_token: Token},
    Data{client_token: Token, format: String, data: String},
}

struct DataFrame {
    op_code: OpCode,
    payload_len: u64,
    masking_key: [u8; 4],
    payload: Vec<u8>
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
    /// Continuation frame from last packed
    Continuation,

    /// UTF-8 text data
    Text,

    /// Binary data as u8
    Binary,

    /// Indicates client has closed connection
    Close,

    /// Heartbeat requested from client
    Ping,

    /// Heartbeat response to ping frame
    /// Can also be sent without a ping request
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
enum ClientState {
    AwaitingHandshake,
    HandshakeResponse,
    Open,
}

#[derive(PartialEq)]
enum SubState {
    Waiting,
    Doing,
}

struct WebSocketClient {
    socket: TcpStream,
    headers: Rc<RefCell<HashMap<String, String>>>,
    http_parser: Parser<HttpParser>,
    interest: EventSet,
    state: ClientState,
    writing_substate: SubState,
    reading_substate: SubState,
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
            interest: EventSet::readable(),
            state: ClientState::AwaitingHandshake,
            writing_substate: SubState::Waiting,
            reading_substate: SubState::Waiting,
            outgoing_messages: std::collections::LinkedList::new(),
        }
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
    fn handshake_request(&mut self) -> bool {
        loop {
            let mut buf = [0; 2048];
            match self.socket.try_read(&mut buf) {
                Err(e) => {
                    panic!("Error while reading socket: {:?}", e);
                },
                Ok(None) =>
                    // Socket buffer has got no more bytes.
                    return false,
                Ok(Some(_len)) => {
                    self.http_parser.parse(&buf);
                    if self.http_parser.is_upgrade() {
                        return true;
                    }
                }
            }
        }
    }

    // return none if it's a multiframe message and we aren't on the last frame yet
    fn read_message(&mut self) -> Option<(OpCode, Vec<u8>)> {
        let (opcode, final_frame) : (OpCode, bool) = match self.read_op_code() {
            None => {
                println!("bad opcode");
                return None;
            }
            Some((o, ff)) => (o, ff)
        };

        if false == final_frame {
            println!("no support for multiframe messages");
            return None;
        }

        let (payload_len,masking):(u64,bool) = match self.read_payload_length_and_masking_bit() {
            None => {
                println!("bad payload length or masking bit");
                return None;
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
            return None;
        }

        let payload_len = payload_len as usize;
        let app_data = match self.read_application_data(payload_len) {
            None => {
                println!("bad application data");
                return None;
            }
            Some(data) => data
        };
        assert!(app_data.len() == payload_len);

        if masking_key.is_none() {
            return Some((opcode, app_data));
        }
        let masking_key = masking_key.unwrap();

        let mut output = Vec::<u8>::with_capacity(payload_len);
        for i in 0..payload_len {
            output.push(app_data[i] ^ masking_key[i % 4]);
        }

        return Some((opcode, output))
    }

    fn read_op_code(&mut self) -> Option<(OpCode, bool)> {
        let mut buff = Vec::new();
        std::io::Read::by_ref(&mut self.socket).take(1).read_to_end(&mut buff).unwrap();
        let op = match buff[0] & OP_CODE_MASK {
            OP_CONTINUATION => OpCode::Continuation,
            OP_TEXT         => OpCode::Text,
            OP_BINARY       => OpCode::Binary,
            OP_CLOSE        => OpCode::Close,
            OP_PING         => OpCode::Ping,
            OP_PONG         => OpCode::Pong,
            _ => return None,
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
        std::io::Read::by_ref(&mut self.socket).take(len as u64).read_to_end(&mut buff);
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
        self.pipe_writer.flush();
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
}

impl Handler for WebSocketServer {
    type Timeout = usize;
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<WebSocketServer>,
             token: Token, events: EventSet) {
        let mut reregister_token : Option<Token> = None;
        println!("TOKEN: {:?}", token);
        if events.is_readable() {
            if token == self.server_token {
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
            } else if token == self.pipe_token {
                // FIXME: handle a broken pipe (ie, reads zero bytes)
                self.pipe_reader.by_ref().take(1).read_to_end(&mut Vec::new()).unwrap();
                let msg = self.input_rx.recv();
                match msg {
                    Ok(InternalMessage::NewClient{client_token: _}) => {},
                    Err(_e) => {},
                    Ok(InternalMessage::CloseClient{client_token: token}) |
                        Ok(InternalMessage::Data{client_token: token, format: _, data: _}) => {
                        match self.clients.get_mut(&token) {
                            Some(client) => {
                                if client.state == ClientState::Open {
                                    client.outgoing_messages.push_back(msg.unwrap());
                                    client.writing_substate = SubState::Doing;
                                    reregister_token = Some(token);
                                }
                            },
                            None => println!("tried sending message to non-existent client!"),
                        }
                    },
                }
            } else {
                let mut client = self.clients.get_mut(&token).unwrap();
                match client.state {
                    ClientState::AwaitingHandshake => {
                        assert!(client.reading_substate == SubState::Waiting);
                        if true == client.handshake_request() {
                            client.state = ClientState::HandshakeResponse;
                            client.reading_substate = SubState::Doing;
                            reregister_token = Some(token);
                        }
                    },
                    ClientState::HandshakeResponse => unreachable!(),
                    ClientState::Open => {
                        assert!(client.reading_substate == SubState::Doing);
                        println!("GOT MSG");
                        match client.read_message() {
                            None => {},
                            Some((opcode, payload)) => println!("PAYLOAD: {:?}", payload),
                        }
                        // self.output_tx.send(InternalMessage::Data
                    },
                }
            }
        }

        if events.is_writable() {
            if token != self.server_token && token != self.pipe_token {
                let mut client = self.clients.get_mut(&token).unwrap();
                match client.state {
                    ClientState::AwaitingHandshake => unreachable!(),
                    ClientState::HandshakeResponse => {
                        client.handshake_response();
                        client.state      = ClientState::Open;
                        reregister_token  = Some(token);

                        self.output_tx.send(InternalMessage::NewClient{client_token: token}).unwrap();
                    },
                    ClientState::Open => {
                        assert!(client.writing_substate == SubState::Doing);
                        assert!(client.outgoing_messages.len() > 0);
                        match client.outgoing_messages.pop_front() {
                            Some(InternalMessage::Data{client_token: token, format, data}) => {
                                // FIXME
                                // client.write_message(OpCode::Text, &mut m.into_bytes());
                            },
                            Some(InternalMessage::CloseClient{client_token: token}) => {
                                client.write_message(OpCode::Close, &mut vec!());
                                client.writing_substate = SubState::Waiting;
                            },
                            Some(InternalMessage::NewClient{client_token: _token}) => unreachable!(),
                            None => unreachable!(),
                        }
                    },
                }
            }
        }

        match reregister_token {
            Some(token) => {
                let client = self.clients.get(&token).unwrap();
                let mut interest = EventSet::none();
                match client.state {
                    ClientState::AwaitingHandshake => unreachable!(),
                    ClientState::HandshakeResponse => interest.insert(EventSet::writable()),
                    ClientState::Open => {
                        match client.reading_substate {
                            SubState::Waiting => {},
                            SubState::Doing   => interest.insert(EventSet::readable()),
                        }

                        match client.writing_substate {
                            SubState::Waiting => {},
                            SubState::Doing   => interest.insert(EventSet::writable()),
                        }
                    }
                }

                event_loop.reregister(&client.socket, token, interest,
                                      PollOpt::edge() | PollOpt::oneshot()).unwrap();
            },
            None => {},
        }
    }
}

fn main() {
    let (mut server, mut reader, mut writer) = WebSocketServer::new("0.0.0.0", 10000);

    thread::spawn(move || {
        // Wait for new client
        match reader.bread() {
            InternalMessage::NewClient{client_token: token} => {
                println!("New Client: {:?}", token);
            },
            _ => panic!("123"),
        }

        // Receive
        match reader.bread() {
            InternalMessage::NewClient{client_token: token} => {
                println!("New Client: {:?}", token);
            },
            InternalMessage::CloseClient{client_token: token} => {
                println!("Close Client: {:?}", token);
            },
            InternalMessage::Data{client_token: _token, format: _format, data: _data} =>
                {},
        }

        // disconnect
        writer.write(InternalMessage::CloseClient{client_token: Token(2)});

        loop {}
    });

    server.start();
}
