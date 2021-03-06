extern crate mio;
extern crate http_muncher;
extern crate sha1;
extern crate rustc_serialize;

use std::collections::HashMap;
use std::collections::LinkedList;
use std::cell::RefCell;
use std::rc::Rc;
use std::fmt;
use std::sync::mpsc;
use std::str::FromStr;

use mio::{TryRead, TryWrite, PollOpt, EventSet, EventLoop, Handler, tcp};
use http_muncher::{Parser, ParserHandler};
use rustc_serialize::base64::{ToBase64, STANDARD};

pub use mio::Token;

enum ReadError {
    Fatal,
    Incomplete,
}


// ####################
// ####################
//   Internal Message
// ####################
// ####################
pub enum InternalMessage {
    NewClient{token: Token},
    CloseClient{token: Token},
    TextData{token: Token, data: String},
    BinaryData{token: Token, data: Vec<u8>},
    Ping{token: Token, data: Vec<u8>},
    Pong{token: Token, data: Vec<u8>},
    Shutdown,
}

fn im_from_wire(token: &Token, opcode: OpCode, data: Vec<u8>) -> Result<InternalMessage, ReadError> {
    let token = token.clone();
    let msg = match opcode {
        OpCode::Text => {
            let data = match String::from_utf8(data) {
                Ok(data) => data,
                Err(_)   => {return Err(ReadError::Fatal);},
            };
            InternalMessage::TextData{
                token: token,
                data:  data,
            }
        },
        OpCode::Binary       => InternalMessage::BinaryData{token: token, data: data},
        OpCode::Close        => InternalMessage::CloseClient{token: token},
        OpCode::Ping         => InternalMessage::Ping{token: token, data: data},
        OpCode::Pong         => InternalMessage::Pong{token: token, data: data},
        OpCode::Continuation => unreachable!(),
    };

    Ok(msg)
}

pub struct InternalReader {
    event_buffer : LinkedList<InternalMessage>,
    output_rx    : mpsc::Receiver<InternalMessage>,
}

impl InternalReader {
    fn new(output_rx: mpsc::Receiver<InternalMessage>) -> InternalReader {
        InternalReader {
            event_buffer : LinkedList::new(),
            output_rx    : output_rx,
        }
    }

    pub fn bread(&mut self) -> InternalMessage {
        if self.event_buffer.len() == 0 {
            match self.output_rx.recv() {
                Ok(m)  => self.event_buffer.push_back(m),
                Err(_) => panic!("aborting: Internal channel is broken"),
            }
        }
        assert!(self.event_buffer.len() > 0);
        return self.event_buffer.pop_front().unwrap();
    }

    pub fn read(&mut self) -> Option<InternalMessage> {
        match self.output_rx.try_recv() {
            Ok(m)  => self.event_buffer.push_back(m),
            Err(_) => {},
        }

        self.event_buffer.pop_front()
    }
}

#[derive(Clone)]
pub struct InternalWriter {
    input_tx : mio::Sender<InternalMessage>,
}

impl InternalWriter {
    fn new(input_tx: mio::Sender<InternalMessage>) -> InternalWriter {
        InternalWriter {input_tx : input_tx}
    }

    pub fn write(&mut self, msg: InternalMessage) {
        self.input_tx.send(msg).unwrap();
    }
}

// ###################
// ###################
//      Op Codes
// ###################
// ###################
pub const OP_CODE_MASK:        u8 = 0b0000_1111;
pub const FINAL_FRAME_MASK:    u8 = 0b1000_0000;
pub const MASKING_MASK:        u8 = 0b1000_0000;
pub const PAYLOAD_KEY_UN_MASK: u8 = 0b0111_1111;

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT:         u8 = 0x1;
pub const OP_BINARY:       u8 = 0x2;
pub const OP_CLOSE:        u8 = 0x8;
pub const OP_PING:         u8 = 0x9;
pub const OP_PONG:         u8 = 0xA;

#[derive(Clone, PartialEq)]
pub enum OpCode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

fn is_control_opcode(opcode : &OpCode) -> bool {
    match opcode {
        &OpCode::Close | &OpCode::Ping | &OpCode::Pong => true,
        _                                              => false,
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            OpCode::Continuation => "Continuation".fmt(f),
            OpCode::Text         => "Text".fmt(f),
            OpCode::Binary       => "Binary".fmt(f),
            OpCode::Close        => "Close".fmt(f),
            OpCode::Ping         => "Ping".fmt(f),
            OpCode::Pong         => "Pong".fmt(f),
        }
    }
}


// ###################
// ###################
//    HTTP handling
// ###################
// ###################
fn gen_key(key: &String) -> String {
    let mut m   = sha1::Sha1::new();
    let mut buf = [0u8; 20];

    m.update(key.as_bytes());
    m.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11".as_bytes());

    m.output(&mut buf);

    return buf.to_base64(STANDARD);
}

struct HttpParser {
    current_key : Option<String>,
    headers     : Rc<RefCell<HashMap<String, String>>>
}

impl ParserHandler for HttpParser {
    fn on_header_field(&mut self, s: &[u8]) -> bool {
        match std::str::from_utf8(s) {
            Ok(s)  => self.current_key = Some(s.to_string()),
            Err(_) => {},
        }

        true
    }

    fn on_header_value(&mut self, s: &[u8]) -> bool {
        if self.current_key.is_some() {
            match std::str::from_utf8(s) {
                Ok(s) => {
                    let key = self.current_key.clone().unwrap();
                    self.headers.borrow_mut().insert(key, s.to_string());
                },
                Err(_) => {},
            }
        }
        self.current_key = None;

        true
    }

    fn on_headers_complete(&mut self) -> bool {
        false
    }
}


// ###################
// ###################
//    Client Socket
// ###################
// ###################
#[derive(PartialEq, Debug)]
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
            CStates::SentClose     => interest.insert(EventSet::readable()),
        }

        interest
    }
}

#[derive(PartialEq, Debug)]
enum ReadState {
    OpCode,
    PayloadKey,
    PayloadLen,
    Payload,
    MaskingKey,
}

struct ReadBuffer {
    state       : ReadState,
    opcode      : Option<OpCode>,
    final_frame : Option<bool>,
    payload_key : Option<u8>,
    payload_len : Option<u64>,
    masking     : Option<bool>,
    masking_key : Option<[u8; 4]>,

    remaining   : u64,
    scratch     : Vec<u8>,
    frames      : LinkedList<(OpCode, Vec<u8>)>,
}

impl ReadBuffer {
    fn new() -> ReadBuffer {
        ReadBuffer {
            state       : ReadState::OpCode,
            opcode      : None,
            final_frame : None,
            payload_key : None,
            payload_len : None,
            masking     : None,
            masking_key : None,

            remaining   : 0,
            scratch     : Vec::new(),
            frames      : LinkedList::new(),
        }
    }

    fn reset_per_frame_state(&mut self) {
        self.state       = ReadState::OpCode;
        self.opcode      = None;
        self.final_frame = None;
        self.payload_key = None;
        self.payload_len = None;
        self.masking     = None;
        self.masking_key = None;
    }

    fn stateful_read(&mut self, socket : &mut tcp::TcpStream) -> Result<bool, u8> {
        let     count = self.remaining as usize;
        let mut buff  = Vec::with_capacity(count);
        unsafe { buff.set_len(count); }
        match socket.try_read(&mut buff[..]) {
            Ok(Some(n)) => {
                assert!(buff.len() == count);
                assert!(n <= count);

                // FIXME: copy
                unsafe { buff.set_len(n); }
                self.scratch.extend(buff.iter());

                self.remaining -= n as u64;
                return Ok(self.remaining == 0);
            },
            Ok(None) => {return Ok(false);}
            Err(_) => {return Err(1);}
        };
    }
}

struct WebSocketClient {
    socket            : tcp::TcpStream,
    headers           : Rc<RefCell<HashMap<String, String>>>,
    http_parser       : Parser<HttpParser>,
    state             : ClientState,
    outgoing_messages : std::collections::LinkedList<InternalMessage>,
    read_buffer       : ReadBuffer,
}

impl WebSocketClient {
    fn new(socket: tcp::TcpStream) -> WebSocketClient {
        let headers = Rc::new(RefCell::new(HashMap::new()));

        WebSocketClient {
            socket      : socket,
            headers     : headers.clone(),
            http_parser : Parser::request(HttpParser {
                current_key : None,
                headers     : headers.clone()
            }),
            state             : ClientState::new(),
            outgoing_messages : std::collections::LinkedList::new(),
            read_buffer       : ReadBuffer::new(),
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
        WebSocketClient::set_payload_info(payload.len() as u64, &mut out_buf);

        out_buf.extend(payload.iter());

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
        buf.push(op_code | FINAL_FRAME_MASK);
    }

    fn set_payload_info(len: u64, buf: &mut Vec<u8>) {
        if len <= 125 {
            buf.push(len as u8);
        } else if len <= 65535 {
            buf.push(126u8); // 16 bit prelude
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        } else {
            buf.push(127u8); // 64 bit prelude
            for i in (0..8) {
                buf.push((len >> (56-i*8)) as u8);
            }
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
                    // FIXME: Socket buffer has got no more bytes.
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

    // Control frames can be injected into the middle of fragmented messages.
    // This means that a successfull return doesn't imply the message that
    // previously caused a ReadError::Incomplete has finished.
    fn read_message(&mut self, token: &Token) -> Result<InternalMessage, ReadError> {
        if ReadState::OpCode == self.read_buffer.state {
            assert!(self.read_buffer.opcode.is_none());
            assert!(self.read_buffer.final_frame.is_none());
            match self.read_op_code() {
                Err(_)      => return Err(ReadError::Fatal),
                Ok((o, ff)) => {
                    self.read_buffer.opcode      = Some(o);
                    self.read_buffer.final_frame = Some(ff);
                    self.read_buffer.state       = ReadState::PayloadKey;

                    // Is the frame violating any protocol rules?
                    if is_control_opcode(&self.read_buffer.opcode.as_ref().unwrap()) {
                        if Some(false) == self.read_buffer.final_frame {
                            println!("Control messages must not be fragmented!");
                            return Err(ReadError::Fatal);
                        }
                    } else {
                        if self.read_buffer.frames.len() > 0 && self.read_buffer.opcode != Some(OpCode::Continuation) {
                            println!("Subsequent frames in a data message must have opcode == continuation");
                            return Err(ReadError::Fatal);
                        }
                    }
                },
            };
        }
        assert!(self.read_buffer.opcode.is_some());
        assert!(self.read_buffer.final_frame.is_some());

        if Some(OpCode::Continuation) == self.read_buffer.opcode {
            if self.read_buffer.frames.len() < 1 {
                println!("First frame shouldn't be a continuation!");
                return Err(ReadError::Fatal);
            }
        }

        if ReadState::PayloadKey == self.read_buffer.state {
            assert!(self.read_buffer.payload_key.is_none());
            assert!(self.read_buffer.masking.is_none());
            match self.read_payload_key() {
                Err(_) => {
                    println!("bad payload key");
                    return Err(ReadError::Fatal);
                },
                Ok((key, masking)) => {
                    self.read_buffer.masking     = Some(masking);
                    self.read_buffer.payload_key = Some(key);

                    match key {
                        0 ... 125 => {
                            assert!(self.read_buffer.payload_len.is_none());
                            self.read_buffer.payload_len = Some(key as u64);
                            self.read_buffer.state       = ReadState::MaskingKey;
                            self.read_buffer.remaining   = 4;
                        },
                        126 => {
                            self.read_buffer.state     = ReadState::PayloadLen;
                            self.read_buffer.remaining = 2;
                        },
                        127 => {
                            self.read_buffer.state     = ReadState::PayloadLen;
                            self.read_buffer.remaining = 8;
                        },
                        _ => unreachable!(),
                    };
                },
            }
        }
        assert!(self.read_buffer.masking.is_some());
        assert!(self.read_buffer.payload_key.is_some());

        if ReadState::PayloadLen == self.read_buffer.state {
            assert!(self.read_buffer.payload_len.is_none());
            match self.read_payload_length() {
                Err(_)      => return Err(ReadError::Fatal),
                Ok(None)    => return Err(ReadError::Incomplete),
                Ok(Some(n)) => {
                    self.read_buffer.payload_len = Some(n);
                    self.read_buffer.state       = ReadState::MaskingKey;
                    self.read_buffer.remaining   = 4;
                },
            };
        }
        assert!(self.read_buffer.payload_len.is_some());

        if is_control_opcode(&self.read_buffer.opcode.as_ref().unwrap()) {
            if self.read_buffer.payload_len.unwrap() > 125 {
                println!("max payload size for control frames is 125");
                return Err(ReadError::Fatal);
            }
        }

        if ReadState::MaskingKey == self.read_buffer.state {
            assert!(self.read_buffer.masking_key.is_none());
            if self.read_buffer.masking == Some(false) {
                println!("client must use masking key");
                return Err(ReadError::Fatal);
            }

            match self.read_masking_key() {
                Err(_)      => return Err(ReadError::Fatal),
                Ok(None)    => return Err(ReadError::Incomplete),
                Ok(Some(k)) => {
                    self.read_buffer.masking_key = Some(k);
                    self.read_buffer.state       = ReadState::Payload;
                    self.read_buffer.remaining   = self.read_buffer.payload_len.unwrap();
                },
            }
        }
        assert!(self.read_buffer.masking_key.is_some());

        // XXX: read extension data

        if ReadState::Payload == self.read_buffer.state {
            match self.read_application_data() {
                Err(_)            => return Err(ReadError::Fatal),
                Ok(None)          => return Err(ReadError::Incomplete),
                Ok(Some(payload)) => {
                    assert!(Some(payload.len() as u64) == self.read_buffer.payload_len);
                    assert!(Some(true) == self.read_buffer.masking);
                    assert!(self.read_buffer.masking_key.unwrap().len() == 4);

                    // FIXME: copy
                    let payload_len = self.read_buffer.payload_len.unwrap();
                    let mut output = Vec::<u8>::with_capacity(payload_len as usize);
                    for i in 0..payload_len {
                        let i = i as usize;
                        output.push(payload[i] ^ self.read_buffer.masking_key.unwrap()[i % 4]);
                    }

                    // Don't try to access per frame state on read_buffer after reset
                    let frame_opcode = self.read_buffer.opcode.as_ref().unwrap().clone();
                    let final_frame  = self.read_buffer.final_frame.as_ref().unwrap().clone();
                    self.read_buffer.reset_per_frame_state();

                    if is_control_opcode(&frame_opcode) {
                        assert!(true == final_frame);
                        return im_from_wire(token, frame_opcode, output);
                    } else {
                        self.read_buffer.frames.push_back((frame_opcode, output));

                        // Are we in the middle of a multiframe message?
                        if false == final_frame {
                            return Err(ReadError::Incomplete);
                        }

                        // Handle a completed data message
                        // FIXME: copy
                        let opcode : OpCode = self.read_buffer.frames.iter().next().unwrap().0.clone();
                        let mut output : Vec<u8> = Vec::new();
                        while let Some(frame) = self.read_buffer.frames.pop_front() {
                            output.extend(frame.1);
                        }

                        assert!(self.read_buffer.scratch.is_empty());
                        self.read_buffer.frames.clear();
                        return im_from_wire(token, opcode, output);
                    }
                },
            }
        }

        unreachable!();
    }

    fn read_op_code(&mut self) -> Result<(OpCode, bool), u8> {
        let mut buff = [0; 1];
        match self.socket.try_read(&mut buff) {
            Ok(Some(1))  => {},
            Ok(_)        => return Err(1),
            Err(_)       => return Err(1),
        }

        let op = match buff[0] & OP_CODE_MASK {
            OP_CONTINUATION => OpCode::Continuation,
            OP_TEXT         => OpCode::Text,
            OP_BINARY       => OpCode::Binary,
            OP_CLOSE        => OpCode::Close,
            OP_PING         => OpCode::Ping,
            OP_PONG         => OpCode::Pong,
            _               => return Err(1),
        };

        Ok((op, (buff[0] & FINAL_FRAME_MASK) == FINAL_FRAME_MASK))
    }

    fn read_payload_key(&mut self) -> Result<(u8, bool), u8> {
        let mut buff = [0; 1];
        match self.socket.try_read(&mut buff) {
            Ok(Some(1)) => {},
            Ok(_)       => return Err(1),
            Err(_)      => return Err(1),
        }

        let masking : bool = (buff[0] & MASKING_MASK) == MASKING_MASK;
        let key     : u8   = buff[0] & PAYLOAD_KEY_UN_MASK;

        Ok((key, masking))
    }

    fn read_payload_length(&mut self) -> Result<Option<u64>, u8> {
        match self.read_buffer.stateful_read(&mut self.socket) {
            Ok(true)  => {},
            Ok(false) => return Ok(None),
            Err(e)    => return Err(e),
        }
        assert!(self.read_buffer.remaining == 0);

        // XXX: assumes host is little endian, reading from big endian (network order)
        match self.read_buffer.payload_key {
            Some(126) => {
                assert!(self.read_buffer.scratch.len() == 2);
                let len : u16 = ((self.read_buffer.scratch[0] as u16) << 8) |
                    (self.read_buffer.scratch[1] as u16);
                self.read_buffer.scratch.clear();
                return Ok(Some(len as u64));
            },
            Some(127) => {
                assert!(self.read_buffer.scratch.len() == 8);
                let mut len = 0u64;
                for i in (0..8) {
                    len += ((self.read_buffer.scratch[i] as u64) << (56 - 8*i)) as u64;
                }
                self.read_buffer.scratch.clear();
                return Ok(Some(len));
            },
            _ => unreachable!(),
        }
    }

    fn read_masking_key(&mut self) -> Result<Option<[u8; 4]>, u8> {
        match self.read_buffer.stateful_read(&mut self.socket) {
            Ok(true)  => {},
            Ok(false) => return Ok(None),
            Err(e)    => return Err(e),
        };
        assert!(self.read_buffer.remaining == 0);
        assert!(self.read_buffer.scratch.len() == 4);

        let key = [self.read_buffer.scratch[0], self.read_buffer.scratch[1],
                   self.read_buffer.scratch[2], self.read_buffer.scratch[3]];
        self.read_buffer.scratch.clear();
        return Ok(Some(key));
    }

    fn read_application_data(&mut self) -> Result<Option<Vec<u8>>, u8> {
        match self.read_buffer.stateful_read(&mut self.socket) {
            Ok(true)  => {},
            Ok(false) => return Ok(None),
            Err(e)    => return Err(e),
        };
        assert!(self.read_buffer.remaining == 0);
        assert!(Some(self.read_buffer.scratch.len() as u64) == self.read_buffer.payload_len);

        // FIXME: copy
        let buff = self.read_buffer.scratch.clone();
        self.read_buffer.scratch.clear();
        return Ok(Some(buff));
    }
}


// ####################
// ####################
//    Server Socket
// ####################
// ####################
pub struct WebSocketServer {
    counter      : Counter,
    socket       : tcp::TcpListener,
    clients      : HashMap<Token, WebSocketClient>,
    output_tx    : mpsc::Sender<InternalMessage>,
    server_token : Token,
    event_loop   : Option<EventLoop<WebSocketServer>>,
}

impl WebSocketServer {
    pub fn new(ip: &str, port: u16) -> (WebSocketServer, InternalReader, InternalWriter) {
        let (output_tx, output_rx) = mpsc::channel();


        let address = FromStr::from_str(&format!("{}:{}", ip, port)).unwrap();
        let server_socket = tcp::TcpListener::bind(&address).unwrap();

        let mut counter = Counter::new();
        let server_token = counter.next();

        let mut event_loop = EventLoop::new().unwrap();
        event_loop.register_opt(&server_socket, server_token,
                                EventSet::readable(), PollOpt::edge()).unwrap();
        let channel = event_loop.channel();

        (WebSocketServer {
            clients       : HashMap::new(),
            socket        : server_socket,
            output_tx     : output_tx,
            server_token  : server_token,
            counter       : counter,
            event_loop    : Some(event_loop),
        },
        InternalReader::new(output_rx),
        InternalWriter::new(channel))

    }

    pub fn start(&mut self) {
        let event_loop = std::mem::replace(&mut self.event_loop, None);
        event_loop.unwrap().run(self).unwrap();
    }

    fn close_connection(&mut self, token : Token) {
        self.clients.remove(&token);
        self.output_tx.send(InternalMessage::CloseClient{token: token}).unwrap();
    }
}

impl Handler for WebSocketServer {
    type Timeout = usize;
    type Message = InternalMessage;

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        match msg {
            InternalMessage::NewClient{token: _} => {
                println!("Writing NewClient to the server has no affect!");
            },
            InternalMessage::CloseClient{token} |
                    InternalMessage::TextData{token, data: _} |
                    InternalMessage::BinaryData{token, data: _} |
                    InternalMessage::Ping{token, data: _} |
                    InternalMessage::Pong{token, data: _} => {
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

                client.outgoing_messages.push_back(msg);

                let interest = client.interest();
                event_loop.reregister(&client.socket, token, interest,
                    PollOpt::edge() | PollOpt::oneshot()).unwrap();
            },
            InternalMessage::Shutdown => event_loop.shutdown(),
        }
    }

    fn ready(&mut self, event_loop: &mut EventLoop<WebSocketServer>,
             token: Token, events: EventSet) {
        if token == self.server_token {
            assert!(events.is_readable());
            let client_socket = match self.socket.accept() {
                Ok(Some(sock)) => sock,
                Ok(None)       => unreachable!(),
                Err(e)         => {
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

        if events.is_readable() && self.clients.contains_key(&token) {
            match self.clients.get_mut(&token).unwrap().state.state {
                CStates::AwaitingHandshake => {
                    self.clients.get_mut(&token).unwrap().handshake_request();
                },
                CStates::HandshakeResponse => unreachable!(),
                CStates::Open => {
                    match self.clients.get_mut(&token).unwrap().read_message(&token) {
                        Ok(InternalMessage::Ping{token, data}) => {
                            let pong = InternalMessage::Pong{token: token, data: data};
                            let mut client = self.clients.get_mut(&token).unwrap();
                            client.outgoing_messages.push_back(pong);
                        },
                        Ok(InternalMessage::Pong{token: _, data: _}) => {},
                        Ok(InternalMessage::CloseClient{token: _}) => {
                            let mut client = self.clients.get_mut(&token).unwrap();
                            client.state.update_received_close();
                        },
                        Ok(InternalMessage::NewClient{token: _}) => unreachable!(),
                        Ok(InternalMessage::Shutdown) => unreachable!(),
                        Ok(m) => {self.output_tx.send(m).unwrap();},
                        Err(ReadError::Incomplete) => {},
                        Err(ReadError::Fatal)      => self.close_connection(token),
                    }
                },
                CStates::ReceivedClose => unreachable!(),
                CStates::SentClose => {
                    match self.clients.get_mut(&token).unwrap().read_message(&token) {
                        Ok(InternalMessage::CloseClient{token}) => self.close_connection(token),
                        Ok(_)  => {},
                        Err(_) => self.close_connection(token),
                    }
                },
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
                        InternalMessage::Ping{token: _, mut data} => {
                            client.write_message(OpCode::Ping, &mut data);
                        },
                        InternalMessage::Pong{token: _, mut data} => {
                            client.write_message(OpCode::Pong, &mut data);
                        },
                        InternalMessage::NewClient{token: _} => unreachable!(),
                        InternalMessage::Shutdown => unreachable!(),
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

        // We may have just closed the connection
        if let Some(client) = self.clients.get_mut(&token) {
            let interest = client.interest();
            event_loop.reregister(&client.socket, token, interest,
                PollOpt::edge() | PollOpt::oneshot()).unwrap();
        }
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

#[test]
fn payload_info_test() {
    let mut buff: Vec<u8> = Vec::new();

    // small payload
    WebSocketClient::set_payload_info(10, &mut buff);
    assert!(buff.len() == 1);
    assert!(buff[0] == 10);

    // medium payload: 2500 == 00001001 11000100 == 9 196
    buff.clear();
    WebSocketClient::set_payload_info(2500, &mut buff);
    assert!(buff.len() == 3);
    assert!(buff[0] == 126);
    assert!(buff[1] == 9);
    assert!(buff[2] == 196);

    // large payload
    buff.clear();
    WebSocketClient::set_payload_info(2u64.pow(63) + 10, &mut buff);
    assert!(buff.len() == 9);
    assert!(buff[0] == 127);
    assert!(buff[1] == 128);
    for i in 2..8 {
        assert!(buff[i] == 0);
    }
    assert!(buff[8] == 10);
}

#[test]
fn writer_usability_test() {
    let (_, _, writer) = WebSocketServer::new("0.0.0.0", 9001);

    // is clonable?
    let clonable = writer.clone();

    // is thread movable?
    std::thread::spawn(move || {
        let _ = clonable.clone();
    });
}
