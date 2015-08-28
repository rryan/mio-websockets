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
enum ClientState {
    AwaitingHandshake,
    HandshakeResponse,
    Open,
}

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
    outgoing_messages: std::collections::LinkedList<String>,
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

    fn write(&mut self) {
        let headers = self.headers.borrow();
        let response_key = gen_key(&headers.get("Sec-WebSocket-Key").unwrap());
        let response = fmt::format(format_args!("HTTP/1.1 101 Switching Protocols\r\n\
                                                 Connection: Upgrade\r\n\
                                                 Sec-WebSocket-Accept: {}\r\n\
                                                 Upgrade: websocket\r\n\r\n", response_key));
        self.socket.try_write(response.as_bytes()).unwrap();

        // Change the state
        self.state = ClientState::Open;

        self.interest.remove(EventSet::writable());
        self.interest.insert(EventSet::readable());
    }

    fn read(&mut self) {
        loop {
            let mut buf = [0; 2048];
            match self.socket.try_read(&mut buf) {
                Err(e) => {
                    println!("Error while reading socket: {:?}", e);
                    return
                },
                Ok(None) =>
                    // Socket buffer has got no more bytes.
                    break,
                Ok(Some(_len)) => {
                    self.http_parser.parse(&buf);
                    if self.http_parser.is_upgrade() {
                        // Change the current state
                        self.state = ClientState::HandshakeResponse;

                        // Change current interest to `Writable`
                        self.interest.remove(EventSet::readable());
                        self.interest.insert(EventSet::writable());
                        break;
                    }
                }
            }
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
        let v = vec![1];
        self.pipe_writer.write(&v).unwrap();

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
        let (p_reader, p_writer) = unix::pipe().unwrap();
        // i/o wrt to the event loop
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
        let (reregister_rtoken, reregister_wtoken) : (Option<Token>, Option<Token>);
        if events.is_readable() {
            println!("SERVER_TOKEN: {:?}", self.server_token);
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
                self.output_tx.send(InternalMessage::NewClient{client_token: new_token}).unwrap();
                reregister_rtoken = None;
            } else if token == self.pipe_token {
                let mut buff = Vec::new();
                let size = self.pipe_reader.read(&mut buff);
                println!("READ: {:?} {:?}", size, buff);
                println!("PIPE_TOKEN: {:?}", self.pipe_token);
                match self.input_rx.recv().unwrap() {
                    InternalMessage::CloseClient{client_token: _token} => {
                        // FIXME: implement
                        reregister_rtoken = None;
                    },
                    InternalMessage::Data{client_token: token, data, format: _} => {
                        let client = self.clients.get_mut(&token).unwrap();
                        client.outgoing_messages.push_back(data);
                        if client.state == ClientState::Open {
                            client.writing_substate = SubState::Doing;
                            reregister_rtoken = Some(token);
                        } else {
                            reregister_rtoken = None;
                        }
                    },
                    _ => {
                        reregister_rtoken = None;
                    },
                }
            } else {
                let mut client = self.clients.get_mut(&token).unwrap();
                client.read();
                reregister_rtoken = Some(token);
            }
        } else {
            reregister_rtoken = None;
        }

        if events.is_writable() {
            if token == self.server_token || token == self.pipe_token {
                reregister_wtoken = None;
            } else {
                let mut client = self.clients.get_mut(&token).unwrap();
                client.write();
                reregister_wtoken = Some(token);
            }
        } else {
            reregister_wtoken = None;
        }

        let vtoken = vec![&reregister_rtoken, &reregister_wtoken];
        for v in vtoken {
            match v.clone() {
                Some(token) => {
                    let client = self.clients.get(&token).unwrap();
                    let mut interest = EventSet::none();
                    match client.state {
                        ClientState::AwaitingHandshake => unreachable!(),
                        ClientState::HandshakeResponse => interest.insert(EventSet::writable()),
                        ClientState::Open => {
                            interest.insert(EventSet::readable());
                            match client.reading_substate {
                                SubState::Waiting => {},
                                SubState::Doing   => {},
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
}

fn main() {
    let (mut server, mut reader, mut writer) = WebSocketServer::new("0.0.0.0", 10000);

    // Receiver Process
    thread::spawn(move || {
        loop {
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
        }
    });

    // Sender Process
    thread::spawn(move || {
        loop {
            loop {}
            let msg = InternalMessage::Data{client_token: Token(2),
                format: String::from("Aaron"),
                data:   String::from("Burrow"),
            };
            writer.write(msg);
        }
    });

    server.start();
}
