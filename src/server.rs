use crate::session::TlsSession;

use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
// use std::net::TcpStream;
// use std::io::{Read, Write};

pub struct TlsServer {
    tcp_listener: TcpListener,
}

impl TlsServer {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        Ok(Self {
            tcp_listener: TcpListener::bind(addr)?,
        })
    }
    pub fn accept(&self) -> std::io::Result<(TlsSession, SocketAddr)> {
        let (tcp_stream, addr) = self.tcp_listener.accept()?;
        let tls_session = TlsSession::server_from_tcp(tcp_stream);
        std::io::Result::Ok((tls_session, addr))
    }
}
