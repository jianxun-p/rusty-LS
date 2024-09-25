use rusty_ls::server::TlsServer;
// use rusty_ls::session::TlsSession;

use std::io::Read;
use std::thread::sleep;

const SOCKET_ADDR: &str = "127.0.0.1:12120";

pub fn main() {
    println!("https://{}", SOCKET_ADDR);

    let server = TlsServer::bind(SOCKET_ADDR).unwrap();
    let (mut client, client_addr) = server.accept().unwrap();
    println!("Accepted client from: {}", client_addr);

    let mut buf = [0; 0x10000];
    match client.read(&mut buf) {
        Ok(n) => println!("Successfully read {} bytes", n),
        Err(err) => panic!("Error: {}", err.to_string()),
    };
    let _ = client.read(&mut buf);
    let _ = client.read(&mut buf);
    sleep(std::time::Duration::from_secs(2));
}
