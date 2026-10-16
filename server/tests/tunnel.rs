//! End-to-end tunnel test over real UDP loopback sockets: full PQANON-HS/1
//! handshake over the OBF/2 boot layer (every message split into sealed
//! 1200-byte datagrams), then a morphed DATA packet echoed back.
//!
//! ML-DSA-65 key generation and signing use large stack frames, so this test
//! runs on a dedicated thread with a generous stack (the default 2 MB test-
//! harness thread stack is too small for both handshake sides concurrently).

use pqanon::handshake::{ClientHandshake, Identity, ServerHandshake};
use pqanon::client::CLIENT_HELLO_DATAGRAMS;
use pqanon::obf::{BootKey, Obfuscator, Reassembly, BOOT_DATAGRAM};
use pqanon::transport::Session;
use pqanon::wire::{Envelope, MsgType};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

async fn send_msg(sock: &UdpSocket, boot: &BootKey, env: &Envelope, min: usize, to: SocketAddr) {
    for d in boot.seal_message(&env.to_plain(), min).unwrap() {
        assert_eq!(d.len(), BOOT_DATAGRAM);
        assert!(!d.windows(4).any(|w| w == b"PQAN"), "magic on the wire");
        sock.send_to(&d, to).await.unwrap();
    }
}

async fn recv_msg(sock: &UdpSocket, boot: &BootKey) -> (Envelope, SocketAddr) {
    let mut buf = vec![0u8; 65536];
    let mut r = Reassembly::new();
    loop {
        let (n, from) = sock.recv_from(&mut buf).await.unwrap();
        if let Some(msg) = r.push(boot.open(&buf[..n]).expect("a boot datagram")) {
            return (Envelope::from_plain(&msg).unwrap(), from);
        }
    }
}

#[test]
fn tunnel_handshake_and_data_over_udp() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run() {
    let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();
    let client_addr = client_sock.local_addr().unwrap();

    let server_id = Identity::generate();
    let client_id = Identity::generate();
    let server_pub = server_id.public();
    let authorized = vec![client_id.identity_id()];
    let boot = BootKey::for_server(&server_pub);
    let server_boot = BootKey::for_server(&server_id.public());

    let server = async move {
        let mut buf = vec![0u8; 65536];
        let boot = server_boot;

        // 1. CLIENT_HELLO.
        let (hello, caddr) = recv_msg(&server_sock, &boot).await;
        let mut hs = ServerHandshake::new(server_id, authorized, hello.conn_id);
        hs.recv_client_hello(&hello, true).unwrap();

        // 2. SERVER_HELLO.
        let shello = hs.server_hello().unwrap();
        send_msg(&server_sock, &boot, &shello, 1, caddr).await;

        // 3. CLIENT_FINISH.
        let (finish, _) = recv_msg(&server_sock, &boot).await;
        let est = hs.recv_client_finish(&finish).unwrap();

        // 4. One morphed DATA packet, echoed back morphed.
        let mut session = Session::new(est.conn_id, est.k_c2s, est.k_s2c, caddr, false, 1400);
        let obf = Obfuscator::new(&est.ss_mix, 1);
        let (n, _) = server_sock.recv_from(&mut buf).await.unwrap();
        let sealed = obf.demorph(&buf[..n]).unwrap();
        let env = session.open_data(&sealed).unwrap();
        assert_eq!(env.msg_type, MsgType::Data);
        let reply = session.seal_data(MsgType::Data, env.payload).unwrap();
        server_sock
            .send_to(&obf.morph(&reply).unwrap(), caddr)
            .await
            .unwrap();
    };

    let client = async move {
        let hs_conn_id: u64 = rand::random();
        let mut client = ClientHandshake::new(client_id, server_pub, hs_conn_id);

        let hello = client.client_hello([0u8; 32]).unwrap();
        send_msg(&client_sock, &boot, &hello, CLIENT_HELLO_DATAGRAMS, server_addr).await;

        let mut buf = vec![0u8; 65536];
        let (shello, _) = recv_msg(&client_sock, &boot).await;
        client.recv_server_hello(&shello).unwrap();

        let (finish, est) = client.client_finish().unwrap();
        send_msg(&client_sock, &boot, &finish, 1, server_addr).await;

        let mut session = Session::new(est.conn_id, est.k_c2s, est.k_s2c, server_addr, true, 1400);
        let obf = Obfuscator::new(&est.ss_mix, 1);
        let sealed = session
            .seal_data(MsgType::Data, b"tunnel payload".to_vec())
            .unwrap();
        client_sock
            .send_to(&obf.morph(&sealed).unwrap(), server_addr)
            .await
            .unwrap();

        let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
        let recovered = obf.demorph(&buf[..n]).unwrap();
        let echo = session.open_data(&recovered).unwrap();
        assert_eq!(echo.payload, b"tunnel payload");
    };

    let _ = client_addr;
    tokio::join!(server, client);
}
