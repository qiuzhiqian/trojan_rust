use crate::common::IpAddress;
use sha2::{Digest, Sha224};
use bytes::Buf;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use std::net::SocketAddr;

use crate::tls::TrojanTlsConnector;

const CRLF: u16 = 0x0D0A;
const HASH_STR_LEN: usize = 56;

pub struct TrojanConnector {
    inner: TrojanTlsConnector,
    hash: [u8; HASH_STR_LEN],
}

enum TROJAN_CMD {
    CONNECT = 0x01,
    UDP = 0x03,
}

impl TrojanConnector {
    pub fn new(passwd: &[u8], inner: TrojanTlsConnector) -> io::Result<Self> {
        let hash_string= Sha224::digest(passwd)
                    .iter()
                    .map(|x| format!("{:02x}", x))
                    .collect::<String>();
        if hash_string.len() != HASH_STR_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("password data is invalid")));
        }

        let mut hash = [0u8; HASH_STR_LEN];
        hash_string.as_bytes().copy_to_slice(&mut hash);
        Ok(Self { inner, hash})
    }
    pub async fn connect(&mut self,addr:&IpAddress) -> io::Result<TlsStream<tokio::net::TcpStream>> {
        let mut stream = self.inner.connect_tcp().await?;
        handshake(&mut stream,self.hash[..].as_mut(),TROJAN_CMD::CONNECT,addr).await?;
        Ok(stream)
    }
}

async fn handshake<T: AsyncWrite + Unpin>(
    stream: &mut T,
    passwd: &[u8],
    command: TROJAN_CMD,
    addr: &IpAddress,
) -> io::Result<()> {
    // Write request header
    stream.write_all(passwd).await?;
    stream.write_u16(CRLF).await?;
    stream.write_u8(command as u8).await?;
    match addr {
        IpAddress::IpAddr(SocketAddr::V4(ipv4)) => {
            stream.write_u8(0x01).await?;
            stream.write_all(&ipv4.ip().octets()).await?;
            stream.write_u16(ipv4.port()).await?;
        }
        IpAddress::IpAddr(SocketAddr::V6(ipv6)) => {
            stream.write_u8(0x04).await?;
            stream.write_all(&ipv6.ip().octets()).await?;
            stream.write_u16(ipv6.port()).await?;
        }
        IpAddress::Domain(domain,port) => {
            stream.write_u8(0x03).await?;
            stream.write_u8(domain.len() as u8).await?;
            stream.write_all(domain.as_bytes()).await?;
            stream.write_u16(*port).await?;
        }
    }
    stream.write_u16(CRLF).await?;

    stream.flush().await?;

    Ok(())
}

pub async fn relay_tcp<T: AsyncRead + AsyncWrite + Unpin + Send,U:AsyncRead + AsyncWrite + Unpin + Send>(a: T, b: U) {
    let (mut a_rx, mut a_tx) = tokio::io::split(a);
    let (mut b_rx, mut b_tx) = tokio::io::split(b);
    let t1 = copy_tcp(&mut a_rx, &mut b_tx, "receive");
    let t2 = copy_tcp(&mut b_rx, &mut a_tx,"send");
    let e = tokio::select! {
        e = t1 => {e}
        e = t2 => {e}
    };
    if let Err(e) = e {
        log::debug!("relay_tcp err: {}", e)
    }
    let mut a = a_rx.unsplit(a_tx);
    let mut b = b_rx.unsplit(b_tx);
    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
    log::info!("relay_tcp end");
}

async fn copy_tcp<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    tag: &str,
) -> io::Result<()> {
    let mut buf = [0u8; 16384];
    loop {
        let len = r.read(&mut buf).await?;
        if len == 0 {
            break;
        }
        log::info!("[{}] raw buff: ",tag);
        //for i in &buf[..len] {
        //    print!("{:#X} ",i);
        //}
        //println!("");
        
        w.write(&buf[..len]).await?;
        w.flush().await?;
    }
    Ok(())
}