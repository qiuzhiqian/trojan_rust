use tokio::{io::{self, AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite}, net::TcpStream,net::TcpListener};
use std::net::{IpAddr,Ipv4Addr,Ipv6Addr,SocketAddr};

use crate::common::IpAddress;

#[derive(Debug)]
pub struct Request {
    pub version: u8,
    pub command: u8,
    pub rsv: u8,
    pub atype: u8,
    pub addr: IpAddress,
}
const VERSION: u8 = 5;
const AUTH_METHOD_NONE: u8 = 0x00;

#[derive(Debug)]
pub struct RequestAuth {
    _version: u8,
    _nm_method: u8,
    methods: Vec<u8>,
}

pub struct Socks5Acceptor {
    tcp_listener: TcpListener,
}

impl Socks5Acceptor {
    pub async fn new(addr: &str) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(Self { tcp_listener })
    }

    pub async fn accept(&self) -> io::Result<(TcpStream,IpAddress)> {
        let (mut stream, addr) = self.tcp_listener.accept().await?;
        log::info!("socks5 stream from address {}", addr);
        let request = Self::parser_auth(&mut stream).await?;
        if !request.methods.contains(&AUTH_METHOD_NONE) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("request contains invalid method:{}",AUTH_METHOD_NONE)));
        }

        Self::auth_ack(&mut stream).await?;
        let request = Self::parser_request(&mut stream).await?;
        Self::request_ack(&mut stream).await?;
        return Ok((stream,request.addr));
    }

    async fn parser_auth<T: AsyncRead + Unpin + Send>(rd: &mut T) -> io::Result<RequestAuth>{
        let version = rd.read_u8().await?;
        if version !=  VERSION{
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("version is not support:{}",version)));
        };
    
        let nm_method = rd.read_u8().await?;
    
        let mut methods = Vec::new();
        for _ in 0..nm_method {
            let method_index = rd.read_u8().await?;
            methods.push(method_index);
        }
    
        return Ok(RequestAuth{_version:version,_nm_method:nm_method,methods});
    }
    
    async fn auth_ack<T: AsyncWrite + Unpin + Send>(wd: &mut T) -> io::Result<()> {
        let buff = vec![VERSION,AUTH_METHOD_NONE];
        wd.write_all(buff.as_slice()).await?;
        wd.flush().await?;
        return io::Result::Ok(());
    }
    
    async fn parser_request<T: AsyncRead + Unpin + Send>(rd: &mut T) -> io::Result<Request>{
        let version = rd.read_u8().await?;
        if version !=  VERSION{
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("version is not support:{}",version)));
        };
    
        // Read command byte
        let command = rd.read_u8().await?;
    
        // Don't do anything about rsv
        let rsv = rd.read_u8().await?;
    
        // Read address type
        let atype = rd.read_u8().await?;
    
        // Get address size and address object
        let addr = match atype {
            0x01 => {
                let addr = rd.read_u32().await?;
                // Read port number
                let port = rd.read_u16().await?;
                IpAddress::IpAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)),port))
            },
            0x04 => {
                let addr = rd.read_u128().await?;
                // Read port number
                let port = rd.read_u16().await?;
                IpAddress::IpAddr(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)),port))
            }
            0x03 => {
                // Read address size
                let size = rd.read_u8().await? as usize;
                let mut buf = Vec::new();
    
                // Read address data
                for _ in 0..size {
                    let data = rd.read_u8().await?;
                    buf.push(data);
                }
                
                // Read port number
                let port = rd.read_u16().await?;
                IpAddress::Domain(String::from_utf8(buf).expect("this is not demain string"),port)
            }
            _other => {
                return Err(io::Error::new(io::ErrorKind::InvalidData,format!("atype({}) is not vaild",atype)));
            }
        };
    
        Ok(Request{version, command, rsv, atype, addr})
    }
    
    async fn request_ack<T: AsyncWrite + Unpin + Send>(wd: &mut T) -> io::Result<()> {
        wd.write_all(&[VERSION, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        wd.flush().await?;
    
        Ok(())
    }
}

