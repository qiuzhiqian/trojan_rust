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
        //Self::request_ack(&mut stream).await?;
        return Ok((stream,request.addr));
    }

    async fn parser_auth<T: AsyncRead + Unpin + Send>(rd: &mut T) -> io::Result<RequestAuth>{
        let version = rd.read_u8().await?;
        if version !=  VERSION{
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("version is not support:{}",version)));
        };
    
        let nm_method = rd.read_u8().await?;
        log::info!("nm_method: {}",nm_method);
    
        let mut methods = Vec::new();
        for _ in 0..nm_method {
            let method_index = rd.read_u8().await?;
            methods.push(method_index);
        }
        log::info!("methods: {:#?}",methods);
    
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
        log::info!("command: {}",command);
    
        // Don't do anything about rsv
        let rsv = rd.read_u8().await?;
        log::info!("rsv: {}",rsv);
    
        // Read address type
        let atype = rd.read_u8().await?;
        log::info!("atype: {}",atype);
    
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
        log::info!("addr: {}",addr);
    
        Ok(Request{version, command, rsv, atype, addr})
    }
    
    pub async fn request_ack<T: AsyncWrite + Unpin + Send>(wd: &mut T) -> io::Result<()> {
        wd.write_all(&[VERSION, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        wd.flush().await?;
    
        Ok(())
    }
}

pub struct Socks5Connector {
    server_addr: String,
}

impl Socks5Connector {
    pub fn new(ip:&str, port: u16) -> Self {
        Socks5Connector { 
            server_addr: format!("{}:{}",ip,port),//"127.0.0.1:1080"
        }
    }

    pub async fn connect(&self,addr:&str,port:u16) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(&self.server_addr).await?;
        Self::handshake(&mut stream).await?;
        Self::handshake_parse(&mut stream).await?;
        Self::request(&mut stream, addr,port).await?;
        Self::request_parse(&mut stream).await?;

        Ok(stream)
    }

    async fn handshake<T: AsyncWrite + Unpin + Send>(wd: &mut T) -> io::Result<()> {
        wd.write_all(&[VERSION, 1, 0]).await?;
        wd.flush().await?;
    
        Ok(())
    }

    async fn handshake_parse<T: AsyncRead + Unpin + Send>(rd: &mut T) -> io::Result<()> {
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
        Ok(())
    }

    async fn request<T: AsyncWrite + Unpin + Send>(wd: &mut T,domain:&str,port:u16) -> io::Result<()> {
        wd.write_all(&[VERSION, 1, 0]).await?;

        wd.write_u8(0x03).await?;
        wd.write_u8(domain.len() as u8).await?;
        wd.write_all(domain.as_bytes()).await?;
        wd.write_u16(port).await?;
        wd.flush().await?;
    
        Ok(())
    }

    async fn request_parse<T: AsyncRead + Unpin + Send>(rd: &mut T) -> io::Result<()> {
        let version = rd.read_u8().await?;
        if version !=  VERSION{
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("version is not support:{}",version)));
        };
    
        let rep = rd.read_u8().await?;
        println!("rep {}",rep);
    
        let rsv = rd.read_u8().await?;
        let atype = rd.read_u8().await?;
        
        //let size = rd.read_u8().await? as usize;
        //let mut buf = Vec::new();

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
        
        println!("[client] version: {},rep: {}, rsv: {}, atype: {}, addr: {}",version,rep,rsv,atype,addr);
    
        Ok(())
    }
}