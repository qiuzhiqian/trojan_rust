mod socks5;
mod trojan;
mod tls;
mod common;

use tokio::{sync::mpsc::Receiver, io::{AsyncReadExt, AsyncWriteExt}};

#[derive(Debug)]
pub struct Proxy {
    client_addr: String,
    client_port: u16,
    server_addr: String,
    server_port: u16,
    passwd: String,
    sni: String,
}

impl Proxy {
    pub fn new(client_addr: &str,client_port: u16,server_addr:&str,server_port:u16,passwd: &str,sni: &str) ->Self {
        if let Err(_) = env_logger::builder().filter_level(log::LevelFilter::Debug).try_init(){
            log::info!("log has init.");
        }

        Self { 
            client_addr: client_addr.to_string(), 
            client_port, 
            server_addr: server_addr.to_string(), 
            server_port, 
            passwd: passwd.to_string(), 
            sni: sni.to_string(),
        }
    }

    pub async fn start(&self,recv: &mut Receiver<bool>) -> tokio::io::Result<()> {
        log::info!("Trojan start...");
        let addr = format!("{}:{}",self.client_addr,self.client_port);

        let acceptor = socks5::Socks5Acceptor::new(&addr).await?;
        loop {
            log::info!("do accept");
            tokio::select! {
                Ok((mut stream,addr))  = acceptor.accept() => {
                    log::info!("Received new connection from {}", addr);
                    let tls_connector = tls::TrojanTlsConnector::new(&self.sni, &self.server_addr,self.server_port)?;
                    let mut connector = trojan::TrojanConnector::new(self.passwd.as_bytes(), tls_connector)?;
                    let trojan_stream = connector.connect(&addr).await.expect("connect failed.");
                    socks5::Socks5Acceptor::request_ack(&mut stream).await?;
                    log::info!("socks5 connect success");
                    tokio::spawn(async move {
                        trojan::relay_tcp(trojan_stream,stream).await;
                    });
                },
                _ = recv.recv() => {
                    log::info!("receive stop signal.");
                    return Ok(());
                }
            }
        }
    }
}

pub async fn client_start(addr:&str,port:u16,proxy_ip:&str, proxy_port: u16) -> tokio::io::Result<()> {
    let connector = socks5::Socks5Connector::new(proxy_ip,proxy_port);
    let mut stream = connector.connect(addr,port).await.unwrap();
    //let mut stream = tokio::net::TcpStream::connect("110.242.68.3:80").await?;
    stream.set_nodelay(true)?;
    println!("get stream");
    let content = vec![
        "GET / HTTP/1.1",
        "Host: www.google.com",
        "User-Agent: curl/7.64.0",
        "Accept: */*",
    ];
    for i in content {
        stream.write_all(i.to_string().as_bytes()).await?;
        stream.write_u16(0x0D0A).await?;
    }
    stream.write_u16(0x0D0A).await?;
    println!("send end");
    // GET http://www.google.com/ HTTP/1.1
    // Accept: */*
    // User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
    let mut frame = String::new();
    //let mut has_response = false;
    loop {
        let mut buf = Vec::new();
        let len = stream.read_buf(&mut buf).await?;
        if len == 0 {
            println!("[client] read end...");
            break;
        }
        println!("len={}",len);
        //frame.append(&mut buf);
        frame = frame + &String::from_utf8(buf).unwrap();
        println!("frame:{}",frame);

        let lines:Vec<&str> = frame.split("\r\n").collect();
        if !lines.is_empty() && lines[0].contains("OK") {
            println!("response ok");
            break;
        }
    }
    //println!("[client] frame[{}]: {}",frame.clone().len(), String::from_utf8(frame).unwrap());
    Ok(())
}

