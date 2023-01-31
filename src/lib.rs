mod socks5;
mod trojan;
mod tls;
mod common;

use tokio::sync::mpsc::Receiver;

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
                Ok((stream,addr))  = acceptor.accept() => {
                    log::info!("Received new connection from {}", addr);
                    let tls_connector = tls::TrojanTlsConnector::new(self.sni.clone(), format!("{}:{}",self.server_addr,self.server_port))?;
                    let mut connector = trojan::TrojanConnector::new(self.passwd.as_bytes(), tls_connector)?;
        
                    tokio::spawn(async move {
                        let trojan_stream = connector.connect(&addr).await.expect("connect faile.");
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

