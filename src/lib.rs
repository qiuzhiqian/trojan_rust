mod socks5;
mod trojan;
mod tls;
mod common;

use tokio::io;

pub struct Proxy {
    client_addr: String,
    client_port: u16,
    server_addr: String,
    server_port: u16,
    passwd: String,
    sni: String,
    running: bool,
}

impl Proxy {
    pub fn new(client_addr: &str,client_port: u16,server_addr:&str,server_port:u16,passwd: &str,sni: &str) ->Self {
        Self { 
            client_addr: client_addr.to_string(), 
            client_port, 
            server_addr: server_addr.to_string(), 
            server_port, 
            passwd: passwd.to_string(), 
            sni: sni.to_string(),
            running: true,
        }
    }

    pub async fn start(&self) -> io::Result<()> {
        env_logger::builder().filter_level(log::LevelFilter::Debug).try_init().expect("init log failed");
        log::info!("Trojan start...");
        let acceptor = socks5::Socks5Acceptor::new(&format!("{}:{}",self.client_addr,self.client_port)).await?;

        while self.running {
            let (stream,addr )= acceptor.accept().await?;
            log::info!("Received new connection from {}", addr);
            let tls_connector = tls::TrojanTlsConnector::new(self.sni.clone(), format!("{}:{}",self.server_addr,self.server_port))?;
            let mut connector = trojan::TrojanConnector::new(self.passwd.as_bytes(), tls_connector)?;

            tokio::spawn(async move {
                let trojan_stream = connector.connect(&addr).await.expect("connect faile.");
                trojan::relay_tcp(trojan_stream,stream).await;
            });
        }
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running = false;
    }
}

