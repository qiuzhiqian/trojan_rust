mod socks5;
mod trojan;
mod tls;
mod common;

use tokio::sync::mpsc;

use tokio::runtime::Runtime;
use tokio::sync::mpsc::{channel, Sender};

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

    pub fn start(&self) -> Option<mpsc::Sender<bool>> {
        log::info!("Trojan start...");
        let addr = format!("{}:{}",self.client_addr,self.client_port);

        let (send, mut recv) = channel::<bool>(1);

        let server_addr = self.server_addr.clone();
        let server_port = self.server_port;
        let sni = self.sni.clone();
        let passwd = self.passwd.clone();
        std::thread::spawn(move ||{
            let runtime = Runtime::new().unwrap();
            runtime.block_on(async {
                let acceptor = socks5::Socks5Acceptor::new(&addr).await.expect("xxx");
                loop {
                    log::info!("do accept");
                    tokio::select! {
                        Ok((stream,addr))  = acceptor.accept() => {
                            log::info!("Received new connection from {}", addr);
                            let tls_connector = match tls::TrojanTlsConnector::new(sni.clone(), format!("{}:{}",server_addr,server_port)) {
                                Ok(tls_connector) => tls_connector,
                                Err(_) => {return;},
                            };
                            let mut connector = match trojan::TrojanConnector::new(passwd.as_bytes(), tls_connector) {
                                Ok(connector) => connector,
                                Err(_) => {return;},
                            };
                
                            tokio::spawn(async move {
                                let trojan_stream = connector.connect(&addr).await.expect("connect faile.");
                                trojan::relay_tcp(trojan_stream,stream).await;
                            });
                        },
                        _ = recv.recv() => {log::info!("has receive."); return;}
                    }
                }
            });
        });
        
        log::info!("start end with send.");
        return Some(send);
    }

    pub fn stop(&self,send:&Sender<bool>) {
        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            send.send(true).await.expect("send failed");
            log::info!("send end...");
        });
    }
}

