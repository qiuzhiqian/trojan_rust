mod socks5;
mod trojan;
mod tls;
mod common;

use tokio::io;

pub async fn run_proxy(client_addr: &str,client_port: u16,server_addr:&str,server_port:u16,passwd: &str,sni: &str) -> io::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Debug).try_init().expect("init log failed");
    log::info!("Trojan start...");
    let acceptor = socks5::Socks5Acceptor::new(&format!("{}:{}",client_addr,client_port)).await?;

    loop {
        let (stream,addr )= acceptor.accept().await?;
        log::info!("Received new connection from {}", addr);
        let tls_connector = tls::TrojanTlsConnector::new(sni.to_string(), format!("{}:{}",server_addr,server_port))?;
        let mut connector = trojan::TrojanConnector::new(passwd.as_bytes(), tls_connector)?;

        tokio::spawn(async move {
            let trojan_stream = connector.connect(&addr).await.expect("connect faile.");
            trojan::relay_tcp(trojan_stream,stream).await;
        });
    }
    Ok(())
}