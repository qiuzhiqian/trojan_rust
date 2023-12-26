use rustls::pki_types::ServerName;
use rustls::{ClientConfig,RootCertStore};
use tokio::{io, net::TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use std::sync::Arc;

pub struct TrojanTlsConnector {
    sni: String,
    server_addr: String,
    tls_config: Arc<ClientConfig>,
}

impl TrojanTlsConnector {
    pub fn new(sni:&str,server_addr: &str,server_port: u16) -> io::Result<Self> {
        let mut root_store = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
            root_store.add(cert).unwrap();
        }
        //root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(TrojanTlsConnector {
            sni: if sni.is_empty() {
                server_addr.to_string()
            } else {
                sni.to_string()
            },
            server_addr: format!("{}:{}",server_addr,server_port),
            tls_config: Arc::new(config),
        })
    }

    pub async fn connect_tcp(&self) -> io::Result<TlsStream<TcpStream>> {
        let connector = TlsConnector::from(self.tls_config.clone());
        let s = TcpStream::connect(&self.server_addr).await?;
        s.set_nodelay(true)?;
        let dns_name: ServerName = ServerName::try_from(self.sni.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?
            .to_owned();
        let stream = connector.connect(dns_name, s).await?;
        Ok(stream)
    }
}
