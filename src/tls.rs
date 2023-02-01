use rustls::client::ServerName;
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
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let config = ClientConfig::builder()
            .with_safe_defaults()
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
        let stream = TcpStream::connect(&self.server_addr).await?;
        stream.set_nodelay(true)?;

        let dns_name = ServerName::try_from(self.sni.as_ref()).expect("Failed to parse host name");
        let stream = TlsConnector::from(self.tls_config.clone())
            .connect(dns_name, stream)
            .await?;

        Ok(stream)
    }
}
