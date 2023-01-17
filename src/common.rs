use std::net:: SocketAddr;

#[derive(Debug)]
pub enum IpAddress {
    IpAddr(SocketAddr),
    Domain(String,u16),
}

impl std::fmt::Display for IpAddress {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            IpAddress::IpAddr(ref addr) => write!(f, "{}", addr),
            IpAddress::Domain(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}