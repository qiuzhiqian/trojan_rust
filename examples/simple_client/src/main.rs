use tokio::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let proxy = trojan_rust::Proxy::new("127.0.0.1",1080,"yourdomain",443,"yourpassword","yoursni");
    proxy.start().await?;
    Ok(())
}
