use tokio::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    trojan_rust::run_proxy("127.0.0.1",1080,"yourdomain",443,"yourpassword","yoursni").await?;
    Ok(())
}
