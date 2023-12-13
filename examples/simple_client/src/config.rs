use serde::{Serialize, Deserialize};
use std::io::Write;
use regex::Regex;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub remarks: String,
    pub server: String,
    pub server_port: u16,
    pub client: String,
    pub client_port: u16,
    pub sni: String,
    pub password: String,
    pub verify: bool,
}

impl Config {
    pub fn default() -> Self {
        Self{
            remarks: "test".to_string(),
            server: "192.168.1.100".to_string(),
            server_port: 443u16,
            client: "127.0.0.1".to_string(),
            client_port: 1080u16,
            sni: "example.com".to_string(),
            password: "123456".to_string(),
            verify: true,
        }
    }

    // trojan://password@domain:port?security=tls&type=tcp&headerType=none#remark
    pub fn from_url(url:&str) -> std::io::Result<Self> {
        // ([-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]):([0-9]*)/(.*)
        let re = Regex::new(r"^trojan://(?P<passwd>[^@]+)@(?P<domain>[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]*):(?P<port>[0-9]{1,5})#(?P<remarks>[-A-Za-z0-9+&@#/%=~_|.]+)$").map_err(|err|{
            std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
        })?;

        let caps = match re.captures(url){
            Some(cap) => cap,
            None => {return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "url is invalid"));},
        };

        let passwd = caps.name("passwd").unwrap().as_str().to_string();
        let domain = caps.name("domain").unwrap().as_str().to_string();
        let port_str = caps.name("port").unwrap().as_str().to_string();
        let remarks = caps.name("remarks").unwrap().as_str().to_string();
        println!("port:{}",port_str);

        let port = port_str.parse::<u16>().unwrap();//String to int

        Ok(Self{
            remarks,
            server: domain,
            server_port: port,
            client: "127.0.0.1".to_string(),
            client_port: 1080u16,
            sni: "".to_string(),
            password: passwd,
            verify: true,
        })
    }

    pub fn to_url(&self) -> String {
        format!("trojan://{}@{}:{}#{}",self.password,self.server,self.server_port,self.remarks)
    }

    pub fn from_file(file: &str) -> std::io::Result<Self> {
        let f = std::fs::File::open(file).unwrap();
        let values:Config = serde_json::from_reader(f)?;
        Ok(values)
    }

    pub fn to_file(&self, file: &str) -> std::io::Result<()> {
        let content = serde_json::to_string(self)?;
        let mut file = std::fs::File::create(file)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}