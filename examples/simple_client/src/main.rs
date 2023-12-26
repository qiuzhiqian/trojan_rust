//use tokio::io;
//use tokio::io::AsyncBufReadExt;

use std::path::PathBuf;
use clap::Parser;
use std::io::BufRead;

mod config;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// set a client address:port
    #[arg(long)]
    client: Option<String>,

    /// set a client address:port
    #[arg(long)]
    server: Option<String>,

    /// set a server password
    #[arg(long)]
    password: Option<String>,

    /// set a server sni
    #[arg(long)]
    sni: Option<String>,

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE", conflicts_with_all = ["client", "server", "password", "sni"])]
    config: Option<PathBuf>,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
}

fn main() {
    if let Err(_) = env_logger::builder().filter_level(log::LevelFilter::Info).try_init(){
        log::info!("log has init.");
    }
    let cli = Cli::parse();

    let (client, client_port, server, server_port, password, sni) = match cli.config.as_deref() {
        Some(config_path) => {
            let path_str = config_path.to_str().expect("file is not exist");
            log::info!("config path: {}", path_str);
            let c = config::Config::from_file(path_str).expect("file format is error");
            (c.client, c.client_port, c.server, c.server_port, c.password, c.sni)
        },
        None => {
            let client = cli.client.as_deref().unwrap();
            let (client_addr, client_port) = match client.find(":") {
                Some(index) => {
                    if index > 0 && (index < client.len() - 1) {
                        let addr = client.get(..index).expect("format error");
                        let port = client.get(index+1..).expect("format error").parse::<u16>().unwrap();
                        (addr.to_string(), port)
                    } else {
                        ("".to_string(), 1080)
                    }
                }
                None =>  ("".to_string(), 1080)
            };

            let server = cli.server.as_deref().unwrap();
            let (server_addr, server_port) = match server.find(":") {
                Some(index) => {
                    if index > 0 && (index < server.len() - 1) {
                        let addr = server.get(..index).expect("format error");
                        let port = server.get(index+1..).expect("format error").parse::<u16>().unwrap();
                        (addr.to_string(), port)
                    } else {
                        ("".to_string(), 1080)
                    }
                }
                None =>  ("".to_string(), 1080)
            };
            //let client_index = client.find(":").expect("format error");
            let password = cli.password.as_deref().unwrap();
            let sni = cli.sni.as_deref().unwrap();
            (client_addr.to_string(), client_port, server_addr.to_string(), server_port, password.to_string(), sni.to_string())
        },
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let proxy = trojan_rust::Proxy::new(&client,
            client_port,
            &server,
            server_port,
            &password,
            &sni);
    rt.spawn(async move{
        proxy.start(&mut rx).await;
    });

    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    match cli.debug {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        2 => println!("Debug mode is on"),
        _ => println!("Don't be crazy"),
    }
    
    let mut input_reader = std::io::BufReader::new(std::io::stdin());
    //stdin.read_line(&mut buffer)?;
    let mut lines = input_reader.lines();
    while let Some(l) = lines.next() {
        if let Ok(line) = l {
            println!("length = {}", line.len());
            if &line == "exit" || &line == "quit" {
                //tx.send(true).await;
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    tx.send(true).await;
                });
                break;
            }
        };
    }
}
