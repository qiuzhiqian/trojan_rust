# 简介
这是一个使用rust编写的单纯适用于client场景下的trojan库。为了简化配置，该库尽可能的采用最小化的配置参数。

# 使用
一个最小化使用的例子会如下面所示：
```
use tokio::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let proxy = trojan_rust::Proxy::new("127.0.0.1",1080,"yourdomain",443,"yourpassword","yoursni");
    proxy.start().await?;
    Ok(())
}
```

# 特性
- 服务器端使用tls连接
- 当前只支持TCP

# 协议参考
[trojan protocol](https://trojan-gfw.github.io/trojan/protocol)

[socks5 protocol](https://www.rfc-editor.org/rfc/rfc1928)