/// Outbound HTTP CONNECT proxy bridge for Nitro Enclaves.
///
/// The enclave has no direct network access. All outbound HTTPS traffic must
/// go through the parent instance via VSOCK. The parent proxy speaks HTTP
/// CONNECT on a VSOCK port.
///
/// reqwest cannot connect over VSOCK natively, so we run a tiny loopback
/// bridge inside the enclave: a TCP listener on 127.0.0.1 that forwards each
/// connection to the parent's VSOCK proxy port. reqwest is then configured
/// with a normal `Proxy::all("http://127.0.0.1:<bridge_port>")`.
///
/// `spawn_bridge(vsock_port)` starts the bridge task and returns the local
/// TCP port it bound to. `vsock_client(bridge_port)` builds the reqwest
/// client pointed at that port.
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio_vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

// CID 3 is the parent instance ("host") as seen from inside the enclave.
const PARENT_CID: u32 = VMADDR_CID_HOST;

async fn pipe(mut reader: impl io::AsyncRead + Unpin, mut writer: impl io::AsyncWrite + Unpin) {
    let _ = io::copy(&mut reader, &mut writer).await;
}

async fn handle(tcp: TcpStream, vsock_port: u32) {
    let vsock = match VsockStream::connect(VsockAddr::new(PARENT_CID, vsock_port)).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("[vsock-bridge] connect to parent port {vsock_port} failed: {e}");
            return;
        }
    };

    let (tcp_r, tcp_w) = tcp.into_split();
    let (vsock_r, vsock_w) = vsock.into_split();

    tokio::join!(pipe(tcp_r, vsock_w), pipe(vsock_r, tcp_w));
}

/// Spawn the loopback TCP→VSOCK bridge and return the local port it bound to.
///
/// The bridge listens on an OS-assigned port on 127.0.0.1 and forwards each
/// connection to `vsock_port` on the parent instance.
pub async fn spawn_bridge(vsock_port: u32) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind vsock bridge");
    let local_port = listener.local_addr().expect("no local addr").port();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp, _)) => {
                    tokio::spawn(handle(tcp, vsock_port));
                }
                Err(e) => {
                    log::error!("[vsock-bridge] accept error: {e}");
                }
            }
        }
    });

    log::info!("[vsock-bridge] 127.0.0.1:{local_port} → VSOCK parent port {vsock_port}");
    local_port
}

/// Build a `reqwest::Client` that routes all connections through the loopback
/// bridge, which forwards them to the parent's outbound VSOCK proxy.
pub fn vsock_client(bridge_port: u16) -> reqwest::Client {
    let proxy_url = format!("http://127.0.0.1:{bridge_port}");
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).expect("invalid proxy URL"))
        .build()
        .expect("failed to build vsock reqwest client")
}
