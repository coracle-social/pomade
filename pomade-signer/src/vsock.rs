use std::io;

use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener as TokioVsockListener, VsockStream};

pub struct VsockListener(TokioVsockListener);

impl VsockListener {
    pub fn bind(port: u32) -> io::Result<Self> {
        Ok(Self(TokioVsockListener::bind(VsockAddr::new(
            VMADDR_CID_ANY,
            port,
        ))?))
    }
}

// VsockStream doesn't implement AsyncRead/AsyncWrite directly on the type,
// but does via DerefMut to the inner tokio type. We wrap it to satisfy axum's bounds.
pub struct VsockIo(VsockStream);

impl AsyncRead for VsockIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for VsockIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Unpin for VsockIo {}

impl Listener for VsockListener {
    type Io = VsockIo;
    type Addr = VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok((stream, addr)) => return (VsockIo(stream), addr),
                Err(e) => {
                    log::error!("[vsock]: accept error: {e}");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.0.local_addr()
    }
}
