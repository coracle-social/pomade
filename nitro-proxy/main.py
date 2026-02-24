#!/usr/bin/env python3
"""
Nitro Enclave VSOCK proxy — runs on the EC2 parent instance.

Two proxy directions are handled:

  INBOUND  (--inbound-vsock-port / --inbound-tcp-port)
    External TCP clients  →  parent TCP listener  →  enclave VSOCK server
    Used so that the enclave's HTTP server (listening on VSOCK) is reachable
    from the internet via a normal TCP port on the parent instance.

  OUTBOUND (--outbound-vsock-port)
    Enclave VSOCK client  →  parent VSOCK listener  →  TCP destination
    The enclave connects to the parent on the outbound VSOCK port and speaks
    standard HTTP CONNECT. The proxy establishes the TCP connection and then
    pipes bytes in both directions. This lets reqwest inside the enclave use
    a normal HTTPS proxy without any custom protocol.

Usage:
    python3 main.py [options]

    Run with --help for the full option list.

Requirements:
    Python 3.8+, no third-party packages.
    The vsock kernel module must be loaded on the parent instance:
        modprobe vsock_loopback   # for local testing
        # vsock is available by default on Nitro-enabled EC2 instances

The enclave CID is always 4 (the fixed CID assigned to Nitro Enclaves by the
hypervisor). CID 3 is the parent instance.
"""

import argparse
import asyncio
import logging
import signal
import sys

log = logging.getLogger("nitro-proxy")

ENCLAVE_CID = 4  # fixed by the Nitro hypervisor


# ---------------------------------------------------------------------------
# Generic bidirectional pipe
# ---------------------------------------------------------------------------

async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def bridge(
    a_reader: asyncio.StreamReader,
    a_writer: asyncio.StreamWriter,
    b_reader: asyncio.StreamReader,
    b_writer: asyncio.StreamWriter,
) -> None:
    await asyncio.gather(
        _pipe(a_reader, b_writer),
        _pipe(b_reader, a_writer),
    )


# ---------------------------------------------------------------------------
# INBOUND: TCP client → VSOCK enclave server
# ---------------------------------------------------------------------------

async def _handle_inbound(
    tcp_reader: asyncio.StreamReader,
    tcp_writer: asyncio.StreamWriter,
    vsock_port: int,
) -> None:
    peer = tcp_writer.get_extra_info("peername")
    log.info("inbound connection from %s", peer)
    try:
        vsock_reader, vsock_writer = await asyncio.open_connection(
            host=None,
            port=vsock_port,
            sock=_vsock_socket(ENCLAVE_CID, vsock_port),
        )
        await bridge(tcp_reader, tcp_writer, vsock_reader, vsock_writer)
    except OSError as e:
        log.error("inbound: could not connect to enclave vsock port %d: %s", vsock_port, e)
    finally:
        tcp_writer.close()
    log.debug("inbound connection from %s closed", peer)


async def run_inbound_proxy(tcp_port: int, vsock_port: int) -> None:
    server = await asyncio.start_server(
        lambda r, w: _handle_inbound(r, w, vsock_port),
        host="0.0.0.0",
        port=tcp_port,
    )
    log.info("inbound proxy: TCP 0.0.0.0:%d → enclave VSOCK port %d", tcp_port, vsock_port)
    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------------------
# OUTBOUND: VSOCK enclave client → TCP destination via HTTP CONNECT
#
# The enclave speaks standard HTTP CONNECT:
#   CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n
# The proxy responds:
#   HTTP/1.1 200 Connection established\r\n\r\n
# Then both sides pipe raw bytes (TLS is handled end-to-end by the enclave).
# ---------------------------------------------------------------------------

async def _parse_connect_request(reader: asyncio.StreamReader):
    """Read and parse an HTTP CONNECT request line, return (host, port)."""
    request_line = await reader.readline()
    request_line = request_line.decode("latin-1").strip()
    # Consume remaining headers until blank line
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break

    # CONNECT host:port HTTP/1.1
    parts = request_line.split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        raise ValueError(f"expected CONNECT request, got: {request_line!r}")

    host_port = parts[1]
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        port = int(port_str)
    else:
        host = host_port
        port = 443

    return host, port


async def _handle_outbound(
    vsock_reader: asyncio.StreamReader,
    vsock_writer: asyncio.StreamWriter,
) -> None:
    try:
        host, port = await _parse_connect_request(vsock_reader)
    except Exception as e:
        log.error("outbound: bad CONNECT request: %s", e)
        vsock_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await vsock_writer.drain()
        vsock_writer.close()
        return

    log.info("outbound CONNECT to %s:%d", host, port)
    try:
        tcp_reader, tcp_writer = await asyncio.open_connection(host, port)
    except OSError as e:
        log.error("outbound: could not connect to %s:%d: %s", host, port, e)
        vsock_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await vsock_writer.drain()
        vsock_writer.close()
        return

    vsock_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await vsock_writer.drain()

    await bridge(vsock_reader, vsock_writer, tcp_reader, tcp_writer)
    log.debug("outbound connection to %s:%d closed", host, port)


async def run_outbound_proxy(vsock_port: int) -> None:
    server = await asyncio.start_server(
        _handle_outbound,
        host=None,
        port=vsock_port,
        sock=_vsock_server_socket(vsock_port),
    )
    log.info("outbound proxy: enclave VSOCK port %d → internet TCP via HTTP CONNECT", vsock_port)
    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------------------
# VSOCK socket helpers
# ---------------------------------------------------------------------------

def _vsock_socket(cid: int, port: int):
    """Return a connected VSOCK socket to the given CID:port."""
    import socket
    AF_VSOCK = socket.AF_VSOCK  # type: ignore[attr-defined]
    sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.connect_ex((cid, port))
    return sock


def _vsock_server_socket(port: int):
    """Return a bound, listening VSOCK server socket on VMADDR_CID_ANY."""
    import socket
    AF_VSOCK = socket.AF_VSOCK          # type: ignore[attr-defined]
    VMADDR_CID_ANY = 0xFFFFFFFF         # -1 as uint32
    sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((VMADDR_CID_ANY, port))
    sock.listen(128)
    sock.setblocking(False)
    return sock


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="VSOCK ↔ TCP proxy for Nitro Enclave parent instances",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--inbound-tcp-port", type=int, default=443,
                   help="TCP port on the parent to accept external HTTPS connections")
    p.add_argument("--inbound-vsock-port", type=int, default=3000,
                   help="VSOCK port the enclave's HTTP server listens on")
    p.add_argument("--outbound-vsock-port", type=int, default=3001,
                   help="VSOCK port the enclave connects to for outbound HTTP CONNECT proxy")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, loop.stop)

    await asyncio.gather(
        run_inbound_proxy(args.inbound_tcp_port, args.inbound_vsock_port),
        run_outbound_proxy(args.outbound_vsock_port),
    )


if __name__ == "__main__":
    asyncio.run(main())
