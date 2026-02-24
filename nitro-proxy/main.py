#!/usr/bin/env python3
"""
Nitro Enclave VSOCK proxy — runs on the EC2 parent instance.

Two proxy directions are handled:

  INBOUND  (--inbound-vsock-port / --inbound-tcp-port)
    External TCP clients  →  parent TCP listener  →  enclave VSOCK server
    Used so that the enclave's HTTP server (listening on VSOCK) is reachable
    from the internet via a normal TCP port on the parent instance.

  OUTBOUND (--outbound-vsock-port / --outbound-tcp-host / --outbound-tcp-port)
    Enclave VSOCK client  →  parent VSOCK listener  →  TCP destination
    Used so that the enclave can make outbound HTTPS calls (KMS, mailers)
    through the parent instance, which has internet access.
    The enclave connects to the parent on the outbound VSOCK port and sends a
    4-byte big-endian destination port number as a preamble, followed by the
    hostname as a length-prefixed UTF-8 string (1-byte length), followed by
    the raw TCP stream. This lets a single outbound port serve any destination.

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
import struct
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
# OUTBOUND: VSOCK enclave client → TCP destination
#
# Preamble sent by the enclave over the VSOCK connection:
#   [1 byte]  hostname length N
#   [N bytes] hostname (UTF-8)
#   [2 bytes] destination port (big-endian uint16)
# ---------------------------------------------------------------------------

async def _read_preamble(reader: asyncio.StreamReader):
    host_len_buf = await reader.readexactly(1)
    host_len = host_len_buf[0]
    host = (await reader.readexactly(host_len)).decode("utf-8")
    port_buf = await reader.readexactly(2)
    port = struct.unpack("!H", port_buf)[0]
    return host, port


async def _handle_outbound(
    vsock_reader: asyncio.StreamReader,
    vsock_writer: asyncio.StreamWriter,
) -> None:
    try:
        host, port = await _read_preamble(vsock_reader)
    except (asyncio.IncompleteReadError, UnicodeDecodeError) as e:
        log.error("outbound: bad preamble: %s", e)
        vsock_writer.close()
        return

    log.info("outbound connection to %s:%d", host, port)
    try:
        tcp_reader, tcp_writer = await asyncio.open_connection(host, port)
        await bridge(vsock_reader, vsock_writer, tcp_reader, tcp_writer)
    except OSError as e:
        log.error("outbound: could not connect to %s:%d: %s", host, port, e)
    finally:
        vsock_writer.close()
    log.debug("outbound connection to %s:%d closed", host, port)


async def run_outbound_proxy(vsock_port: int) -> None:
    server = await asyncio.start_server(
        _handle_outbound,
        host=None,
        port=vsock_port,
        sock=_vsock_server_socket(vsock_port),
    )
    log.info("outbound proxy: enclave VSOCK port %d → internet TCP", vsock_port)
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
                   help="VSOCK port the enclave connects to for outbound TCP")
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
