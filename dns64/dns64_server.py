"""DNS64 server built on dnslib.

Receives UDP DNS queries (primarily AAAA) and synthesizes AAAA records from
A records using a configured /96 prefix, RFC 6147 style, with an extra
consistency check: the AAAA (NODATA) reply and the follow-up A reply must
agree on the same endpoint (final name after at most one CNAME hop).

Behaviour summary
-----------------
* Native AAAA answers and NXDOMAIN replies are returned to the client as-is.
* Only when the name exists but has no AAAA (NOERROR/NODATA) *and* the two
  upstream replies (the AAAA reply and the A reply) point to the same
  endpoint do we synthesize AAAA records from the A records + /96 prefix.
* One CNAME hop is supported; the synthesized answer keeps the CNAME (alias)
  record in the answer section.
* If the endpoints match but there is no A record either, the original
  no-data (NODATA) answer is returned unchanged.
* The synthesized TTL is the minimum of:
    - the negative-caching period of the no-AAAA answer
      (min(SOA TTL, SOA MINIMUM), RFC 2308),
    - the remaining TTL of the A record(s),
    - the remaining TTL of the CNAME actually used,
  where each remaining lifetime is counted from the moment its own upstream
  reply arrived.
* Upstream timeout, inconsistent endpoints, or an expired synthesis basis
  all produce SERVFAIL.

Truncation (TC) handling
------------------------
The expanded collector puts many A records behind one name, so an upstream
UDP reply may come back with the TC (truncation) bit set and only part of the
answer section.  Acting on such a reply would hand the collector a partial
set of synthesized addresses; a truncated *empty* AAAA answer would also
falsely trigger the follow-up A query.

Therefore every upstream query (AAAA, A, and the transparent proxy path)
works like this:

1. Send the query over UDP.
2. If the UDP reply has TC=1, re-ask the **same question to the same
   upstream over TCP** and use only the complete TCP reply.
3. The UDP attempt and the TCP retry share the single timeout budget of the
   original query.  A deadline is taken once; TCP reads of a segmented
   response re-use the *remaining* budget, so slow segment delivery can
   never extend the overall wait.
4. If the retry cannot deliver a complete, non-truncated answer in time (or
   the UDP attempt itself fails), the whole upstream exchange fails and the
   client gets SERVFAIL.

The collector-facing service stays UDP-only.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from dnslib import QTYPE, RCODE, RR, AAAA, DNSRecord
from dnslib.server import BaseResolver, DNSServer

log = logging.getLogger("dns64")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _norm(name) -> str:
    """Normalize a DNS name for comparison (lowercase, single trailing dot)."""
    return str(name).rstrip(".").lower() + "."


class UpstreamTimeout(Exception):
    """Raised when the upstream does not answer within the timeout budget."""


class UpstreamError(Exception):
    """Raised when an upstream transport exchange fails (other than timeout)."""


@dataclass
class UpstreamExchange:
    """An upstream reply plus the moment it arrived.

    Remaining TTLs of every record in the reply are counted from ``arrived``.
    For a UDP->TCP fallback this is the moment the complete TCP reply was
    received, i.e. the arrival of the (only) reply the synthesis relies on.
    """

    reply: DNSRecord
    arrived: float = field(default_factory=time.monotonic)

    def remaining(self, ttl: int, now: Optional[float] = None) -> float:
        now = time.monotonic() if now is None else now
        return ttl - (now - self.arrived)


def _family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _recv_udp(host: str, port: int, packet: bytes, deadline: float) -> bytes:
    """One UDP exchange. Must finish (reply in hand) before ``deadline``."""
    sock = socket.socket(_family(host), socket.SOCK_DGRAM)
    try:
        sock.settimeout(max(0.0, deadline - time.monotonic()))
        sock.sendto(packet, (host, port))
        while True:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise UpstreamTimeout(
                    f"upstream {host}:{port} UDP deadline reached before reply")
            sock.settimeout(timeout)
            try:
                data, sender = sock.recvfrom(8192)
            except socket.timeout as exc:
                raise UpstreamTimeout(
                    f"upstream {host}:{port} timed out within the query budget"
                ) from exc
            # The socket talks to a single upstream; accept its first reply.
            return data
    finally:
        sock.close()


def _recv_tcp(host: str, port: int, packet: bytes, deadline: float) -> bytes:
    """One TCP exchange reusing the remaining budget up to ``deadline``.

    The 2-octet length prefix and every segment are read against the same
    deadline, so a response that arrives in many segments can never extend
    the wait beyond the original query's budget.
    """
    family = _family(host)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            raise UpstreamTimeout(
                f"upstream {host}:{port} TCP: no budget left for the retry")
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except socket.timeout as exc:
            raise UpstreamTimeout(
                f"upstream {host}:{port} TCP connect exceeded the query budget"
            ) from exc
        except OSError as exc:
            raise UpstreamError(f"upstream {host}:{port} TCP connect failed: {exc}") from exc

        wire = struct.pack("!H", len(packet)) + packet

        def _wait_remaining() -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpstreamTimeout(
                    f"upstream {host}:{port} TCP deadline reached mid-message")
            sock.settimeout(remaining)
            return remaining

        # sendall may also block; keep it inside the same budget.
        _wait_remaining()
        try:
            sock.sendall(wire)
        except socket.timeout as exc:
            raise UpstreamTimeout(
                f"upstream {host}:{port} TCP send exceeded the query budget"
            ) from exc
        except OSError as exc:
            raise UpstreamError(f"upstream {host}:{port} TCP send failed: {exc}") from exc

        # Length prefix (exactly 2 bytes).
        header = b""
        while len(header) < 2:
            _wait_remaining()
            try:
                chunk = sock.recv(2 - len(header))
            except socket.timeout as exc:
                raise UpstreamTimeout(
                    f"upstream {host}:{port} TCP timed out reading length prefix"
                ) from exc
            except OSError as exc:
                raise UpstreamError(f"upstream {host}:{port} TCP read failed: {exc}") from exc
            if not chunk:
                raise UpstreamError(f"upstream {host}:{port} TCP closed before length prefix")
            header += chunk
        length = struct.unpack("!H", header)[0]

        # Full message, however many segments it arrives in.
        chunks: list[bytes] = []
        received = 0
        while received < length:
            _wait_remaining()
            try:
                chunk = sock.recv(min(8192, length - received))
            except socket.timeout as exc:
                raise UpstreamTimeout(
                    f"upstream {host}:{port} TCP timed out reading message "
                    f"({received}/{length} bytes)"
                ) from exc
            except OSError as exc:
                raise UpstreamError(f"upstream {host}:{port} TCP read failed: {exc}") from exc
            if not chunk:
                raise UpstreamError(
                    f"upstream {host}:{port} TCP closed after {received}/{length} bytes")
            chunks.append(chunk)
            received += len(chunk)
        return b"".join(chunks)
    finally:
        sock.close()


def query_upstream(name: str, qtype: str, host: str, port: int,
                   timeout: float) -> UpstreamExchange:
    """Resolve one question against the upstream with a shared timeout budget.

    UDP is tried first; a truncated (TC=1) UDP reply is retried over TCP to
    the same host/port with the *same* question, reusing whatever time of the
    original ``timeout`` budget remains.  Returns only a complete,
    non-truncated reply; otherwise raises :class:`UpstreamTimeout` or
    :class:`UpstreamError`.
    """
    question = DNSRecord.question(name, qtype)
    packet = question.pack()
    deadline = time.monotonic() + timeout

    try:
        raw = _recv_udp(host, port, packet, deadline)
    except UpstreamTimeout:
        raise
    except OSError as exc:  # e.g. ICMP port unreachable -> ECONNREFUSED
        raise UpstreamTimeout(f"upstream {host}:{port} unreachable: {exc}") from exc

    reply = DNSRecord.parse(raw)
    if not reply.header.tc:
        return UpstreamExchange(reply=reply)

    log.info(
        "upstream %s:%s UDP reply for %s %s has TC=1 (%d answer(s)); "
        "retrying over TCP with the remaining budget",
        host, port, name, qtype, len(reply.rr),
    )
    try:
        tcp_raw = _recv_tcp(host, port, packet, deadline)
    except UpstreamTimeout as exc:
        log.warning(
            "upstream %s:%s TCP retry for %s %s failed within the shared "
            "budget: %s", host, port, name, qtype, exc,
        )
        raise
    tcp_reply = DNSRecord.parse(tcp_raw)
    if tcp_reply.header.tc:
        # TCP messages are not supposed to be truncated; a set TC means we
        # still do not have the complete answer.
        raise UpstreamError(
            f"upstream {host}:{port} TCP reply for {name} {qtype} still has TC=1")
    log.info(
        "upstream %s:%s TCP retry for %s %s delivered %d answer(s)",
        host, port, name, qtype, len(tcp_reply.rr),
    )
    return UpstreamExchange(reply=tcp_reply)


# ---------------------------------------------------------------------------
# Reply inspection helpers
# ---------------------------------------------------------------------------


def _records(reply: DNSRecord, rtype: int):
    return [rr for rr in reply.rr if rr.rtype == rtype]


def extract_endpoint(reply: DNSRecord, qname: str) -> str:
    """Endpoint of a reply: the first CNAME target for qname, else qname.

    Only one CNAME hop is followed, per the supported feature set.
    """
    wanted = _norm(qname)
    for rr in _records(reply, QTYPE.CNAME):
        if _norm(rr.rname) == wanted:
            return _norm(rr.rdata.label)
    return wanted


def extract_negative_ttl(reply: DNSRecord) -> Optional[int]:
    """Negative-caching period (RFC 2308): min(SOA TTL, SOA MINIMUM).

    dnslib keeps the SOA numeric fields in ``rdata.times`` where index 4 is
    the MINIMUM field.
    """
    for rr in reply.auth:
        if rr.rtype == QTYPE.SOA:
            return min(int(rr.ttl), int(rr.rdata.times[4]))
    return None


def first_cname_for(reply: DNSRecord, qname: str) -> Optional[RR]:
    wanted = _norm(qname)
    for rr in _records(reply, QTYPE.CNAME):
        if _norm(rr.rname) == wanted:
            return rr
    return None


# ---------------------------------------------------------------------------
# The DNS64 resolver
# ---------------------------------------------------------------------------


class DNS64Resolver(BaseResolver):
    def __init__(self, upstream_host: str, upstream_port: int, prefix: str, timeout: float = 2.0):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        net = ipaddress.IPv6Network(prefix)
        if net.prefixlen != 96:
            raise ValueError("DNS64 prefix must be a /96")
        self.prefix = net
        self.timeout = timeout

    # -- main entry point called by dnslib's DNSServer ----------------------
    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        if qtype != "AAAA":
            # Transparent proxy for anything that is not an AAAA query.
            try:
                up = query_upstream(qname, qtype, self.upstream_host,
                                    self.upstream_port, self.timeout)
            except (UpstreamTimeout, UpstreamError) as exc:
                log.warning("%s %s: %s -> SERVFAIL", qtype, qname, exc)
                return self._servfail(request)
            return self._passthrough(request, up.reply)
        try:
            return self._resolve_aaaa(request, qname)
        except (UpstreamTimeout, UpstreamError) as exc:
            log.warning("AAAA %s: %s -> SERVFAIL", qname, exc)
            return self._servfail(request)

    # -- AAAA handling -------------------------------------------------------
    def _resolve_aaaa(self, request: DNSRecord, qname: str) -> DNSRecord:
        aaaa_up = query_upstream(qname, "AAAA", self.upstream_host,
                                 self.upstream_port, self.timeout)
        reply = aaaa_up.reply
        rcode = RCODE[reply.header.rcode]

        if rcode == "NXDOMAIN":
            log.info("AAAA %s: NXDOMAIN from upstream, passthrough", qname)
            return self._passthrough(request, reply)
        if rcode != "NOERROR":
            log.info("AAAA %s: upstream rcode=%s, passthrough", qname, rcode)
            return self._passthrough(request, reply)
        if _records(reply, QTYPE.AAAA):
            log.info("AAAA %s: native AAAA answer, passthrough", qname)
            return self._passthrough(request, reply)

        # NOERROR + no AAAA in the answer: the name exists but has no AAAA.
        # A truncated empty answer can never reach this point: query_upstream
        # would have retried it over TCP first.
        endpoint_aaaa = extract_endpoint(reply, qname)
        neg_ttl = extract_negative_ttl(reply)
        log.info(
            "AAAA %s: NODATA (endpoint=%s, negative-ttl=%s); querying A",
            qname, endpoint_aaaa, neg_ttl,
        )

        a_up = query_upstream(qname, "A", self.upstream_host,
                              self.upstream_port, self.timeout)
        a_reply = a_up.reply
        if RCODE[a_reply.header.rcode] != "NOERROR":
            # e.g. A is NXDOMAIN while AAAA was NODATA: endpoints cannot be
            # shown to be the same -> treat as inconsistent.
            log.warning("AAAA %s: A reply rcode=%s while AAAA was NODATA -> SERVFAIL",
                        qname, RCODE[a_reply.header.rcode])
            return self._servfail(request)

        endpoint_a = extract_endpoint(a_reply, qname)
        if endpoint_a != endpoint_aaaa:
            log.warning(
                "AAAA %s: endpoint mismatch (AAAA reply -> %s, A reply -> %s) -> SERVFAIL",
                qname, endpoint_aaaa, endpoint_a,
            )
            return self._servfail(request)

        a_records = [rr for rr in _records(a_reply, QTYPE.A)
                     if _norm(rr.rname) == endpoint_a]
        if not a_records:
            # Same endpoint but no A either: hand back the original
            # no-data answer untouched.
            log.info("AAAA %s: endpoints match (%s) but no A record; returning NODATA",
                     qname, endpoint_a)
            return self._passthrough(request, reply)

        return self._synthesize(request, qname, endpoint_a, aaaa_up, a_up, a_records, neg_ttl)

    # -- synthesis -----------------------------------------------------------
    def _synthesize(self, request, qname, endpoint, aaaa_up, a_up, a_records, neg_ttl) -> DNSRecord:
        now = time.monotonic()

        # Remaining lifetimes of everything the synthesis is based on.
        basis = {}
        if neg_ttl is not None:
            basis["negative-ttl"] = aaaa_up.remaining(neg_ttl, now)
        else:
            basis["negative-ttl"] = 0.0  # no SOA -> nothing we may cache
        basis["A"] = min(a_up.remaining(int(rr.ttl), now) for rr in a_records)

        cname_rr = first_cname_for(aaaa_up.reply, qname) or first_cname_for(a_up.reply, qname)
        cname_exchange = aaaa_up if first_cname_for(aaaa_up.reply, qname) else a_up
        if cname_rr is not None:
            basis["CNAME"] = cname_exchange.remaining(int(cname_rr.ttl), now)

        synth_ttl = int(min(basis.values()))
        if synth_ttl < 1:
            expired = {k: round(v, 3) for k, v in basis.items()}
            log.warning("AAAA %s: synthesis basis expired %s -> SERVFAIL", qname, expired)
            return self._servfail(request)

        out = request.reply()
        # Keep the alias: copy the CNAME with its remaining TTL.
        if cname_rr is not None:
            out.add_answer(RR(cname_rr.rname, QTYPE.CNAME,
                              rdata=cname_rr.rdata,
                              ttl=max(1, int(cname_exchange.remaining(int(cname_rr.ttl))))))
        for rr in a_records:
            v6 = self._map_address(str(rr.rdata))
            out.add_answer(RR(endpoint, QTYPE.AAAA, rdata=AAAA(v6), ttl=synth_ttl))
        log.info(
            "AAAA %s: synthesized %d record(s) via endpoint %s, ttl=%d (basis: %s)",
            qname, len(a_records), endpoint, synth_ttl,
            {k: round(v, 2) for k, v in basis.items()},
        )
        return out

    def _map_address(self, ipv4: str) -> str:
        v4 = ipaddress.IPv4Address(ipv4)
        return str(ipaddress.IPv6Address(int(self.prefix.network_address) | int(v4)))

    # -- response builders ---------------------------------------------------
    @staticmethod
    def _passthrough(request: DNSRecord, upstream_reply: DNSRecord) -> DNSRecord:
        upstream_reply.header.id = request.header.id
        return upstream_reply

    @staticmethod
    def _servfail(request: DNSRecord) -> DNSRecord:
        out = request.reply()
        out.header.rcode = RCODE.SERVFAIL
        return out


# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------


def make_server(resolver: DNS64Resolver, host: str, port: int) -> DNSServer:
    # UDP only on the client side: the collector keeps sending UDP AAAA
    # queries.  TCP is used only for upstream retries inside the resolver.
    return DNSServer(resolver, address=host, port=port, tcp=False)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    resolver = DNS64Resolver(
        upstream_host=os.environ.get("UPSTREAM_HOST", "127.0.0.1"),
        upstream_port=int(os.environ.get("UPSTREAM_PORT", "5353")),
        prefix=os.environ.get("DNS64_PREFIX", "64:ff9b::/96"),
        timeout=float(os.environ.get("UPSTREAM_TIMEOUT", "2.0")),
    )
    server = make_server(
        resolver,
        host=os.environ.get("LISTEN_HOST", "0.0.0.0"),
        port=int(os.environ.get("LISTEN_PORT", "5354")),
    )
    server.start()
    log.info("DNS64 listening on UDP %s:%s, upstream=%s:%s, prefix=%s",
             os.environ.get("LISTEN_HOST", "0.0.0.0"),
             os.environ.get("LISTEN_PORT", "5354"),
             resolver.upstream_host, resolver.upstream_port, resolver.prefix)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
