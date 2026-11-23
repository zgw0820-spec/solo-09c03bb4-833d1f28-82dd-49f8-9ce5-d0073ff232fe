"""Sample upstream DNS server (dnslib) used to exercise the DNS64 service.

It answers from a scripted table so every DNS64 code path can be triggered
with real UDP/TCP queries.  It listens on **both UDP and TCP** because the
DNS64 service retries truncated (TC=1) UDP answers over TCP.

======================  ==================================================  ==================================================
name                    AAAA query                                           A query
======================  ==================================================  ==================================================
native.example.         AAAA 2001:db8::53 (ttl 300)                          NODATA
gone.example.           NXDOMAIN                                             NXDOMAIN
web.example.            NODATA (neg-ttl 30)                                  A 192.0.2.10 (ttl 60)
alias.example.          CNAME web.example. (ttl 45) + NODATA (neg 30)        CNAME web.example. (ttl 45) + A 192.0.2.10
noaddr.example.         NODATA (neg-ttl 20)                                  NODATA (neg-ttl 20)
slow.example.           NODATA (neg-ttl 1)                                   A 192.0.2.20 (ttl 60) after 1.5s delay (any transport)
flap.example.           CNAME ep-a.example. + NODATA                         CNAME ep-b.example. + A 192.0.2.30
multi.example.          NODATA (neg-ttl 30)                                  A 192.0.2.41 (ttl 120) + A 192.0.2.42 (ttl 25)
drop.example.           no response (client times out)                       no response
tc-many.example.        NODATA (neg 30); UDP carries TC=1                    UDP: only A 192.0.2.41 + TC=1;
                        TCP: complete NODATA                                  TCP: A 192.0.2.41 + 192.0.2.42 + 192.0.2.43, no TC
tc-empty.example.       UDP: empty answer + TC=1 (no SOA);                   A 192.0.2.50 (ttl 60)
                        TCP: complete NODATA (neg 30)
tc-expire.example.      NODATA (neg-ttl 1); UDP carries TC=1, TCP delayed     A 192.0.2.60 (ttl 60)
                        1.5s -> negative TTL expired before basis complete
tcdrop.example.         UDP: empty answer + TC=1; TCP never accepts          A 192.0.2.70 (ttl 60) (TCP also unavailable)
======================  ==================================================  ==================================================

The truncating behaviours only apply to UDP; TCP always returns the full,
un-truncated answer (except ``tcdrop`` which refuses TCP altogether and
``tc-expire`` whose TCP answer is deliberately late).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from dnslib import QTYPE, RCODE, RR, A, AAAA, CNAME, SOA
from dnslib.server import BaseResolver, DNSServer

log = logging.getLogger("mock-upstream")

ZONE = "example."
SOA_SERIAL = 2026112301


def soa(neg_ttl: int) -> RR:
    """SOA whose TTL and MINIMUM both equal the wanted negative TTL."""
    return RR(
        ZONE,
        QTYPE.SOA,
        rdata=SOA(f"ns1.{ZONE}", f"hostmaster.{ZONE}",
                  (SOA_SERIAL, 7200, 3600, 1209600, neg_ttl)),
        ttl=neg_ttl,
    )


@dataclass
class Behaviour:
    """Scripted answer for one name."""

    aaaa_records: list = field(default_factory=list)   # RRs for the answer section
    a_records: list = field(default_factory=list)
    cname_for_aaaa: Optional[str] = None               # CNAME target, AAAA queries
    cname_for_a: Optional[str] = None                  # CNAME target, A queries
    cname_ttl: int = 45
    nxdomain: bool = False
    neg_ttl: int = 30                                  # negative TTL of NODATA replies
    delay: float = 0.0                                 # delay before answering A queries
    drop: bool = False                                 # never answer (client times out)
    # Truncation / TCP fallback scripting ----------------------------------
    truncate_udp_aaaa: bool = False                    # UDP AAAA: TC=1, empty answer
    truncate_udp_a: bool = False                       # UDP A: TC=1, only first A record
    tcp_delay: float = 0.0                             # extra delay for TCP answers
    tcp_refuse: bool = False                           # TCP listener rejects the name
    delay_aaaa_too: bool = False                       # ``delay`` also applies to AAAA


ZONE_FILE = {
    "native.example.": Behaviour(
        aaaa_records=[("2001:db8::53", 300)],
    ),
    "gone.example.": Behaviour(nxdomain=True, neg_ttl=60),
    "web.example.": Behaviour(
        a_records=[("192.0.2.10", 60)],
        neg_ttl=30,
    ),
    "alias.example.": Behaviour(
        cname_for_aaaa="web.example.",
        cname_for_a="web.example.",
        cname_ttl=45,
        a_records=[("192.0.2.10", 60)],
        neg_ttl=30,
    ),
    "noaddr.example.": Behaviour(neg_ttl=20),
    "slow.example.": Behaviour(
        a_records=[("192.0.2.20", 60)],
        neg_ttl=1,          # negative cache lifetime of the no-AAAA answer
        delay=1.5,          # ... but the A reply arrives 1.5s later -> expired
    ),
    "flap.example.": Behaviour(
        cname_for_aaaa="ep-a.example.",   # the two queries see different
        cname_for_a="ep-b.example.",      # alias endpoints -> SERVFAIL
        cname_ttl=40,
        a_records=[("192.0.2.30", 60)],
        neg_ttl=30,
    ),
    "multi.example.": Behaviour(
        a_records=[("192.0.2.41", 120), ("192.0.2.42", 25)],
        neg_ttl=30,
    ),
    "drop.example.": Behaviour(drop=True),

    # --- truncation / TCP-fallback scenarios -------------------------------
    "tc-many.example.": Behaviour(
        # AAAA NODATA itself arrives truncated on UDP; the A answer holds
        # three records but UDP returns just one with TC=1.  Only the TCP
        # retry exposes the complete set, so synthesis must produce 3 AAAA.
        a_records=[("192.0.2.41", 120), ("192.0.2.42", 120), ("192.0.2.43", 120)],
        neg_ttl=30,
        truncate_udp_aaaa=True,
        truncate_udp_a=True,
    ),
    "tc-empty.example.": Behaviour(
        # The truncated empty AAAA answer must not be treated as NODATA:
        # the server retries over TCP, gets the real NODATA, and only then
        # runs the A query and synthesizes.
        a_records=[("192.0.2.50", 60)],
        neg_ttl=30,
        truncate_udp_aaaa=True,
    ),
    "tc-expire.example.": Behaviour(
        # The UDP AAAA is truncated and the complete TCP answer only arrives
        # after 1.5s; with a 1s negative TTL the no-AAAA basis is already
        # stale once the A records are in -> SERVFAIL.
        a_records=[("192.0.2.60", 60)],
        neg_ttl=1,
        truncate_udp_aaaa=True,
        tcp_delay=1.5,
        delay_aaaa_too=True,
    ),
    "tcdrop.example.": Behaviour(
        # Truncated on UDP but the TCP retry cannot even establish a
        # connection -> no complete answer within the budget -> SERVFAIL.
        a_records=[("192.0.2.70", 60)],
        neg_ttl=30,
        truncate_udp_aaaa=True,
        tcp_refuse=True,
    ),
}


class ScriptedResolver(BaseResolver):
    def __init__(self, zone: dict):
        self.zone = zone

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower() + "."
        qtype = QTYPE[request.q.qtype]
        protocol = getattr(handler, "protocol", "udp")
        is_tcp = protocol == "tcp"
        behaviour = self.zone.get(qname)

        reply = request.reply()
        if behaviour is None:
            # Unknown name inside our zone: NXDOMAIN.
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_auth(soa(60))
            return reply
        if behaviour.tcp_refuse and is_tcp:
            # Simulate an upstream whose TCP service is not there: hold the
            # connection open without ever sending a reply so the client
            # budget expires (the socket connect itself succeeds).
            log.info("%s %s over TCP: configured to hang (tcp_refuse)", qname, qtype)
            time.sleep(30)
            return reply
        if behaviour.drop:
            log.info("%s %s: dropping (no response)", qname, qtype)
            time.sleep(10)  # longer than any client timeout
            return reply
        if behaviour.tcp_delay and is_tcp:
            log.info("%s %s over TCP: delaying answer by %.1fs",
                     qname, qtype, behaviour.tcp_delay)
            time.sleep(behaviour.tcp_delay)
        if behaviour.delay and qtype == "A" and not is_tcp:
            # The A reply arrives late (the AAAA reply is not delayed), so
            # the negative-caching window of the no-AAAA answer can expire
            # before the synthesis basis is complete.
            log.info("%s %s: delaying answer by %.1fs", qname, qtype, behaviour.delay)
            time.sleep(behaviour.delay)
        if behaviour.delay and behaviour.delay_aaaa_too and qtype == "AAAA" and not is_tcp:
            time.sleep(behaviour.delay)
        if behaviour.nxdomain:
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_auth(soa(behaviour.neg_ttl))
            return reply

        cname_target = behaviour.cname_for_aaaa if qtype == "AAAA" else behaviour.cname_for_a
        if cname_target:
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(cname_target),
                                ttl=behaviour.cname_ttl))
            owner = cname_target
        else:
            owner = qname

        records = behaviour.aaaa_records if qtype == "AAAA" else behaviour.a_records
        if qtype == "AAAA":
            truncated = behaviour.truncate_udp_aaaa and not is_tcp
            if truncated:
                # Truncated empty answer: TC=1 and no records at all.  This
                # must be retried rather than mistaken for a real NODATA.
                reply.header.tc = 1
                log.info("%s AAAA over UDP: sending truncated EMPTY answer (TC=1)", qname)
                return reply
            for addr, ttl in records:
                reply.add_answer(RR(owner, QTYPE.AAAA, rdata=AAAA(addr), ttl=ttl))
        elif qtype == "A":
            truncated = behaviour.truncate_udp_a and not is_tcp
            sent = records[:1] if truncated else records
            for addr, ttl in sent:
                reply.add_answer(RR(owner, QTYPE.A, rdata=A(addr), ttl=ttl))
            if truncated:
                reply.header.tc = 1
                log.info("%s A over UDP: sending truncated answer (%d/%d records, TC=1)",
                         qname, len(sent), len(records))
        else:
            truncated = False

        if not records:
            # NODATA: name exists, no record of this type -> SOA authority.
            reply.add_auth(soa(behaviour.neg_ttl))
        log.info("%s %s over %s: %d answer(s), rcode=%s, tc=%d",
                 qname, qtype, protocol, len(reply.rr),
                 RCODE[reply.header.rcode], reply.header.tc)
        return reply


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    resolver = ScriptedResolver(ZONE_FILE)
    host = os.environ.get("LISTEN_HOST", "0.0.0.0")
    port = int(os.environ.get("LISTEN_PORT", "5353"))

    # UDP and TCP share the same scripted resolver; the resolver branches on
    # handler.protocol so truncation only happens on UDP.  Both listeners run
    # in their own daemon threads because DNSServer.start() is blocking.
    udp_server = DNSServer(resolver, address=host, port=port, tcp=False)
    tcp_server = DNSServer(resolver, address=host, port=port, tcp=True)
    udp_server.start_thread()
    tcp_server.start_thread()
    log.info("mock upstream listening on UDP/TCP %s:%s", host, port)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        udp_server.stop()
        tcp_server.stop()


if __name__ == "__main__":
    main()
