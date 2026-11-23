"""End-to-end tests: real UDP queries through the DNS64 server backed by the
scripted sample upstream.

The sample upstream listens on both UDP and TCP because the DNS64 service
retries truncated (TC=1) UDP answers over TCP.  The collector-facing DNS64
service itself stays UDP-only.
"""

import socket

import pytest
from dnslib import QTYPE, RCODE, DNSRecord
from dnslib.server import DNSServer

from dns64_server import DNS64Resolver
from mock_upstream import ScriptedResolver, ZONE_FILE


@pytest.fixture(scope="module")
def servers():
    # Pick a free UDP port, then bind the TCP listener to the same number
    # (SO_REUSEADDR allows the two sockets to coexist).
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    upstream_port = probe.getsockname()[1]
    probe.close()

    upstream_udp = DNSServer(ScriptedResolver(ZONE_FILE),
                             address="127.0.0.1", port=upstream_port, tcp=False)
    upstream_tcp = DNSServer(ScriptedResolver(ZONE_FILE),
                             address="127.0.0.1", port=upstream_port, tcp=True)
    upstream_udp.start_thread()
    upstream_tcp.start_thread()

    resolver = DNS64Resolver("127.0.0.1", upstream_port, "64:ff9b::/96", timeout=2.0)
    dns64 = DNSServer(resolver, address="127.0.0.1", port=0, tcp=False)
    dns64.start_thread()
    dns64_port = dns64.server.server_address[1]

    yield dns64_port

    dns64.stop()
    upstream_udp.stop()
    upstream_tcp.stop()


def ask(port, name, qtype="AAAA", timeout=5.0):
    q = DNSRecord.question(name, qtype)
    try:
        raw = q.send("127.0.0.1", port, tcp=False, timeout=timeout)
    except (socket.timeout, TimeoutError):
        return None
    return DNSRecord.parse(raw)


def test_native_aaaa_passthrough(servers):
    reply = ask(servers, "native.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa) == 1
    assert str(aaaa[0].rdata) == "2001:db8::53"
    assert aaaa[0].ttl == 300


def test_nxdomain_passthrough(servers):
    reply = ask(servers, "gone.example.")
    assert RCODE[reply.header.rcode] == "NXDOMAIN"


def test_simple_synthesis(servers):
    reply = ask(servers, "web.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa) == 1
    assert str(aaaa[0].rdata) == "64:ff9b::c000:20a"  # 192.0.2.10
    # min(negative 30, A 60) == 30
    assert 28 <= aaaa[0].ttl <= 30


def test_cname_alias_preserved(servers):
    reply = ask(servers, "alias.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    cnames = [rr for rr in reply.rr if rr.rtype == QTYPE.CNAME]
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(cnames) == 1
    assert str(cnames[0].rname) == "alias.example."
    assert str(cnames[0].rdata.label) == "web.example."
    assert len(aaaa) == 1
    assert str(aaaa[0].rname) == "web.example."
    assert str(aaaa[0].rdata) == "64:ff9b::c000:20a"
    # min(negative 30, A 60, CNAME 45) == 30
    assert 28 <= aaaa[0].ttl <= 30


def test_no_a_record_returns_nodata(servers):
    reply = ask(servers, "noaddr.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    assert not reply.rr  # NODATA: empty answer section
    assert any(rr.rtype == QTYPE.SOA for rr in reply.auth)


def test_late_a_reply_expires_basis(servers):
    # slow.example.: negative TTL of the no-AAAA answer is 1s, but the A
    # reply only arrives after 1.5s -> synthesis basis expired -> SERVFAIL.
    reply = ask(servers, "slow.example.")
    assert RCODE[reply.header.rcode] == "SERVFAIL"


def test_inconsistent_alias_endpoints(servers):
    # flap.example.: the AAAA reply aliases to ep-a, the A reply to ep-b.
    reply = ask(servers, "flap.example.")
    assert RCODE[reply.header.rcode] == "SERVFAIL"


def test_multiple_a_records_min_ttl(servers):
    reply = ask(servers, "multi.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa) == 2
    # min(negative 30, A 120, A 25) == 25
    assert all(23 <= rr.ttl <= 25 for rr in aaaa)


def test_upstream_timeout_gives_servfail(servers):
    reply = ask(servers, "drop.example.", timeout=5.0)
    assert RCODE[reply.header.rcode] == "SERVFAIL"


def test_non_aaaa_queries_are_proxied(servers):
    reply = ask(servers, "web.example.", qtype="A")
    assert RCODE[reply.header.rcode] == "NOERROR"
    a_records = [rr for rr in reply.rr if rr.rtype == QTYPE.A]
    assert len(a_records) == 1
    assert str(a_records[0].rdata) == "192.0.2.10"


# ---------------------------------------------------------------------------
# Truncation (TC) -> TCP fallback
# ---------------------------------------------------------------------------


def test_truncated_aaaa_and_a_fallback_to_tcp_full_synthesis(servers):
    # tc-many.example.: both the AAAA NODATA and the A answer are truncated
    # on UDP (TC=1).  The DNS64 service must retry each over TCP and only
    # synthesize from the complete replies -> all three A records.
    reply = ask(servers, "tc-many.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa) == 3
    assert {str(rr.rdata) for rr in aaaa} == {
        "64:ff9b::c000:229",  # 192.0.2.41
        "64:ff9b::c000:22a",  # 192.0.2.42
        "64:ff9b::c000:22b",  # 192.0.2.43
    }
    # The collector reply itself must not carry TC: it is built from the
    # complete TCP answers.
    assert reply.header.tc == 0


def test_truncated_empty_aaaa_is_retried_not_treated_as_nodata(servers):
    # tc-empty.example.: the UDP AAAA answer is an empty truncated message
    # (no SOA, no records).  It must be retried over TCP; only the complete
    # NODATA then triggers the A query and synthesis.
    reply = ask(servers, "tc-empty.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa) == 1
    assert str(aaaa[0].rdata) == "64:ff9b::c000:232"  # 192.0.2.50
    assert reply.header.tc == 0


def test_tcp_retry_after_truncation_shares_the_timeout_budget(servers):
    # tc-expire.example.: the truncated UDP AAAA is retried over TCP, but the
    # complete answer only arrives after 1.5s while the negative TTL is 1s.
    # The whole exchange stays within the 2s budget; the basis then expires.
    started = __import__("time").monotonic()
    reply = ask(servers, "tc-expire.example.", timeout=5.0)
    elapsed = __import__("time").monotonic() - started
    assert RCODE[reply.header.rcode] == "SERVFAIL"
    # Two upstream questions, each with a 1.5s TCP retry, plus the final A
    # query; the shared per-query budget (2s) is never exceeded, so the total
    # stays well under two full budgets + slack.
    assert elapsed < 4.5


def test_truncated_reply_with_unreachable_tcp_gives_servfail(servers):
    # tcdrop.example.: TC=1 on UDP but the TCP "service" never answers; the
    # retry cannot get a complete reply inside the 2s budget -> SERVFAIL.
    reply = ask(servers, "tcdrop.example.", timeout=5.0)
    assert RCODE[reply.header.rcode] == "SERVFAIL"


def test_truncated_non_aaaa_query_is_also_retried_over_tcp(servers):
    # The transparent proxy path applies the same UDP->TCP fallback, so a
    # plain A query for tc-many sees all three records, not just the one
    # truncated UDP record.
    reply = ask(servers, "tc-many.example.", qtype="A")
    assert RCODE[reply.header.rcode] == "NOERROR"
    assert reply.header.tc == 0
    a_records = [rr for rr in reply.rr if rr.rtype == QTYPE.A]
    assert len(a_records) == 3
    assert {str(rr.rdata) for rr in a_records} == {
        "192.0.2.41", "192.0.2.42", "192.0.2.43",
    }
