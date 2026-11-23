"""Unit tests for the UDP -> TCP truncation fallback mechanics.

These tests drive ``query_upstream`` against tiny hand-rolled socket mocks so
the shared-deadline behaviour can be measured precisely without the full
DNS64 pipeline.
"""

import socket
import struct
import threading
import time

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord

from dns64_server import (
    UpstreamTimeout,
    _recv_tcp,
    query_upstream,
)


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def free_tcp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_answer(question: DNSRecord, tc: bool = False, records=()) -> DNSRecord:
    reply = question.reply()
    for addr, ttl in records:
        reply.add_answer(RR(str(question.q.qname), QTYPE.A, rdata=A(addr), ttl=ttl))
    reply.header.tc = 1 if tc else 0
    return reply


class _TcpHangServer(threading.Thread):
    """Accepts TCP connections but never sends anything (like tcdrop)."""

    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", port))
        self._srv.listen(5)
        self.accepted = threading.Event()
        self._stop = threading.Event()

    def run(self):
        self._srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            self.accepted.set()
            # Hold the connection open without writing; the client deadline
            # must fire and close it.
            time.sleep(5)
            conn.close()

    def stop(self):
        self._stop.set()
        self._srv.close()


class _TcpSegmentedServer(threading.Thread):
    """Serves one TCP response split into many tiny segments."""

    def __init__(self, port: int, payload: bytes, segment_delay: float = 0.02):
        super().__init__(daemon=True)
        self.port = port
        self.wire = struct.pack("!H", len(payload)) + payload
        self.segment_delay = segment_delay
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", port))
        self._srv.listen(5)
        self._stop = threading.Event()

    def run(self):
        self._srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            try:
                # Read the question (2-byte length + payload), then answer.
                hdr = self._read_n(conn, 2)
                if not hdr:
                    conn.close()
                    continue
                qlen = struct.unpack("!H", hdr)[0]
                self._read_n(conn, qlen)
                # Send the response one byte at a time to force many recv()
                # calls on the client.
                for byte in self.wire:
                    conn.sendall(bytes([byte]))
                    time.sleep(self.segment_delay)
            except OSError:
                pass
            finally:
                conn.close()

    @staticmethod
    def _read_n(conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return data
            data += chunk
        return data

    def stop(self):
        self._stop.set()
        self._srv.close()


class _UpstreamPorts:
    def __init__(self, udp: int, tcp: int):
        self.udp = udp
        self.tcp = tcp


@pytest.fixture
def udp_then_tcp_upstream():
    """UDP listener that returns a scripted reply; TCP port chosen separately."""
    udp_port = free_udp_port()
    tcp_port = free_tcp_port()
    state = {"udp_replies": [], "closed": threading.Event(), "ready": threading.Event()}

    def serve_udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", udp_port))
        state["ready"].set()
        s.settimeout(0.2)
        while not state["closed"].is_set():
            try:
                data, addr = s.recvfrom(8192)
            except socket.timeout:
                continue
            question = DNSRecord.parse(data)
            reply = state["udp_replies"].pop(0)(question)
            s.sendto(reply.pack(), addr)
        s.close()

    t = threading.Thread(target=serve_udp, daemon=True)
    t.start()
    state["ready"].wait(timeout=3)
    yield _UpstreamPorts(udp_port, tcp_port), state
    state["closed"].set()


def test_non_truncated_udp_needs_no_tcp(udp_then_tcp_upstream):
    ports, state = udp_then_tcp_upstream
    state["udp_replies"].append(lambda q: make_answer(q, records=[("192.0.2.1", 60)]))
    exchange = query_upstream("web.example.", "A", "127.0.0.1", ports.udp, timeout=2.0)
    assert RCODE[exchange.reply.header.rcode] == "NOERROR"
    assert exchange.reply.header.tc == 0
    assert len(exchange.reply.rr) == 1


def test_truncated_udp_is_retried_over_tcp_with_full_answer(udp_then_tcp_upstream):
    ports, state = udp_then_tcp_upstream

    question_holder = {}

    # UDP: truncated answer containing just one record.
    state["udp_replies"].append(
        lambda q: make_answer(q, tc=True, records=[("192.0.2.41", 120)])
    )

    # The TCP retry goes to the same host and port number, so bind a TCP
    # listener on the UDP port (the two protocols share port numbers freely).
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", ports.udp))
    srv.listen(1)
    srv.settimeout(3)

    def serve_tcp_same_port():
        conn, _ = srv.accept()
        hdr = conn.recv(2)
        qlen = struct.unpack("!H", hdr)[0]
        q = DNSRecord.parse(_recv_exact(conn, qlen))
        question_holder["q"] = q
        answer = make_answer(
            q, records=[("192.0.2.41", 120), ("192.0.2.42", 120), ("192.0.2.43", 120)]
        )
        payload = answer.pack()
        conn.sendall(struct.pack("!H", len(payload)) + payload)
        conn.close()
        srv.close()

    tcp_thread = threading.Thread(target=serve_tcp_same_port, daemon=True)
    tcp_thread.start()

    exchange = query_upstream("tc-many.example.", "A", "127.0.0.1", ports.udp, timeout=2.0)
    tcp_thread.join(timeout=3)

    assert exchange.reply.header.tc == 0
    assert len(exchange.reply.rr) == 3
    # The retry must ask the same question.
    assert QTYPE[question_holder["q"].q.qtype] == "A"
    assert str(question_holder["q"].q.qname) == "tc-many.example."


def _recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def test_tcp_retry_uses_remaining_budget_and_times_out(udp_then_tcp_upstream):
    ports, state = udp_then_tcp_upstream
    # UDP answers immediately with TC=1.
    state["udp_replies"].append(lambda q: make_answer(q, tc=True))

    hang = _TcpHangServer(ports.udp)  # same port number, different protocol
    hang.start()
    try:
        budget = 1.0
        started = time.monotonic()
        with pytest.raises(UpstreamTimeout):
            query_upstream("tcdrop.example.", "AAAA", "127.0.0.1", ports.udp,
                           timeout=budget)
        elapsed = time.monotonic() - started
        # The TCP wait is bounded by the shared budget, never restarted.
        assert elapsed < budget + 0.5
        assert hang.accepted.is_set()
    finally:
        hang.stop()


def test_segmented_tcp_response_does_not_extend_deadline():
    port = free_tcp_port()
    question = DNSRecord.question("web.example.", "A")
    answer = make_answer(question, records=[("192.0.2.10", 60)])
    server = _TcpSegmentedServer(port, answer.pack(), segment_delay=0.01)
    server.start()
    try:
        # A generous deadline: many 1-byte segments must still complete.
        deadline = time.monotonic() + 3.0
        raw = _recv_tcp("127.0.0.1", port, question.pack(), deadline)
        parsed = DNSRecord.parse(raw)
        assert len(parsed.rr) == 1
        assert str(parsed.rr[0].rdata) == "192.0.2.10"

        # Now a deadline shorter than the time the segmented transfer needs:
        # each recv reuses the remaining budget and the call must raise
        # roughly at the deadline rather than after len*segment_delay.
        port2 = free_tcp_port()
        server2 = _TcpSegmentedServer(port2, answer.pack(), segment_delay=0.05)
        server2.start()
        deadline2 = time.monotonic() + 0.3
        started = time.monotonic()
        with pytest.raises(UpstreamTimeout):
            _recv_tcp("127.0.0.1", port2, question.pack(), deadline2)
        elapsed = time.monotonic() - started
        assert 0.25 < elapsed < 0.9  # bounded by the 0.3s deadline, not 10+ segments
        server2.stop()
    finally:
        server.stop()


def test_udp_silence_consumes_budget_and_fails_without_tcp():
    # No listener at all on the UDP port: the single budget must expire and
    # surface as UpstreamTimeout.
    port = free_udp_port()
    started = time.monotonic()
    with pytest.raises(UpstreamTimeout):
        query_upstream("drop.example.", "AAAA", "127.0.0.1", port, timeout=0.5)
    assert time.monotonic() - started < 1.0
