from bastion.services.ports import parse_listening_ports


def test_parse_counts_only_listen_lines(fixture):
    ports = parse_listening_ports(fixture("ss_tlnp.txt"))
    assert len(ports) == 10


def test_parse_ipv4_and_ipv6(fixture):
    ports = parse_listening_ports(fixture("ss_tlnp.txt"))
    by_addr_port = {(p.local_address, p.port) for p in ports}
    assert ("127.0.0.1", 631) in by_addr_port
    assert ("0.0.0.0", 22) in by_addr_port
    assert ("[::]", 22) in by_addr_port
    assert ("*", 9090) in by_addr_port


def test_parse_process_with_space_in_name(fixture):
    ports = parse_listening_ports(fixture("ss_tlnp.txt"))
    p3017 = next(p for p in ports if p.port == 3017)
    assert p3017.process == "node /home/jamk"
    assert p3017.pid == 895


def test_parse_no_process_column(fixture):
    ports = parse_listening_ports(fixture("ss_tlnp.txt"))
    p22 = next(p for p in ports if p.port == 22 and p.local_address == "0.0.0.0")
    assert p22.process is None
    assert p22.pid is None
    assert p22.recv_q == 0
