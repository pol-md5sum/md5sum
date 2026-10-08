import pytest

import pcapgen
from irsys import network


@pytest.mark.parametrize("writer", [pcapgen.write_pcap, pcapgen.write_pcapng])
def test_network_analysis(tmp_path, writer):
    p = tmp_path / "cap.bin"
    writer(p, pcapgen.scenario())
    r = network.analyze(p)
    assert r["packets"] == 28

    names = {d["name"]: d for d in r["dns"]}
    assert names["update.c2-relay.example"]["resolved"] == ["203.0.113.50"]
    assert names["update.c2-relay.example"]["clients"] == ["10.0.0.15"]

    assert {t["sni"] for t in r["tls"]} == {"update.c2-relay.example"}
    assert r["tls"][0]["ja3"] == "771,4865,0-10-11,29-23,0"  # GREASE 제거

    [h] = r["http"]
    assert (h["method"], h["uri"], h["user_agent"]) == ("GET", "/gate.php?id=15", "Mozilla/4.0")

    by_type = {}
    for f in r["findings"]:
        by_type.setdefault(f["type"], []).append(f)
    [beacon] = by_type["beacon"]
    assert (beacon["dst"], beacon["dport"], beacon["events"]) == ("203.0.113.50", 443, 10)
    assert 59 < beacon["interval_sec"] < 61
    assert by_type["dns_tunnel"][0]["domain"] == "tunnel.example"
    assert by_type["http_nonstandard_port"][0]["dport"] == 8888

    assert {"T1071.001", "T1071.004", "T1571"} <= set(r["attack_techniques"])
    assert "203.0.113.50" in r["iocs"]["ipv4"]
    assert "10.0.0.15" not in r["iocs"].get("ipv4", [])
    assert "update.c2-relay.example" in r["iocs"]["domain"]
    assert "http://198.51.100.9:8888/gate.php?id=15" in r["iocs"]["url"]


def test_irregular_traffic_is_not_beacon(tmp_path):
    frames = []
    for i, gap in enumerate([3, 50, 7, 120, 15, 300, 2, 90]):
        frames.append((1_791_000_000 + sum([3, 50, 7, 120, 15, 300, 2, 90][:i]),
                       pcapgen.tcp("10.0.0.15", "203.0.113.50", 40000 + i, 443, flags=0x02)))
    p = tmp_path / "c.pcap"
    pcapgen.write_pcap(p, frames)
    assert not [f for f in network.analyze(p)["findings"] if f["type"] == "beacon"]


def test_registered_domain():
    assert network.registered_domain("a.b.example.co.kr") == "example.co.kr"
    assert network.registered_domain("x.y.evil.com") == "evil.com"


def test_rejects_non_pcap(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not a capture file at all......")
    with pytest.raises(ValueError):
        network.analyze(p)
