import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "tlm-port-fabric.py"
spec = importlib.util.spec_from_file_location("tlm_port_fabric", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def test_nft_script_forwards_tcp_and_udp_and_snat_back_to_iran_overlay():
    script, mappings, conflicts = module.build_nft_script([
        {
            "uuid": "aaaaaaaa-1111-2222-3333-444444444444",
            "ready": True,
            "interface": "tlmaaaaaaa",
            "iran_ip": "10.203.0.1",
            "foreign_ip": "10.203.0.2",
            "ports": [21001, 31001],
        }
    ])

    assert not conflicts
    assert len(mappings) == 2
    assert "tcp dport 21001 dnat to 10.203.0.2:21001" in script
    assert "udp dport 21001 dnat to 10.203.0.2:21001" in script
    assert "snat to 10.203.0.1" in script
    assert 'oifname "tlmaaaaaaa"' in script


def test_duplicate_public_port_is_not_silently_mapped_to_two_foreign_nodes():
    script, mappings, conflicts = module.build_nft_script([
        {
            "uuid": "aaaaaaaa-1111-2222-3333-444444444444",
            "ready": True,
            "interface": "tlmaaaaaaa",
            "iran_ip": "10.203.0.1",
            "foreign_ip": "10.203.0.2",
            "ports": [443],
        },
        {
            "uuid": "bbbbbbbb-1111-2222-3333-444444444444",
            "ready": True,
            "interface": "tlmbbbbbbb",
            "iran_ip": "10.203.0.5",
            "foreign_ip": "10.203.0.6",
            "ports": [443],
        },
    ])

    assert len(mappings) == 1
    assert conflicts
    assert script.count("tcp dport 443 dnat") == 1


def test_unready_or_invalid_links_are_ignored():
    script, mappings, conflicts = module.build_nft_script([
        {
            "uuid": "bad",
            "ready": False,
            "interface": "not-safe",
            "iran_ip": "bad",
            "foreign_ip": "bad",
            "ports": [80],
        }
    ])
    assert mappings == []
    assert conflicts == []
    assert "add table ip tlm_port_fabric" not in script
