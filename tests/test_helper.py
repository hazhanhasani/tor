import base64
import os

from cryptography.fernet import Fernet

os.environ.setdefault("TORPANEL_FERNET_KEY", Fernet.generate_key().decode())

from torpanel.helper import gateway_config
from torpanel.security import encrypt_secret


def test_gateway_blocks_udp_and_routes_tcp_to_tor():
    loc = {
        "slug": "de-test", "gateway_port": 31001, "socks_port": 19050,
        "ss_method": "2022-blake3-aes-128-gcm",
        "ss_password": encrypt_secret(base64.b64encode(b"x" * 32).decode()),
    }
    cfg = gateway_config([loc])
    assert cfg["inbounds"][0]["listen"] == "0.0.0.0"
    assert cfg["inbounds"][0]["settings"]["network"] == "tcp"
    assert cfg["outbounds"][1]["protocol"] == "socks"
    assert cfg["routing"]["rules"][0]["network"] == "udp"
    assert cfg["routing"]["rules"][0]["outboundTag"] == "blocked"
    assert cfg["routing"]["rules"][1]["outboundTag"] == "tor-de-test"
