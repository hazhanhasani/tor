import base64
import uuid

from torpanel.vless import (
    REALITY_DEST,
    REALITY_FLOW,
    REALITY_SERVER_NAME,
    build_gateway_vless_inbound,
    build_gateway_vless_outbound,
    gateway_reality_identity,
    managed_inbound_reality_identity,
)


def fake_decrypt(value):
    return "persistent-transport-seed"


def location():
    return {
        "slug": "de-test",
        "name": "Germany",
        "country_code": "DE",
        "gateway_port": 31001,
        "ss_password": "encrypted",
    }


def _decode_unpadded(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_gateway_reality_identity_is_stable_and_valid():
    loc = location()
    first = gateway_reality_identity(loc, fake_decrypt)
    second = gateway_reality_identity(loc, fake_decrypt)
    assert first == second
    assert uuid.UUID(first.client_id).version == 4
    assert len(_decode_unpadded(first.private_key)) == 32
    assert len(_decode_unpadded(first.public_key)) == 32
    assert len(first.short_id) == 16
    int(first.short_id, 16)


def test_gateway_server_and_client_configs_share_reality_identity():
    loc = location()
    server = build_gateway_vless_inbound(loc, fake_decrypt, "gateway-de")
    client = build_gateway_vless_outbound(loc, "203.0.113.10", fake_decrypt, "torloc-de")
    identity = gateway_reality_identity(loc, fake_decrypt)

    assert server["protocol"] == client["protocol"] == "vless"
    assert server["settings"]["clients"][0]["id"] == client["settings"]["id"] == identity.client_id
    assert server["settings"]["clients"][0]["flow"] == client["settings"]["flow"] == REALITY_FLOW

    sr = server["streamSettings"]["realitySettings"]
    cr = client["streamSettings"]["realitySettings"]
    assert server["streamSettings"]["security"] == client["streamSettings"]["security"] == "reality"
    assert sr["dest"] == REALITY_DEST
    assert sr["serverNames"] == [REALITY_SERVER_NAME]
    assert sr["shortIds"] == [cr["shortId"]]
    assert cr["publicKey"] == identity.public_key
    assert cr["serverName"] == REALITY_SERVER_NAME


def test_public_managed_inbound_uses_different_identity_from_gateway():
    loc = location()
    assert managed_inbound_reality_identity(loc, fake_decrypt) != gateway_reality_identity(loc, fake_decrypt)


def test_managed_3xui_inbound_contains_share_link_reality_metadata():
    from torpanel.vless import build_managed_vless_inbound

    loc = {**location(), "xui_inbound_port": 21000}
    inbound = build_managed_vless_inbound(loc, fake_decrypt, tag="torloc-in-de-test", port=21000)
    identity = managed_inbound_reality_identity(loc, fake_decrypt)
    assert inbound["settings"]["encryption"] == "none"
    assert inbound["settings"]["clients"][0]["flow"] == REALITY_FLOW
    assert inbound["streamSettings"]["tcpSettings"]["header"]["type"] == "none"
    reality = inbound["streamSettings"]["realitySettings"]
    assert reality["target"] == REALITY_DEST
    assert reality["privateKey"] == identity.private_key
    assert reality["shortIds"] == [identity.short_id]
    assert reality["settings"]["publicKey"] == identity.public_key
    assert reality["settings"]["fingerprint"] == "chrome"
    assert reality["settings"]["spiderX"] == "/"
