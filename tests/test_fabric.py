from torpanel.fabric import build_location_port_inventory


def test_inventory_includes_every_external_location_port_and_excludes_socks():
    locations = [
        {
            "slug": "de-one",
            "name": "Germany",
            "country_code": "de",
            "enabled": True,
            "socks_port": 19050,
            "gateway_port": 31001,
            "xui_inbound_port": 21001,
            "inbound_tags": ["manual-de"],
        },
        {
            "slug": "fr-two",
            "name": "France",
            "country_code": "fr",
            "enabled": True,
            "socks_port": 19051,
            "gateway_port": 31002,
            "xui_inbound_port": 21002,
            "inbound_tags": [],
        },
    ]
    result = build_location_port_inventory(
        locations,
        xui_rows=[{"tag": "manual-de", "port": 443}],
        pasarguard_rows=[{"tag": "pg-de", "port": 8443}],
        pasarguard_tags_by_slug={"de-one": ["pg-de"]},
    )

    assert result["location_count"] == 2
    assert result["ports"] == [443, 8443, 21001, 21002, 31001, 31002]
    assert 19050 not in result["ports"]
    assert 19051 not in result["ports"]
    germany = next(row for row in result["locations"] if row["slug"] == "de-one")
    assert germany["ports"] == [443, 8443, 21001, 31001]


def test_inventory_ignores_disabled_locations_and_invalid_ports():
    result = build_location_port_inventory([
        {
            "slug": "disabled",
            "name": "Disabled",
            "country_code": "us",
            "enabled": False,
            "gateway_port": 32000,
            "xui_inbound_port": 22000,
            "inbound_tags": [],
        },
        {
            "slug": "active",
            "name": "Active",
            "country_code": "nl",
            "enabled": True,
            "gateway_port": 70000,
            "xui_inbound_port": 0,
            "inbound_tags": ["bad"],
        },
    ], xui_rows=[{"tag": "bad", "port": -1}])

    assert result["location_count"] == 1
    assert result["ports"] == []


def test_inventory_never_forwards_reserved_tunnel_or_panel_ports():
    result = build_location_port_inventory(
        [{
            "slug": "de-conflict",
            "name": "Germany",
            "country_code": "de",
            "enabled": True,
            "socks_port": 19050,
            "gateway_port": 22000,
            "xui_inbound_port": 8787,
            "inbound_tags": ["safe", "wg-conflict"],
        }],
        xui_rows=[
            {"tag": "safe", "port": 443},
            {"tag": "wg-conflict", "port": 52000},
        ],
        reserved_ports={8787, 22000, 40000, 52000},
    )

    assert result["ports"] == [443]
    assert result["blocked_ports"] == [8787, 22000, 52000]
    assert result["locations"][0]["ports"] == [443]
    assert result["locations"][0]["blocked_ports"] == [8787, 22000, 52000]
