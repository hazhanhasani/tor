from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import torpanel.cloudflare_origin as cloudflare_origin


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def test_issue_origin_certificate_uses_local_private_key_and_cloudflare_csr(monkeypatch):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Origin CA")])
    captured = {}

    def fake_post(url, headers, json, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        csr = x509.load_pem_x509_csr(json["csr"].encode("ascii"))
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_name)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return FakeResponse({
            "success": True,
            "errors": [],
            "result": {
                "id": "origin-cert-id",
                "expires_on": "2041-09-18T00:00:00Z",
                "certificate": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            },
        })

    monkeypatch.setattr(cloudflare_origin.requests, "post", fake_post)
    issued = cloudflare_origin.issue_origin_certificate(
        "panel.example.com", "secret-token"
    )

    assert captured["url"] == cloudflare_origin.API_URL
    assert captured["headers"]["Authorization"] == "Bearer secret-token"
    assert captured["json"]["request_type"] == "origin-ecc"
    assert captured["json"]["requested_validity"] == 5475
    assert captured["json"]["hostnames"] == ["panel.example.com"]

    cert = x509.load_pem_x509_certificate(issued.certificate_pem.encode("ascii"))
    key = serialization.load_pem_private_key(
        issued.private_key_pem.encode("ascii"), password=None
    )
    cert_public = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert cert_public == key_public
    assert issued.certificate_id == "origin-cert-id"
