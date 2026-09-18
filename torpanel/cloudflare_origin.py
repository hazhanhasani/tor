from __future__ import annotations

from dataclasses import dataclass

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

API_URL = "https://api.cloudflare.com/client/v4/certificates"


class CloudflareOriginError(RuntimeError):
    pass


@dataclass(frozen=True)
class OriginCertificate:
    certificate_pem: str
    private_key_pem: str
    certificate_id: str
    expires_on: str


def issue_origin_certificate(
    hostname: str,
    api_token: str,
    *,
    requested_validity: int = 5475,
    timeout: int = 30,
) -> OriginCertificate:
    hostname = (hostname or "").strip().lower().rstrip(".")
    api_token = (api_token or "").strip()
    if not hostname:
        raise CloudflareOriginError("Cloudflare Origin CA hostname is empty.")
    if not api_token:
        raise CloudflareOriginError("Cloudflare Origin CA API token is empty.")

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")

    try:
        response = requests.post(
            API_URL,
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={
                "hostnames": [hostname],
                "request_type": "origin-ecc",
                "requested_validity": requested_validity,
                "csr": csr_pem,
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise CloudflareOriginError(f"Cloudflare Origin CA request failed: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise CloudflareOriginError(
            f"Cloudflare Origin CA returned HTTP {response.status_code} with invalid JSON."
        ) from exc

    if response.status_code >= 400 or not payload.get("success"):
        errors = payload.get("errors") or []
        messages = []
        for item in errors:
            if isinstance(item, dict):
                message = str(item.get("message") or "").strip()
                if message:
                    messages.append(message)
        detail = "; ".join(messages) or f"HTTP {response.status_code}"
        raise CloudflareOriginError(f"Cloudflare Origin CA rejected the request: {detail}")

    result = payload.get("result") or {}
    certificate = str(result.get("certificate") or "").strip()
    if "BEGIN CERTIFICATE" not in certificate:
        raise CloudflareOriginError("Cloudflare Origin CA response did not include a certificate.")

    return OriginCertificate(
        certificate_pem=certificate + "\n",
        private_key_pem=private_key_pem,
        certificate_id=str(result.get("id") or ""),
        expires_on=str(result.get("expires_on") or ""),
    )
