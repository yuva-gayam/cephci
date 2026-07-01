"""Unit tests for Apple-style RGW SSL certificate generation."""

import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from utility.apple_rgw_ssl_certs import (
    APPLE_RGW_CERT_SENTINELS,
    format_inline_pem_for_rgw_spec,
    generate_apple_rgw_ssl_certificate,
    get_last_generated_root_ca,
    resolve_apple_rgw_key_format,
    split_inline_pem_for_ssl_cert_ssl_key,
)


def _pem_blocks(pem: str):
    return re.findall(
        r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", pem, re.DOTALL
    )


def _first_key_header(inline_pem: str) -> str:
    return _pem_blocks(inline_pem)[0].splitlines()[0]


def test_generate_apple_rgw_ssl_certificate_pkcs1_order_and_chain():
    inline_pem, root_ca_pem = generate_apple_rgw_ssl_certificate(
        common_name="rgw.ceph-apple.local",
        dns_names=["node3.example", "node4.example"],
        ip_addresses=["10.0.66.108", "10.0.67.232"],
        key_format="PKCS#1",
    )

    blocks = _pem_blocks(inline_pem)
    assert len(blocks) == 4
    assert blocks[0].startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert _pem_blocks(root_ca_pem)[0].startswith("-----BEGIN CERTIFICATE-----")

    certs = [
        x509.load_pem_x509_certificate(block.encode(), default_backend())
        for block in blocks[1:]
    ]
    leaf, int2, int1 = certs
    root = x509.load_pem_x509_certificate(root_ca_pem.encode(), default_backend())

    assert leaf.issuer == int2.subject
    assert int2.issuer == int1.subject
    assert int1.issuer == root.subject


def test_key_format_pem_headers():
    expected_headers = {
        "PKCS#1": "-----BEGIN RSA PRIVATE KEY-----",
        "PKCS#8": "-----BEGIN PRIVATE KEY-----",
        "PKCS#8_enc": "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "EC": "-----BEGIN EC PRIVATE KEY-----",
        "DSA": "-----BEGIN DSA PRIVATE KEY-----",
    }
    for key_format, header in expected_headers.items():
        inline_pem, _ = generate_apple_rgw_ssl_certificate(
            common_name=f"rgw.{key_format}.test",
            dns_names=["node1.example.test"],
            ip_addresses=["10.0.0.1"],
            key_format=key_format,
        )
        assert _first_key_header(inline_pem) == header
        assert inline_pem.count("-----BEGIN CERTIFICATE-----") == 3


def test_pkcs8_encrypted_key_requires_password_to_load():
    inline_pem, _ = generate_apple_rgw_ssl_certificate(
        common_name="rgw.enc.test",
        key_format="PKCS#8_enc",
        pkcs8_password="test-secret",
    )
    key_pem = _pem_blocks(inline_pem)[0]
    with_password = serialization.load_pem_private_key(
        key_pem.encode(),
        password=b"test-secret",
        backend=default_backend(),
    )
    assert with_password is not None


def test_sentinel_mapping():
    assert resolve_apple_rgw_key_format("create-cert_apple_PKCS#8") == "PKCS#8"
    assert resolve_apple_rgw_key_format("create-cert_apple") == "PKCS#1"
    assert resolve_apple_rgw_key_format("create-cert") is None
    assert len(APPLE_RGW_CERT_SENTINELS) == 6


def test_get_last_generated_root_ca_returns_latest_value():
    _, root_ca_pem = generate_apple_rgw_ssl_certificate(
        common_name="rgw.example.test",
        key_format="PKCS#8",
    )
    assert get_last_generated_root_ca() == root_ca_pem


def test_split_inline_pem_for_ssl_cert_ssl_key():
    inline_pem, _ = generate_apple_rgw_ssl_certificate(
        common_name="rgw.split.test",
        key_format="PKCS#1",
    )
    key, certs = split_inline_pem_for_ssl_cert_ssl_key(inline_pem)
    assert key.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert certs.count("-----BEGIN CERTIFICATE-----") == 3


def test_format_inline_pem_for_rgw_spec():
    inline_pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n"
    formatted = format_inline_pem_for_rgw_spec(inline_pem)
    assert formatted.startswith("|\n")
    assert "    -----BEGIN RSA PRIVATE KEY-----" in formatted
