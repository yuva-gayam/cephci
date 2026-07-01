"""Apple-style RGW SSL certificate generation for cephci apply_spec.

Generates a three-tier PKI (root CA, two intermediate CAs, leaf server cert)
matching the Apple ceph-provisioning inline PEM pattern:

  server.key → leaf → intermediate CA 2 → intermediate CA 1

Supported server private-key PEM headers (sentinel suffix after create-cert_apple_):

  PKCS#1     -----BEGIN RSA PRIVATE KEY-----        (PKCS#1 / legacy RSA)
  PKCS#8     -----BEGIN PRIVATE KEY-----            (unencrypted PKCS#8)
  PKCS#8_enc -----BEGIN ENCRYPTED PRIVATE KEY-----  (password-protected PKCS#8)
  EC         -----BEGIN EC PRIVATE KEY-----         (SEC1 / EC leaf key)
  DSA        -----BEGIN DSA PRIVATE KEY-----         (OpenSSL legacy DSA)

The root CA is returned separately for client trust and is NOT included in the
inline bundle served by RGW.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from utility.log import Log

LOG = Log(__name__)

_LAST_GENERATED_ROOT_CA: Optional[str] = None

_DEFAULT_ORG = "Ceph Lab"
_DEFAULT_COUNTRY = "US"
_ROOT_CA_DAYS = 1825
_INTERMEDIATE_CA_DAYS = 1825
_LEAF_DAYS = 825
_DEFAULT_PKCS8_ENC_PASSWORD = "cephci-apple-rgw-test"

# Sentinel value → key format (used by ceph/ceph_admin/helper.py)
APPLE_RGW_CERT_SENTINELS = {
    "create-cert_apple": "PKCS#1",
    "create-cert_apple_PKCS#1": "PKCS#1",
    "create-cert_apple_PKCS#8": "PKCS#8",
    "create-cert_apple_PKCS#8_enc": "PKCS#8_enc",
    "create-cert_apple_EC": "EC",
    "create-cert_apple_DSA": "DSA",
}

APPLE_RGW_DEFAULT_PORTS = {
    "PKCS#1": 443,
    "PKCS#8": 444,
    "PKCS#8_enc": 445,
    "EC": 8443,
    "DSA": 8444,
}


def get_last_generated_root_ca() -> Optional[str]:
    """Return the root CA PEM from the most recent Apple RGW cert generation."""
    return _LAST_GENERATED_ROOT_CA


def resolve_apple_rgw_key_format(cert_mode: str) -> Optional[str]:
    """Map an rgw_frontend_ssl_certificate sentinel to a key format name."""
    return APPLE_RGW_CERT_SENTINELS.get(cert_mode)


def _pem_certificate(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _serialize_server_private_key(
    private_key: PrivateKeyTypes,
    key_format: str,
    password: Optional[str] = None,
) -> str:
    if key_format == "PKCS#1":
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("PKCS#1 format requires an RSA private key")
        pem_format = serialization.PrivateFormat.TraditionalOpenSSL
        encryption = serialization.NoEncryption()
    elif key_format == "PKCS#8":
        pem_format = serialization.PrivateFormat.PKCS8
        encryption = serialization.NoEncryption()
    elif key_format == "PKCS#8_enc":
        pem_format = serialization.PrivateFormat.PKCS8
        encryption = serialization.BestAvailableEncryption(
            (password or _DEFAULT_PKCS8_ENC_PASSWORD).encode("utf-8")
        )
    elif key_format in ("EC", "DSA"):
        pem_format = serialization.PrivateFormat.TraditionalOpenSSL
        encryption = serialization.NoEncryption()
    else:
        raise ValueError(f"Unsupported Apple RGW key format: {key_format}")

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=pem_format,
        encryption_algorithm=encryption,
    ).decode("utf-8")


def _generate_server_private_key(key_format: str) -> PrivateKeyTypes:
    if key_format == "EC":
        return ec.generate_private_key(ec.SECP256R1(), default_backend())
    if key_format == "DSA":
        return dsa.generate_private_key(key_size=2048, backend=default_backend())
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def _distinguished_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, _DEFAULT_COUNTRY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, _DEFAULT_ORG),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _leaf_key_usage(key_format: str) -> x509.KeyUsage:
    if key_format == "EC":
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    if key_format == "DSA":
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _build_self_signed_root_ca(
    *,
    common_name: str,
    key_size: int,
    days_valid: int,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    subject = _distinguished_name(common_name)
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(_ca_key_usage(), critical=True)
    )

    certificate = builder.sign(private_key, hashes.SHA256(), default_backend())
    return private_key, certificate


def _build_ca_certificate(
    *,
    common_name: str,
    signing_key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
    path_length: Optional[int],
    key_size: int,
    days_valid: int,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    subject = _distinguished_name(common_name)
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(_ca_key_usage(), critical=True)
    )

    certificate = builder.sign(signing_key, hashes.SHA256(), default_backend())
    return private_key, certificate


def _build_leaf_certificate(
    *,
    common_name: str,
    server_key: PrivateKeyTypes,
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    dns_names: List[str],
    ip_addresses: List[str],
    days_valid: int,
    key_format: str,
) -> x509.Certificate:
    subject = _distinguished_name(common_name)
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=days_valid)

    san_entries = []
    for dns_name in dns_names:
        if dns_name:
            san_entries.append(x509.DNSName(dns_name))
    for addr in ip_addresses:
        if addr:
            san_entries.append(x509.IPAddress(ip_address(addr)))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(_leaf_key_usage(key_format), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )

    return builder.sign(issuer_key, hashes.SHA256(), default_backend())


def generate_apple_rgw_ssl_certificate(
    common_name: str,
    dns_names: Optional[List[str]] = None,
    ip_addresses: Optional[List[str]] = None,
    key_format: str = "PKCS#1",
    pkcs8_password: Optional[str] = None,
) -> Tuple[str, str]:
    """Create Apple-style RGW inline PEM bundle and root CA certificate.

    Args:
        common_name: Leaf certificate CN.
        dns_names: Hostnames for the leaf SAN extension.
        ip_addresses: IP addresses for the leaf SAN extension.
        key_format: One of PKCS#1, PKCS#8, PKCS#8_enc, EC, DSA.
        pkcs8_password: Password for PKCS#8_enc keys (optional).

    Returns:
        Tuple of (inline_pem, root_ca_pem).
    """
    global _LAST_GENERATED_ROOT_CA

    if key_format not in APPLE_RGW_DEFAULT_PORTS:
        raise ValueError(f"Unsupported key format: {key_format}")

    dns_names = dns_names or []
    ip_addresses = ip_addresses or []

    all_dns = list(dict.fromkeys([common_name, *dns_names]))
    all_ips = list(dict.fromkeys(ip_addresses))

    root_key, root_cert = _build_self_signed_root_ca(
        common_name="Ceph RGW Root CA",
        key_size=4096,
        days_valid=_ROOT_CA_DAYS,
    )

    int_ca1_key, int_ca1_cert = _build_ca_certificate(
        common_name="Ceph RGW Intermediate CA 1",
        signing_key=root_key,
        issuer_name=root_cert.subject,
        path_length=1,
        key_size=4096,
        days_valid=_INTERMEDIATE_CA_DAYS,
    )

    int_ca2_key, int_ca2_cert = _build_ca_certificate(
        common_name="Ceph RGW Intermediate CA 2",
        signing_key=int_ca1_key,
        issuer_name=int_ca1_cert.subject,
        path_length=0,
        key_size=4096,
        days_valid=_INTERMEDIATE_CA_DAYS,
    )

    server_key = _generate_server_private_key(key_format)
    server_cert = _build_leaf_certificate(
        common_name=common_name,
        server_key=server_key,
        issuer_cert=int_ca2_cert,
        issuer_key=int_ca2_key,
        dns_names=all_dns,
        ip_addresses=all_ips,
        days_valid=_LEAF_DAYS,
        key_format=key_format,
    )

    inline_pem = (
        _serialize_server_private_key(server_key, key_format, password=pkcs8_password)
        + _pem_certificate(server_cert)
        + _pem_certificate(int_ca2_cert)
        + _pem_certificate(int_ca1_cert)
    )
    root_ca_pem = _pem_certificate(root_cert)

    _LAST_GENERATED_ROOT_CA = root_ca_pem
    LOG.info(
        "Generated Apple-style RGW SSL bundle (format=%s) for CN=%s",
        key_format,
        common_name,
    )
    return inline_pem, root_ca_pem


def format_inline_pem_for_rgw_spec(inline_pem: str) -> str:
    """Format inline PEM for embedding in an RGW orchestrator service spec."""
    cert_value = "|\n" + inline_pem
    return "\n    ".join(cert_value.split("\n"))


def extract_pem_blocks(pem: str) -> List[str]:
    """Return ordered PEM blocks (key, certs, ...) from a bundle string."""
    return re.findall(
        r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", pem, re.DOTALL
    )


def split_inline_pem_for_ssl_cert_ssl_key(inline_pem: str) -> Tuple[str, str]:
    """Split Apple inline PEM into ssl_key and ssl_cert (leaf + intermediate chain)."""
    blocks = extract_pem_blocks(inline_pem)
    if len(blocks) < 2:
        raise ValueError("inline PEM must contain a private key and at least one certificate")
    return blocks[0], "".join(blocks[1:])
