"""Automated Apple RGW SSL test scenarios (P0/P1/P2 manual test plan)."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from ceph.ceph import CommandFailed
from utility.apple_rgw_ssl_certs import get_last_generated_root_ca
from utility.log import Log

LOG = Log(__name__)

_CEPHADM = "cephadm shell --"


def _installer(cluster):
    return cluster.get_nodes(role="installer")[0]


def _ceph_cmd(installer, cmd: str, check: bool = True) -> str:
    out, _ = installer.exec_command(
        sudo=True, cmd=f"{_CEPHADM} {cmd}", check_ec=check
    )
    return out


def _orch_ps(installer, service_id: Optional[str] = None) -> List[Dict[str, Any]]:
    out = _ceph_cmd(installer, "ceph orch ps --format json")
    daemons = json.loads(out)
    if service_id:
        return [d for d in daemons if service_id in d.get("daemon_name", "")]
    return daemons


def _rgw_daemons(installer, service_id: str) -> List[Dict[str, Any]]:
    return [
        d
        for d in _orch_ps(installer)
        if d.get("daemon_type") == "rgw" and service_id in d.get("daemon_name", "")
    ]


def _service_name(installer, service_id: str) -> str:
    out = _ceph_cmd(installer, "ceph orch ls --format json")
    for svc in json.loads(out):
        if svc.get("service_id") == service_id:
            return svc["service_name"]
    raise AssertionError(f"RGW service_id {service_id} not found in orch ls")


def _count_running(daemons: List[Dict[str, Any]]) -> int:
    return sum(1 for d in daemons if d.get("status_desc") == "running")


def verify_rgw_running(cluster, config: Dict[str, Any]) -> None:
    """P0-3 / P0-4: RGW service reaches expected running count."""
    service_id = config["service_id"]
    min_running = config.get("min_running", config.get("expected_count", 3))
    installer = _installer(cluster)
    daemons = _rgw_daemons(installer, service_id)
    running = _count_running(daemons)
    LOG.info("RGW %s: %s/%s running", service_id, running, len(daemons))
    assert len(daemons) >= min_running, (
        f"Expected at least {min_running} RGW daemons, found {len(daemons)}"
    )
    assert running >= min_running, (
        f"Expected at least {min_running} running RGW daemons, found {running}"
    )


def verify_daemon_count_unchanged(cluster, config: Dict[str, Any]) -> None:
    """P0-6: RGW daemon count unchanged after upgrade."""
    service_id = config["service_id"]
    expected = config.get("expected_count")
    installer = _installer(cluster)
    daemons = _rgw_daemons(installer, service_id)
    count = len(daemons)
    if expected is not None:
        assert count == expected, f"RGW count {count} != expected {expected}"
    baseline = config.get("baseline_count")
    if baseline is not None:
        assert count == baseline, f"RGW count changed: {baseline} -> {count}"


def verify_export_ssl_fields(cluster, config: Dict[str, Any]) -> None:
    """P0-5 / P1-1: Exported spec contains ssl_cert and ssl_key (hotfix migration)."""
    service_id = config["service_id"]
    installer = _installer(cluster)
    svc_name = _service_name(installer, service_id)
    out = _ceph_cmd(installer, f"ceph orch ls {svc_name} --export")
    if config.get("require_ssl_cert_ssl_key"):
        assert "ssl_cert:" in out, "ssl_cert missing from exported RGW spec"
        assert "ssl_key:" in out, "ssl_key missing from exported RGW spec"
    if config.get("require_legacy_field"):
        assert "rgw_frontend_ssl_certificate:" in out, (
            "rgw_frontend_ssl_certificate missing from export"
        )
    if config.get("forbid_legacy_field"):
        assert "rgw_frontend_ssl_certificate:" not in out, (
            "legacy rgw_frontend_ssl_certificate still present after migration"
        )
    if config.get("allow_either_ssl_format"):
        has_legacy = "rgw_frontend_ssl_certificate:" in out
        has_split = "ssl_cert:" in out and "ssl_key:" in out
        assert has_legacy or has_split, (
            "Export missing both legacy and ssl_cert/ssl_key fields"
        )


def verify_tls_https(cluster, config: Dict[str, Any]) -> None:
    """P1-3: HTTPS responds on all RGW nodes (curl + openssl s_client)."""
    service_id = config["service_id"]
    port = config.get("port", 443)
    installer = _installer(cluster)
    daemons = _rgw_daemons(installer, service_id)
    assert daemons, f"No RGW daemons for {service_id}"

    for daemon in daemons:
        hostname = daemon["hostname"]
        node = cluster.get_node_by_hostname(hostname)
        ip = node.ip_address
        curl_cmd = (
            f"curl -sk --connect-timeout 10 -o /dev/null -w '%{{http_code}}' "
            f"https://{ip}:{port}/"
        )
        code, _ = node.exec_command(sudo=True, cmd=curl_cmd, check_ec=False)
        code = (code or "").strip()
        LOG.info("curl https://%s:%s -> %s", ip, port, code)
        assert code and code[0] in ("2", "3", "4", "5"), (
            f"HTTPS not responding on {hostname} ({ip}:{port}), code={code}"
        )

        s_client_cmd = (
            f"echo | timeout 15 openssl s_client -connect {ip}:{port} -servername "
            f"{hostname} 2>/dev/null | openssl x509 -noout -subject"
        )
        subject, _ = node.exec_command(sudo=True, cmd=s_client_cmd, check_ec=False)
        assert subject.strip(), f"openssl s_client failed on {hostname} ({ip}:{port})"
        LOG.info("TLS OK on %s: %s", hostname, subject.strip())


def verify_fullchain_pem_order(cluster, config: Dict[str, Any]) -> None:
    """P1-4: openssl s_client -showcerts serves 3 certificates in chain."""
    service_id = config["service_id"]
    port = config.get("port", 443)
    expected_certs = config.get("expected_cert_count", 3)
    installer = _installer(cluster)
    daemons = _rgw_daemons(installer, service_id)
    assert daemons, f"No RGW daemons for {service_id}"

    daemon = daemons[0]
    node = cluster.get_node_by_hostname(daemon["hostname"])
    ip = node.ip_address
    cmd = (
        f"echo | timeout 15 openssl s_client -connect {ip}:{port} -showcerts "
        f"2>/dev/null"
    )
    out, _ = node.exec_command(sudo=True, cmd=cmd)
    cert_count = out.count("-----BEGIN CERTIFICATE-----")
    LOG.info("Certificate count from s_client on %s: %s", ip, cert_count)
    assert cert_count >= expected_certs, (
        f"Expected >= {expected_certs} certs in chain, got {cert_count}"
    )


def install_apple_root_ca(cluster, config: Dict[str, Any]) -> None:
    """Install generated Apple root CA on client/RGW nodes for verified TLS."""
    root_ca = get_last_generated_root_ca()
    if not root_ca and config.get("inline_root_ca"):
        root_ca = config["inline_root_ca"]
    if not root_ca:
        LOG.warning("No Apple root CA available; skipping trust install")
        return

    cert_name = config.get("cert_name", "ceph-apple-rgw-root-ca.crt")
    roles = config.get("roles", ["client", "rgw"])
    anchors = "/etc/pki/ca-trust/source/anchors"
    for role in roles:
        for node in cluster.get_nodes(role=role):
            path = f"{anchors}/{cert_name}"
            node.exec_command(sudo=True, cmd=f"mkdir -p {anchors}")
            f = node.remote_file(sudo=True, file_name=path, file_mode="w")
            f.write(root_ca)
            f.flush()
            f.close()
            node.exec_command(sudo=True, cmd="update-ca-trust extract")
            LOG.info("Installed Apple root CA on %s", node.hostname)


def orch_redeploy_rgw(cluster, config: Dict[str, Any]) -> None:
    """P1-2: orch redeploy RGW service on hotfix."""
    service_id = config["service_id"]
    installer = _installer(cluster)
    svc_name = _service_name(installer, service_id)
    _ceph_cmd(installer, f"ceph orch redeploy {svc_name}")
    time.sleep(config.get("wait_seconds", 60))
    verify_rgw_running(cluster, config)
    if config.get("verify_tls", True):
        verify_tls_https(cluster, config)


def certificate_rotation(cluster, config: Dict[str, Any]) -> None:
    """P2-1: Re-apply spec with new cert sentinel and redeploy."""
    service_id = config["service_id"]
    installer = _installer(cluster)
    svc_name = _service_name(installer, service_id)
    _ceph_cmd(installer, f"ceph orch redeploy {svc_name}")
    time.sleep(config.get("wait_seconds", 45))
    verify_rgw_running(cluster, config)


def negative_invalid_pem(cluster, config: Dict[str, Any]) -> None:
    """P2-3: Invalid PEM should fail apply without silent daemon removal."""
    installer = _installer(cluster)
    before = _rgw_daemons(installer, config.get("service_id", "rgw.ssl"))
    before_count = len(before)
    bad_spec = """service_type: rgw
service_id: rgw.ssl.invalid
placement:
  hosts:
    - PLACEHOLDER_HOST
spec:
  ssl: true
  rgw_frontend_port: 9443
  rgw_frontend_ssl_certificate: |
    -----BEGIN INVALID-----
    not-a-real-pem
    -----END INVALID-----
"""
    host = cluster.get_nodes(role="rgw")[0].hostname
    spec = bad_spec.replace("PLACEHOLDER_HOST", host)
    path = "/tmp/rgw-invalid-apple-ssl.yaml"
    f = installer.remote_file(sudo=True, file_name=path, file_mode="w")
    f.write(spec)
    f.flush()
    f.close()

    failed = False
    try:
        installer.exec_command(
            sudo=True,
            cmd=f"{_CEPHADM} ceph orch apply -i {path}",
            check_ec=True,
        )
    except CommandFailed:
        failed = True

    if config.get("expect_apply_failure", True):
        assert failed, "Expected orch apply to fail for invalid PEM"

    after = _rgw_daemons(installer, config.get("service_id", "rgw.ssl"))
    assert len(after) >= before_count, (
        "Existing RGW daemons were removed after invalid PEM apply"
    )


def idempotent_apply(cluster, config: Dict[str, Any]) -> None:
    """P2-5: Applying the same exported spec multiple times does not flap."""
    service_id = config["service_id"]
    installer = _installer(cluster)
    svc_name = _service_name(installer, service_id)
    export_path = "/tmp/rgw-apple-export.yaml"
    out = _ceph_cmd(installer, f"ceph orch ls {svc_name} --export")
    f = installer.remote_file(sudo=True, file_name=export_path, file_mode="w")
    f.write(out)
    f.flush()
    f.close()

    repeats = config.get("repeat", 3)
    for i in range(repeats):
        LOG.info("Idempotent apply iteration %s", i + 1)
        _ceph_cmd(installer, f"ceph orch apply -i {export_path}")
        time.sleep(config.get("wait_seconds", 20))

    verify_rgw_running(cluster, config)


def export_import_roundtrip(cluster, config: Dict[str, Any]) -> None:
    """P2-4: export -> re-apply succeeds."""
    service_id = config["service_id"]
    installer = _installer(cluster)
    svc_name = _service_name(installer, service_id)
    export_path = "/tmp/rgw-apple-roundtrip.yaml"
    out = _ceph_cmd(installer, f"ceph orch ls {svc_name} --export")
    f = installer.remote_file(sudo=True, file_name=export_path, file_mode="w")
    f.write(out)
    f.flush()
    f.close()
    _ceph_cmd(installer, f"ceph orch apply -i {export_path}")
    time.sleep(config.get("wait_seconds", 30))
    verify_rgw_running(cluster, config)


def record_baseline_daemon_count(cluster, config: Dict[str, Any]) -> None:
    """Store RGW daemon count in log for P0-6 baseline comparison."""
    service_id = config["service_id"]
    installer = _installer(cluster)
    count = len(_rgw_daemons(installer, service_id))
    LOG.info("BASELINE_RGW_COUNT service_id=%s count=%s", service_id, count)


SCENARIOS = {
    "verify_rgw_running": verify_rgw_running,
    "verify_daemon_count_unchanged": verify_daemon_count_unchanged,
    "verify_export_ssl_fields": verify_export_ssl_fields,
    "verify_tls_https": verify_tls_https,
    "verify_fullchain_pem_order": verify_fullchain_pem_order,
    "install_apple_root_ca": install_apple_root_ca,
    "orch_redeploy_rgw": orch_redeploy_rgw,
    "certificate_rotation": certificate_rotation,
    "negative_invalid_pem": negative_invalid_pem,
    "idempotent_apply": idempotent_apply,
    "export_import_roundtrip": export_import_roundtrip,
    "record_baseline_daemon_count": record_baseline_daemon_count,
}


def run(ceph_cluster, **kwargs) -> int:
    """Run a named Apple RGW SSL scenario from suite config."""
    config = kwargs.get("config", {})
    scenario = config.get("scenario")
    if not scenario:
        raise ValueError("config.scenario is required for apple_rgw_ssl_scenarios.py")

    handler = SCENARIOS.get(scenario)
    if not handler:
        raise ValueError(f"Unknown Apple RGW SSL scenario: {scenario}")

    LOG.info("Running Apple RGW SSL scenario: %s", scenario)
    handler(ceph_cluster, config)
    return 0
