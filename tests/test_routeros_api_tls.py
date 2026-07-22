from __future__ import annotations

import datetime
import socket
import ssl
import threading
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from routeros_inspector_mcp.backends.base import BackendError
from routeros_inspector_mcp.backends.routeros_api import RouterOSAPIBackend
from routeros_inspector_mcp.config import DeviceEntry


def device(**overrides: Any) -> DeviceEntry:
    values: dict[str, Any] = {
        "role": "gateway",
        "risk": "critical",
        "host": "192.0.2.1",
        "transport": "api",
        "credential_ref": "vault:test",
    }
    values.update(overrides)
    return DeviceEntry(**values)


def self_signed_server_certificate(tmp_path: Path, name: str) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / f"{name}.crt"
    key_path = tmp_path / f"{name}.key"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


def complete_tls_handshake(
    ssl_wrapper: Any, certificate_path: Path, key_path: Path
) -> tuple[ssl.SSLSocket, list[BaseException]]:
    client_socket, server_socket = socket.socketpair()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate_path, key_path)
    server_errors: list[BaseException] = []

    def serve() -> None:
        try:
            with server_context.wrap_socket(server_socket, server_side=True):
                pass
        except BaseException as exc:
            server_errors.append(exc)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client_tls = ssl_wrapper(client_socket)
    except BaseException:
        client_socket.close()
        thread.join(timeout=2)
        raise
    thread.join(timeout=2)
    assert not thread.is_alive()
    return client_tls, server_errors


def test_plaintext_device_defaults_remain_explicit() -> None:
    entry = device()
    backend = RouterOSAPIBackend({"router": entry})

    kwargs = backend._connect_kwargs(entry, "readonly", "secret", encoding="UTF-8")

    assert kwargs["port"] == 8728
    assert "ssl_wrapper" not in kwargs
    assert entry.routeros_api_tls is False


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"routeros_api_tls": True}, "explicit TCP/8729"),
        (
            {"routeros_api_tls": True, "routeros_api_port": 8729},
            "requires a pinned certificate",
        ),
        (
            {"routeros_api_certificate": "router.crt"},
            "require explicit TLS mode",
        ),
        (
            {
                "transport": "ssh",
                "routeros_api_tls": True,
                "routeros_api_port": 8729,
                "routeros_api_certificate": "router.crt",
                "routeros_api_server_name": "router.example.test",
            },
            "requires API transport",
        ),
    ],
)
def test_invalid_tls_inventory_fails_closed(overrides: dict[str, Any], error: str) -> None:
    with pytest.raises(ValidationError, match=error):
        device(**overrides)


def test_api_ssl_port_rejects_plaintext_configuration() -> None:
    with pytest.raises(ValidationError, match="TCP/8729 requires TLS"):
        device(routeros_api_port=8729)


def test_unknown_tls_inventory_field_is_rejected() -> None:
    with pytest.raises(ValidationError, match="routeros_api_tsl"):
        device(routeros_api_tsl=True)


def test_verified_tls_kwargs_pin_certificate_and_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    certificate = tmp_path / "router.crt"
    certificate.write_text("test certificate")
    entry = device(
        routeros_api_tls=True,
        routeros_api_port=8729,
        routeros_api_certificate=str(certificate),
        routeros_api_server_name="router.example.test",
    )
    backend = RouterOSAPIBackend({"router": entry})
    observed: dict[str, Any] = {}

    class FakeContext:
        minimum_version: Any = None
        check_hostname = False
        verify_mode: Any = None

        def wrap_socket(self, sock: socket.socket, *, server_hostname: str) -> socket.socket:
            observed["server_hostname"] = server_hostname
            return sock

    context = FakeContext()
    monkeypatch.setattr(
        "routeros_inspector_mcp.backends.routeros_api.ssl.create_default_context",
        lambda *, cafile: observed.update(cafile=cafile) or context,
    )

    kwargs = backend._connect_kwargs(entry, "readonly", "secret", encoding="latin-1")
    ssl_wrapper = kwargs["ssl_wrapper"]
    marker = socket.socket()
    try:
        assert ssl_wrapper(marker) is marker
    finally:
        marker.close()

    assert kwargs["port"] == 8729
    assert kwargs["encoding"] == "latin-1"
    assert observed["cafile"] == str(certificate)
    assert observed["server_hostname"] == "router.example.test"
    assert context.minimum_version.name == "TLSv1_2"
    assert context.check_hostname is True
    assert context.verify_mode.name == "CERT_REQUIRED"


def test_tls_wrapper_completes_verified_handshake(tmp_path: Path) -> None:
    certificate, key = self_signed_server_certificate(tmp_path, "router.example.test")
    entry = device(
        routeros_api_tls=True,
        routeros_api_port=8729,
        routeros_api_certificate=str(certificate),
        routeros_api_server_name="router.example.test",
    )
    backend = RouterOSAPIBackend({"router": entry})
    kwargs = backend._connect_kwargs(entry, "readonly", "secret", encoding="UTF-8")

    client_tls, server_errors = complete_tls_handshake(kwargs["ssl_wrapper"], certificate, key)
    try:
        assert client_tls.version() in {"TLSv1.2", "TLSv1.3"}
        assert server_errors == []
    finally:
        client_tls.close()


def test_tls_wrapper_rejects_wrong_server_identity(tmp_path: Path) -> None:
    certificate, key = self_signed_server_certificate(tmp_path, "router.example.test")
    entry = device(
        routeros_api_tls=True,
        routeros_api_port=8729,
        routeros_api_certificate=str(certificate),
        routeros_api_server_name="wrong.home.arpa",
    )
    backend = RouterOSAPIBackend({"router": entry})
    kwargs = backend._connect_kwargs(entry, "readonly", "secret", encoding="UTF-8")

    with pytest.raises(ssl.SSLCertVerificationError, match="Hostname mismatch"):
        complete_tls_handshake(kwargs["ssl_wrapper"], certificate, key)


def test_tls_wrapper_rejects_untrusted_certificate(tmp_path: Path) -> None:
    trusted_certificate, _ = self_signed_server_certificate(tmp_path, "trusted.home.arpa")
    presented_certificate, presented_key = self_signed_server_certificate(
        tmp_path, "router.example.test"
    )
    entry = device(
        routeros_api_tls=True,
        routeros_api_port=8729,
        routeros_api_certificate=str(trusted_certificate),
        routeros_api_server_name="router.example.test",
    )
    backend = RouterOSAPIBackend({"router": entry})
    kwargs = backend._connect_kwargs(entry, "readonly", "secret", encoding="UTF-8")

    with pytest.raises(ssl.SSLCertVerificationError, match="self-signed certificate"):
        complete_tls_handshake(kwargs["ssl_wrapper"], presented_certificate, presented_key)


def test_missing_pinned_certificate_fails_before_connect(tmp_path: Path) -> None:
    entry = device(
        routeros_api_tls=True,
        routeros_api_port=8729,
        routeros_api_certificate=str(tmp_path / "missing.crt"),
        routeros_api_server_name="router.example.test",
    )
    backend = RouterOSAPIBackend({"router": entry})

    with pytest.raises(BackendError, match="missing or empty"):
        backend._connect_kwargs(entry, "readonly", "secret", encoding="UTF-8")
