from __future__ import annotations

from typing import Any

import dns.exception
import pytest
from fastapi.testclient import TestClient

from app import service
from app.dns_client import LookupResult, resolve_record
from app.main import app
from app.tls_client import TLSResult, inspect_tls


client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_cache() -> None:
    service.domain_cache.clear()


def empty_dns(name: str, record_type: str) -> LookupResult:
    del name, record_type
    return LookupResult(values=[])


def no_tls(domain: str, addresses: list[str]) -> TLSResult:
    del addresses
    return TLSResult(value=None, note=f"TLS check for {domain} was mocked.")


@pytest.mark.parametrize(
    "name",
    [
        "not-a-domain",
        "127.0.0.1",
        "localhost",
        "service.internal",
        "bad_label.example",
        f"{'a' * 250}.com",
    ],
)
def test_rejects_invalid_or_private_names(name: str) -> None:
    response = client.get("/domain", params={"name": name})

    assert response.status_code == 422


def test_detects_spf_and_dmarc(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_dns(name: str, record_type: str) -> LookupResult:
        if name == "example.com" and record_type == "A":
            return LookupResult(values=["93.184.216.34"], ttl=300)
        if name == "example.com" and record_type == "TXT":
            return LookupResult(
                values=["google-site-verification=abc", "v=spf1 -all"], ttl=600
            )
        if name == "_dmarc.example.com" and record_type == "TXT":
            return LookupResult(values=["v=DMARC1; p=reject"], ttl=120)
        return LookupResult(values=[])

    monkeypatch.setattr(service, "resolve_record", fake_dns)
    monkeypatch.setattr(service, "inspect_tls", no_tls)

    response = client.get("/domain", params={"name": "EXAMPLE.COM"})
    body = response.json()

    assert response.status_code == 200
    assert body["domain"] == "example.com"
    assert body["resolves"] is True
    assert body["has_spf"] is True
    assert body["spf_record"] == "v=spf1 -all"
    assert body["has_dmarc"] is True
    assert body["dmarc_record"] == "v=DMARC1; p=reject"
    assert body["ttl_hint"] == 120


def test_normalizes_unicode_domain_to_punycode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service, "resolve_record", empty_dns)
    monkeypatch.setattr(service, "inspect_tls", no_tls)

    response = client.get("/domain", params={"name": "BÜCHER.de"})

    assert response.status_code == 200
    assert response.json()["domain"] == "xn--bcher-kva.de"


def test_dns_timeout_degrades_fields_and_adds_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timed_out(name: str, record_type: str) -> LookupResult:
        return LookupResult(
            values=None,
            note=f"{record_type} lookup for {name} timed out.",
        )

    monkeypatch.setattr(service, "resolve_record", timed_out)
    monkeypatch.setattr(
        service,
        "inspect_tls",
        lambda domain, addresses: TLSResult(
            value=None,
            note=f"TLS check for {domain} timed out.",
        ),
    )

    response = client.get("/domain", params={"name": "example.com"})
    body = response.json()

    assert response.status_code == 200
    assert body["resolves"] is False
    assert body["a"] is None
    assert body["aaaa"] is None
    assert body["mx"] is None
    assert body["tls"] is None
    assert "timed out" in body["note"]


def test_dns_client_enforces_timeout_and_degrades(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResolver:
        timeout = 0.0
        lifetime = 0.0

        def resolve(self, *args: object, **kwargs: object) -> None:
            assert kwargs["lifetime"] == 4.0
            assert kwargs["search"] is False
            raise dns.exception.Timeout

    monkeypatch.setattr(
        "app.dns_client.dns.resolver.Resolver",
        lambda configure: FakeResolver(),
    )

    result = resolve_record("example.com", "A")

    assert result.values is None
    assert result.note == "A lookup for example.com timed out."


def test_tls_certificate_is_parsed_with_chain_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate: dict[str, Any] = {
        "issuer": ((('commonName', "Test Root CA"),),),
        "subject": ((('commonName', "example.com"),),),
        "notBefore": "Jan  1 00:00:00 2025 GMT",
        "notAfter": "Jan  1 00:00:00 2030 GMT",
    }

    class FakeRawSocket:
        def __enter__(self) -> "FakeRawSocket":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def settimeout(self, timeout: float) -> None:
            assert 0 < timeout <= 5.0

    class FakeSecureSocket:
        def __enter__(self) -> "FakeSecureSocket":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def getpeercert(self) -> dict[str, Any]:
            return certificate

    class FakeContext:
        def wrap_socket(
            self, raw_socket: FakeRawSocket, *, server_hostname: str
        ) -> FakeSecureSocket:
            assert isinstance(raw_socket, FakeRawSocket)
            assert server_hostname == "example.com"
            return FakeSecureSocket()

    def fake_connection(address: tuple[str, int], timeout: float) -> FakeRawSocket:
        assert address == ("93.184.216.34", 443)
        assert 0 < timeout <= 5.0
        return FakeRawSocket()

    monkeypatch.setattr("app.tls_client.socket.create_connection", fake_connection)
    monkeypatch.setattr("app.tls_client.ssl.create_default_context", FakeContext)

    result = inspect_tls("example.com", ["93.184.216.34"])

    assert result.note is None
    assert result.value is not None
    assert result.value["valid_chain"] is True
    assert result.value["issuer_cn"] == "Test Root CA"
    assert result.value["subject_cn"] == "example.com"
    assert result.value["not_before"] == "2025-01-01T00:00:00Z"
    assert result.value["not_after"] == "2030-01-01T00:00:00Z"
    assert isinstance(result.value["days_until_expiry"], int)


def test_tls_skips_private_dns_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    def should_not_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("private address must not be contacted")

    monkeypatch.setattr("app.tls_client.socket.create_connection", should_not_connect)

    result = inspect_tls("public-name.example", ["127.0.0.1", "10.0.0.8", "::1"])

    assert result.value is None
    assert result.note is not None
    assert "no public A/AAAA address" in result.note


def test_health_root_cors_and_openapi() -> None:
    assert client.get("/health").json() == {
        "status": "ok",
        "cache_ttl_seconds": 300,
    }
    assert client.get("/").status_code == 200
    assert client.get("/openapi.json").status_code == 200

    response = client.options(
        "/domain",
        headers={
            "Origin": "https://client.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
