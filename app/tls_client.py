"""Verified TLS certificate inspection using only the standard library."""

from __future__ import annotations

import ipaddress
import math
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from typing import Any


TLS_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class TLSResult:
    value: dict[str, Any] | None
    note: str | None = None


def _common_name(name_parts: Any) -> str | None:
    for relative_name in name_parts or ():
        for key, value in relative_name:
            if key == "commonName":
                return str(value)
    return None


def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)


def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


def _public_addresses(addresses: list[str]) -> list[str]:
    public: list[str] = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.is_global and address not in public:
            public.append(address)
    return public


def inspect_tls(domain: str, addresses: list[str]) -> TLSResult:
    """Verify TLS through globally routable DNS addresses with SNI enabled."""

    candidates = _public_addresses(addresses)
    if not candidates:
        return TLSResult(
            value=None,
            note=f"TLS check for {domain} was skipped: no public A/AAAA address.",
        )

    try:
        context = ssl.create_default_context()
    except Exception as exc:
        return TLSResult(
            value=None,
            note=f"TLS check for {domain} failed ({type(exc).__name__}).",
        )

    failures: list[Exception] = []
    certificate: dict[str, Any] | None = None
    deadline = monotonic() + TLS_TIMEOUT_SECONDS
    for address in candidates:
        remaining = deadline - monotonic()
        if remaining <= 0:
            failures.append(TimeoutError("five-second TLS budget exhausted"))
            break
        try:
            with socket.create_connection(
                (address, 443), timeout=remaining
            ) as raw_socket:
                raw_socket.settimeout(max(deadline - monotonic(), 0.001))
                with context.wrap_socket(
                    raw_socket, server_hostname=domain
                ) as secure_socket:
                    certificate = secure_socket.getpeercert()
            break
        except Exception as exc:  # Try another public address when available.
            failures.append(exc)

    if certificate is None:
        exc = failures[-1] if failures else RuntimeError("handshake did not complete")
        detail = str(exc).replace("\n", " ").strip()[:160]
        suffix = f": {detail}" if detail else ""
        return TLSResult(
            value=None,
            note=f"TLS check for {domain} failed ({type(exc).__name__}){suffix}.",
        )

    try:
        not_before = _parse_cert_time(certificate.get("notBefore"))
        not_after = _parse_cert_time(certificate.get("notAfter"))
        days_until_expiry = None
        if not_after is not None:
            seconds_remaining = (not_after - datetime.now(timezone.utc)).total_seconds()
            days_until_expiry = math.ceil(seconds_remaining / 86_400)

        return TLSResult(
            value={
                "valid_chain": True,
                "issuer_cn": _common_name(certificate.get("issuer")),
                "subject_cn": _common_name(certificate.get("subject")),
                "not_before": _iso_utc(not_before),
                "not_after": _iso_utc(not_after),
                "days_until_expiry": days_until_expiry,
            }
        )
    except Exception as exc:
        detail = str(exc).replace("\n", " ").strip()[:160]
        suffix = f": {detail}" if detail else ""
        return TLSResult(
            value=None,
            note=f"TLS check for {domain} failed ({type(exc).__name__}){suffix}.",
        )
