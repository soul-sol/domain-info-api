"""Bounded DNS lookups and record normalization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver


DNS_TIMEOUT_SECONDS = 4.0


@dataclass(frozen=True)
class LookupResult:
    values: list[Any] | None
    ttl: int | None = None
    note: str | None = None


def _target_text(value: Any) -> str:
    if hasattr(value, "to_text"):
        return value.to_text(omit_final_dot=True)
    return str(value).rstrip(".")


def _txt_text(record: Any) -> str:
    strings = getattr(record, "strings", None)
    if strings is not None:
        return b"".join(strings).decode("utf-8", errors="replace")
    return record.to_text().strip('"').replace('" "', "")


def _normalize_values(answer: Any, record_type: str) -> list[Any]:
    if record_type in {"A", "AAAA"}:
        return [str(record.address) for record in answer]
    if record_type == "MX":
        values = [
            {
                "host": _target_text(record.exchange),
                "priority": int(record.preference),
            }
            for record in answer
        ]
        return sorted(values, key=lambda item: (item["priority"], item["host"]))
    if record_type == "NS":
        return sorted(_target_text(record.target) for record in answer)
    if record_type == "TXT":
        return [_txt_text(record) for record in answer]
    if record_type == "CNAME":
        return [_target_text(record.target) for record in answer]
    return [record.to_text() for record in answer]


def resolve_record(name: str, record_type: str) -> LookupResult:
    """Resolve one record type with a hard four-second lifetime."""

    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = DNS_TIMEOUT_SECONDS
        resolver.lifetime = DNS_TIMEOUT_SECONDS
        answer = resolver.resolve(
            name,
            record_type,
            lifetime=DNS_TIMEOUT_SECONDS,
            search=False,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return LookupResult(values=[])
    except dns.exception.Timeout:
        return LookupResult(
            values=None,
            note=f"{record_type} lookup for {name} timed out.",
        )
    except dns.resolver.NoNameservers:
        return LookupResult(
            values=None,
            note=f"{record_type} lookup for {name} had no usable nameserver.",
        )
    except dns.exception.DNSException as exc:
        return LookupResult(
            values=None,
            note=f"{record_type} lookup for {name} failed: {type(exc).__name__}.",
        )
    except Exception as exc:
        return LookupResult(
            values=None,
            note=f"{record_type} lookup for {name} failed: {type(exc).__name__}.",
        )

    try:
        rrset = getattr(answer, "rrset", None)
        ttl = int(rrset.ttl) if rrset is not None and rrset.ttl is not None else None
        return LookupResult(values=_normalize_values(answer, record_type), ttl=ttl)
    except Exception as exc:
        return LookupResult(
            values=None,
            note=f"{record_type} response for {name} could not be parsed: "
            f"{type(exc).__name__}.",
        )
