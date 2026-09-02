"""Concurrent domain-intelligence aggregation."""

from __future__ import annotations

import asyncio
from typing import Any

from app.cache import TTLCache
from app.dns_client import LookupResult, resolve_record
from app.tls_client import TLSResult, inspect_tls


CACHE_TTL_SECONDS = 300
MAX_RECORDS = 5
MAX_TXT_LENGTH = 200

domain_cache: TTLCache[dict[str, Any]] = TTLCache(
    ttl_seconds=CACHE_TTL_SECONDS,
    max_size=1024,
)


def _limited(values: list[Any] | None) -> list[Any] | None:
    if values is None:
        return None
    return values[:MAX_RECORDS]


def _limited_txt(values: list[Any] | None) -> list[str] | None:
    if values is None:
        return None
    return [str(value)[:MAX_TXT_LENGTH] for value in values[:MAX_RECORDS]]


def _policy_record(values: list[Any] | None, prefix: str) -> str | None:
    if values is None:
        return None
    for value in values:
        text = str(value)
        if text.lower().startswith(prefix.lower()):
            return text[:MAX_TXT_LENGTH]
    return None


async def collect_domain_info(domain: str) -> dict[str, Any]:
    """Collect DNS and TLS information, using a five-minute response cache."""

    cached = domain_cache.get(domain)
    if cached is not None:
        return cached

    lookup_specs = {
        "a": (domain, "A"),
        "aaaa": (domain, "AAAA"),
        "mx": (domain, "MX"),
        "ns": (domain, "NS"),
        "txt": (domain, "TXT"),
        "cname": (domain, "CNAME"),
        "dmarc": (f"_dmarc.{domain}", "TXT"),
    }
    lookup_tasks = {
        key: asyncio.to_thread(resolve_record, name, record_type)
        for key, (name, record_type) in lookup_specs.items()
    }
    keys = list(lookup_tasks)
    gathered = await asyncio.gather(
        *(lookup_tasks[key] for key in keys),
        return_exceptions=True,
    )
    lookups: dict[str, LookupResult] = {}
    for key, value in zip(keys, gathered, strict=True):
        if isinstance(value, BaseException):
            name, record_type = lookup_specs[key]
            lookups[key] = LookupResult(
                values=None,
                note=f"{record_type} lookup for {name} failed: "
                f"{type(value).__name__}.",
            )
        else:
            lookups[key] = value

    a_values = lookups["a"].values
    aaaa_values = lookups["aaaa"].values
    tls_addresses = [str(value) for value in (a_values or []) + (aaaa_values or [])]
    tls_result: TLSResult = await asyncio.to_thread(
        inspect_tls,
        domain,
        tls_addresses,
    )

    notes = [result.note for result in lookups.values() if result.note]
    if tls_result.note:
        notes.append(tls_result.note)

    txt_values = lookups["txt"].values
    dmarc_values = lookups["dmarc"].values
    spf_record = _policy_record(txt_values, "v=spf1")
    dmarc_record = _policy_record(dmarc_values, "v=dmarc1")

    ttl_values = [
        result.ttl for result in lookups.values() if result.ttl is not None
    ]
    cname_values = lookups["cname"].values

    result: dict[str, Any] = {
        "domain": domain,
        "resolves": bool((a_values or []) or (aaaa_values or [])),
        "a": _limited(a_values),
        "aaaa": _limited(aaaa_values),
        "mx": _limited(lookups["mx"].values),
        "ns": _limited(lookups["ns"].values),
        "txt": _limited_txt(txt_values),
        "has_spf": spf_record is not None,
        "spf_record": spf_record,
        "has_dmarc": dmarc_record is not None,
        "dmarc_record": dmarc_record,
        "cname": (
            str(cname_values[0])
            if cname_values is not None and len(cname_values) > 0
            else None
        ),
        "ttl_hint": min(ttl_values) if ttl_values else None,
        "tls": tls_result.value,
        "note": " ".join(notes) if notes else None,
    }
    domain_cache.set(domain, result)
    return result
