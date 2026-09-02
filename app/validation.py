"""Domain normalization and input validation."""

from __future__ import annotations

import ipaddress
import re


LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
PRIVATE_SUFFIXES = (
    "localhost",
    "local",
    "internal",
    "intranet",
    "home",
    "lan",
    "corp",
    "private",
    "home.arpa",
    "test",
    "invalid",
    "onion",
)


class InvalidDomain(ValueError):
    """Raised when a value is not a safe public DNS domain name."""


def normalize_domain(value: str) -> str:
    """Return a lowercase ASCII IDNA domain or raise ``InvalidDomain``."""

    candidate = value.strip().lower()
    if not candidate:
        raise InvalidDomain("Domain name is required.")

    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not candidate or candidate.endswith("."):
        raise InvalidDomain("Domain name has an invalid trailing dot.")

    try:
        ipaddress.ip_address(candidate.strip("[]"))
    except ValueError:
        pass
    else:
        raise InvalidDomain("IP addresses are not accepted.")

    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomain("Domain name cannot be converted to IDNA.") from exc

    if len(normalized) > 253:
        raise InvalidDomain("Domain name exceeds 253 characters.")

    labels = normalized.split(".")
    if len(labels) < 2:
        raise InvalidDomain("A public domain name must contain a suffix.")
    if any(not LABEL_PATTERN.fullmatch(label) for label in labels):
        raise InvalidDomain("Domain name contains an invalid label.")
    if labels[-1].isdigit():
        raise InvalidDomain("The final domain label cannot be numeric.")

    if any(
        normalized == suffix or normalized.endswith(f".{suffix}")
        for suffix in PRIVATE_SUFFIXES
    ):
        raise InvalidDomain("Local and private-use domain suffixes are not accepted.")

    return normalized
