"""Syntax validation only; never resolve DNS or visit an indicator."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

import idna

from .models import IOC, IOCType


def domain(value: str) -> str:
    value = idna.encode(value.rstrip("."), uts46=True).decode("ascii").lower()
    if len(value) > 253 or "." not in value:
        raise ValueError("Domain must have at least two labels and be at most 253 characters")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
        raise ValueError("Invalid domain label")
    if value.rsplit(".", 1)[1].isdigit():
        raise ValueError("Numeric top-level label is invalid")
    return value


def public_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return not (
            host.endswith(
                (
                    ".local",
                    ".localhost",
                    ".internal",
                    ".lan",
                    ".home",
                    ".test",
                    ".invalid",
                    ".example",
                )
            )
            or host == "localhost"
        )


def validate(value: str) -> IOC:
    value = value.strip()
    if not value or len(value) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Indicator must be 1-2048 characters without control characters")
    for size, kind in ((32, IOCType.md5), (40, IOCType.sha1), (64, IOCType.sha256)):
        if re.fullmatch(rf"[a-fA-F0-9]{{{size}}}", value):
            return IOC(value=value.lower(), type=kind)
    if "%" not in value:
        try:
            ip = ipaddress.ip_address(value)
            return IOC(
                value=str(ip),
                type=IOCType.ipv4 if ip.version == 4 else IOCType.ipv6,
                public=ip.is_global and not ip.is_multicast,
            )
        except ValueError:
            pass
    if "://" in value:
        try:
            parts = urlsplit(value)
            if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
                raise ValueError("Only absolute HTTP(S) URLs are accepted")
            if parts.username is not None or parts.password is not None:
                raise ValueError("Credentials in URLs are not accepted")
            if any(c.isspace() for c in value) or "\\" in value or "%" in parts.hostname:
                raise ValueError("Invalid URL characters")
            port = parts.port
            try:
                host = str(ipaddress.ip_address(parts.hostname))
            except ValueError:
                host = domain(parts.hostname)
            netloc = f"[{host}]" if ":" in host else host
            if port is not None:
                netloc += f":{port}"
            normalized = urlunsplit(
                (parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")
            )
            return IOC(value=normalized, type=IOCType.url, public=public_host(host))
        except (ValueError, idna.IDNAError) as exc:
            raise ValueError(f"Invalid URL: {exc}") from exc
    if re.fullmatch(r"[0-9.]+", value) or ":" in value or "/" in value:
        raise ValueError("Invalid IP address or URL")
    try:
        host = domain(value)
        return IOC(value=host, type=IOCType.domain, public=public_host(host))
    except (ValueError, idna.IDNAError) as exc:
        raise ValueError(f"Invalid indicator: {exc}") from exc
