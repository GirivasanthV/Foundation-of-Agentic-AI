import ipaddress
import socket
import re
from urllib.parse import urlparse, urlunparse


class UnsafeIndicator(ValueError):
    pass


def normalize_indicator(raw: str) -> tuple[str, str]:
    value = raw.strip()
    if re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "sha256", value.lower()
    try:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise UnsafeIndicator("Private, loopback, reserved and link-local IP addresses are not allowed")
        return "ip", str(ip)
    except ValueError as exc:
        if isinstance(exc, UnsafeIndicator):
            raise

    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeIndicator("Enter a valid public HTTP(S) URL, IP address, or SHA-256 hash")
    if parsed.username or parsed.password:
        raise UnsafeIndicator("URLs containing embedded credentials are not allowed")

    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise UnsafeIndicator("Local network destinations are not allowed")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise UnsafeIndicator("Private, loopback, reserved and link-local destinations are not allowed")
    except ValueError as exc:
        if isinstance(exc, UnsafeIndicator):
            raise

    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    normalized = urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, ""))
    return "url", normalized


def resolve_public_ips(url: str) -> list[str]:
    host = urlparse(url).hostname
    if not host:
        raise UnsafeIndicator("URL has no resolvable hostname")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        return []
    for value in addresses:
        if not ipaddress.ip_address(value).is_global:
            raise UnsafeIndicator("The hostname resolves to a private, reserved, or local network address")
    return sorted(addresses)
