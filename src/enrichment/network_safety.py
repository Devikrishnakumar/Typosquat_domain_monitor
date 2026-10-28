"""Network destination checks for browser-based enrichment of untrusted sites."""

import ipaddress
import socket
from urllib.parse import urlsplit, urljoin

import requests


class UnsafeTargetError(ValueError):
    """Raised when an enrichment request targets a non-public destination."""


def _is_public_address(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def validate_public_http_url(url, allowed_hosts=()):
    """Allow HTTP(S) requests only when every resolved address is globally routable."""
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTargetError("Malformed network URL.") from exc

    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise UnsafeTargetError("Only HTTP(S) URLs with a valid hostname are allowed.")

    if hostname in {host.lower().rstrip(".") for host in allowed_hosts}:
        return True

    if (
        hostname == "localhost"
        or hostname.endswith((".localhost", ".local", ".internal"))
    ):
        raise UnsafeTargetError("Local and internal hostnames are blocked.")

    try:
        literal_address = ipaddress.ip_address(hostname)
    except ValueError:
        literal_address = None
    if literal_address is not None:
        if not literal_address.is_global:
            raise UnsafeTargetError("Private and special-use IP addresses are blocked.")
        return True

    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(
                hostname,
                port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, socket.gaierror) as exc:
        raise UnsafeTargetError(f"Could not safely resolve {hostname}.") from exc

    if not addresses or not all(_is_public_address(address) for address in addresses):
        raise UnsafeTargetError(
            f"{hostname} resolves to a non-public or unusable network address."
        )
    return True


def install_public_network_guard(context, allowed_hosts=()):
    """Abort browser requests that resolve to private or otherwise non-public IPs."""
    explicitly_allowed = frozenset(
        str(host).lower().rstrip(".")
        for host in allowed_hosts
        if host
    )

    def guard(route):
        try:
            validate_public_http_url(
                route.request.url,
                allowed_hosts=explicitly_allowed,
            )
        except UnsafeTargetError:
            route.abort("blockedbyclient")
            return
        route.continue_()

    context.route("**/*", guard)


def public_http_get(url, *, allowed_hosts=(), max_redirects=5, **kwargs):
    """Validate the initial destination and each redirect before making a request.

    The caller owns the returned response and must close it after consuming it.
    """
    kwargs.pop("allow_redirects", None)
    kwargs.setdefault("timeout", 8)
    kwargs.setdefault("stream", True)
    history = []
    for hop in range(max_redirects + 1):
        validate_public_http_url(url, allowed_hosts=allowed_hosts)
        response = requests.get(url, allow_redirects=False, **kwargs)
        location = response.headers.get("Location")
        if response.status_code in {301, 302, 303, 307, 308} and location:
            response.close()
            history.append(response)
            if hop == max_redirects:
                raise requests.TooManyRedirects("Redirect limit exceeded")
            url = urljoin(url, location)
            continue
        response.history = history
        return response
    raise requests.TooManyRedirects("Redirect limit exceeded")


def read_bounded_text(response, max_bytes=1_048_576):
    """Read at most max_bytes and always release the response connection."""
    try:
        body = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            body.extend(chunk[:max(0, max_bytes - len(body))])
            if len(body) >= max_bytes:
                break
        return bytes(body).decode(response.encoding or "utf-8", errors="replace")
    finally:
        response.close()
