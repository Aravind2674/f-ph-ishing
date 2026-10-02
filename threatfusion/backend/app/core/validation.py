import re
import socket
import asyncio
import logging
import ipaddress
import httpx
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def _normalize(target: str) -> str:
    """Removes protocol, paths, query parameters, fragments, ports, and www."""
    if not target:
        return ""
    
    t = target.strip().lower()
    
    # Check for non-http protocols (SSRF protection) before they get stripped
    blocked_schemes = ("file://", "javascript:", "ftp://", "data:", "gopher:", "ws:", "wss:")
    if any(t.startswith(scheme) for scheme in blocked_schemes):
        return t # Will be caught by format validation
    
    # Strip scheme to extract hostname
    if "://" in t:
        try:
            parsed = urlparse(t)
            t = parsed.hostname or parsed.netloc or parsed.path
        except Exception:
            t = t.split("://", 1)[-1]
    
    # Remove paths, queries, fragments, ports
    t = t.split('/')[0].split('?')[0].split('#')[0].split(':')[0]
    
    # Remove www.
    if t.startswith("www."):
        t = t[4:]
        
    return t

def _is_valid_format(hostname: str) -> bool:
    """Validates if the hostname is a properly formed FQDN."""
    # FQDN regex
    domain_regex = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'
    )
    
    # Reject raw IP addresses (e.g. 192.168.1.1, 127.0.0.1) as we only want domains
    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError:
        pass

    if not domain_regex.match(hostname):
        return False
    
    return True

# NAT64 well-known prefix (RFC 6052). Addresses in 64:ff9b::/96 embed an IPv4
# address in their low 32 bits; networks using DNS64/NAT64 return these for
# ordinary public sites. They are NOT internal, but ``is_reserved`` flags the
# whole prefix — which wrongly blocked legitimate domains that resolve to a
# NAT64 address (e.g. universities). We instead unwrap the embedded IPv4 and
# judge that, so a crafted NAT64 address hiding an internal IPv4 (e.g.
# 64:ff9b::7f00:1 → 127.0.0.1) is still correctly rejected.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _is_internal(hostname: str) -> bool:
    """Checks if the hostname is an internal/loopback domain or IP."""
    if hostname in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False

    # Unwrap NAT64 addresses to the embedded IPv4 before judging.
    if isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64_PREFIX:
        ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    )

async def _check_dns(hostname: str) -> list[str]:
    """Performs DNS lookup (A, AAAA, CNAME) to get IPs."""
    loop = asyncio.get_running_loop()
    try:
        res = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        return [r[4][0] for r in res]
    except (socket.gaierror, Exception):
        return []

async def _check_reachability(hostname: str) -> bool:
    """Checks if the web server is reachable via HTTPS or HTTP."""
    valid_statuses = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 404, 405}

    # httpx is the project's single HTTP client (A0-7: the previous aiohttp import was
    # never declared in requirements.txt, so a clean install could not run /scan).
    # verify=False is deliberate *here only*: we are asking "does anything answer?",
    # not trusting the response. This whole function is replaced by the SSRF-safe
    # fetcher in A0-4.
    async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
        for scheme in ("https", "http"):  # HTTPS first, then fall back to HTTP
            try:
                resp = await client.get(f"{scheme}://{hostname}")
                if resp.status_code in valid_statuses:
                    return True
            except Exception:
                continue

    return False

async def validate_domain_target(target: str) -> tuple[bool, dict, str]:
    """
    Validates if a target domain exists by performing normalization, syntax checks, DNS, and connectivity.
    Returns: (is_valid, error_json, normalized_target)
    """
    # Reject explicitly blocked SSRF schemes early
    blocked_schemes = ("file://", "javascript:", "ftp://", "data:", "gopher:", "ws:", "wss:")
    if any(target.strip().lower().startswith(s) for s in blocked_schemes):
        return False, {"success": False, "stage": "format", "message": "Invalid domain format.\nPlease enter a valid website domain."}, target
        
    # Step 1: Normalize Input
    normalized = _normalize(target)
    if not normalized:
        return False, {"success": False, "stage": "normalize", "message": "Empty or invalid target."}, target

    # Step 2: Validate Domain Format
    if not _is_valid_format(normalized):
        return False, {"success": False, "stage": "format", "message": "Invalid domain format.\nPlease enter a valid website domain."}, normalized

    # Step 3: Block Internal Targets
    if _is_internal(normalized):
        return False, {"success": False, "stage": "blocked", "message": "Scanning internal or local addresses is not permitted."}, normalized

    # Step 4: DNS Lookup
    ips = await _check_dns(normalized)
    if not ips:
        return False, {"success": False, "stage": "dns", "message": "The specified website does not exist."}, normalized
        
    # Security: Ensure DNS didn't resolve to a private/internal IP
    for ip in ips:
        if _is_internal(ip):
            return False, {"success": False, "stage": "blocked", "message": "Scanning internal or local addresses is not permitted."}, normalized

    # Step 5 & 6: Check Website Reachability
    reachable = await _check_reachability(normalized)
    if not reachable:
        return False, {"success": False, "stage": "connectivity", "message": "The domain exists, but its web server is currently unreachable."}, normalized

    # Step 7: Success
    return True, {"success": True, "stage": "success", "message": "Validation passed."}, normalized
