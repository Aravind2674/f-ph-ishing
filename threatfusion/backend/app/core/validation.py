import re
import logging
import ipaddress
from urllib.parse import urlparse

from app.core.safe_http import (
    FetchError,
    FetchPolicy,
    SafeFetcher,
    UnsafeTargetError,
    blocked_reason,
    parse_host_ip,
    resolve_host,
)

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

def _is_internal(hostname: str) -> bool:
    """True if the hostname is a local name or an IP literal that must not be fetched.

    Classification lives in :mod:`app.core.safe_http` (``ipaddress``-based, incl. IPv4-mapped,
    NAT64 and 6to4 unwrapping and legacy numeric spellings) so validation and fetching can never
    disagree about what "internal" means.
    """
    if hostname in ("localhost", "localhost.localdomain"):
        return True
    ip = parse_host_ip(hostname)
    return ip is not None and blocked_reason(ip) is not None


async def _check_dns(hostname: str) -> list[str]:
    """Resolve all A/AAAA records (async). Empty list = the name does not resolve."""
    try:
        return [str(ip) for ip in await resolve_host(hostname, 443)]
    except FetchError:
        return []


async def _check_reachability(hostname: str) -> bool:
    """Does anything answer on HTTPS or HTTP?  (Redirects are NOT followed: 3xx counts as alive.)

    Goes through the SSRF-safe fetcher: the connection is pinned to a freshly validated public IP,
    so the DNS answer checked by ``validate_domain_target`` cannot be swapped between check and use.
    TLS verification is off *only* because the question is "does a server answer", not "trust it".
    """
    valid_statuses = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 404, 405}
    fetcher = SafeFetcher(FetchPolicy.from_settings(
        max_bytes=16 * 1024, total_timeout=10.0, request_timeout=5.0, verify_tls=False))
    for scheme in ("https", "http"):  # HTTPS first, then fall back to HTTP
        try:
            res = await fetcher.fetch(f"{scheme}://{hostname}/", follow_redirects=False)
        except (UnsafeTargetError, FetchError):
            continue
        if res.status_code in valid_statuses:
            return True
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
