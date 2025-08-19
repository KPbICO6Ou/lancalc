#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Core functionality for LanCalc - IPv4 subnet calculations.

Pure business logic for network calculations without external dependencies.
"""
import ipaddress
import logging
import sys
import asyncio
import functools
import time
from typing import Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor
import threading


# Global configuration
DEBUG_MODE = False
CACHE_ENABLED = True
MAX_WORKERS = 4

# Thread-safe cache for computation results
_computation_cache = {}
_cache_lock = threading.Lock()

# Configure logging with dynamic level
def setup_logging(debug: bool = False) -> None:
    """Setup logging with optional debug mode."""
    global DEBUG_MODE
    DEBUG_MODE = debug
    
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(
        handlers=[logging.StreamHandler(sys.stderr)],
        level=level,
        format='%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s.%(funcName)s) - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True
    )

setup_logging()
logger = logging.getLogger(__name__)

REPO_URL = "https://github.com/lancalc/lancalc"

# Thread pool executor for async operations
_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="LanCalc")


def debug_log(func):
    """Decorator for debug logging with timing."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if DEBUG_MODE:
            start_time = time.time()
            logger.debug(f"Entering {func.__name__} with args={args}, kwargs={kwargs}")
            
            try:
                result = func(*args, **kwargs)
                elapsed = (time.time() - start_time) * 1000
                logger.debug(f"Exiting {func.__name__} in {elapsed:.2f}ms with result={result}")
                return result
            except Exception as e:
                elapsed = (time.time() - start_time) * 1000
                logger.debug(f"Exception in {func.__name__} after {elapsed:.2f}ms: {e}")
                raise
        else:
            return func(*args, **kwargs)
    return wrapper


def get_cache_key(ip: str, prefix: int) -> str:
    """Generate cache key for IP and prefix combination."""
    return f"{ip}/{prefix}"


def get_cached_result(ip: str, prefix: int) -> Optional[Dict[str, str]]:
    """Get cached computation result if available."""
    if not CACHE_ENABLED:
        return None
    
    cache_key = get_cache_key(ip, prefix)
    with _cache_lock:
        return _computation_cache.get(cache_key)


def set_cached_result(ip: str, prefix: int, result: Dict[str, str]) -> None:
    """Cache computation result."""
    if not CACHE_ENABLED:
        return
    
    cache_key = get_cache_key(ip, prefix)
    with _cache_lock:
        # Limit cache size to prevent memory issues
        if len(_computation_cache) > 1000:
            # Remove oldest entries (simple FIFO)
            oldest_keys = list(_computation_cache.keys())[:100]
            for key in oldest_keys:
                del _computation_cache[key]
        
        _computation_cache[cache_key] = result


@debug_log
def validate_ip(ip: str) -> None:
    """Validate IPv4 address format or raise ValueError."""
    if DEBUG_MODE:
        logger.debug(f"Validating IP address: {ip}")
    
    try:
        ipaddress.IPv4Address(ip)
        if DEBUG_MODE:
            logger.debug(f"IP address {ip} is valid")
    except ipaddress.AddressValueError as exc:
        if DEBUG_MODE:
            logger.debug(f"IP address {ip} is invalid: {exc}")
        raise ValueError(f"Invalid IP address: {ip}") from exc


@debug_log
def validate_prefix(prefix: str) -> int:
    """Validate CIDR prefix (0-32). Return int or raise ValueError."""
    if DEBUG_MODE:
        logger.debug(f"Validating prefix: {prefix}")
    
    try:
        prefix_int = int(prefix)
        if 0 <= prefix_int <= 32:
            if DEBUG_MODE:
                logger.debug(f"Prefix {prefix} is valid")
            return prefix_int
        else:
            if DEBUG_MODE:
                logger.debug(f"Prefix {prefix} is out of range [0-32]")
            raise ValueError(f"Invalid prefix: {prefix}")
    except ValueError as exc:
        if DEBUG_MODE:
            logger.debug(f"Prefix {prefix} is not a valid integer: {exc}")
        raise ValueError(f"Invalid prefix: {prefix}") from exc


@debug_log
def classify_ipv4_range(network: ipaddress.IPv4Network) -> str:
    """
    Classify IPv4 network range and return message for special ranges.

    Args:
        network: IPv4Network object to classify

    Returns:
        Message string for special ranges, empty string for unicast

    Special ranges:
        - loopback: Loopback address (127.0.0.0/8) → "Loopback - RFC3330"
        - link_local: Link-local address (169.254.0.0/16) → "Link-local - RFC3927"
        - multicast: Multicast address (224.0.0.0/4) → "Multicast - RFC5771"
        - unspecified: Unspecified address (0.0.0.0/8 but not 0.0.0.0/0) → "Unspecified - RFC1122"
        - broadcast: Limited broadcast (255.255.255.255/32) → "Broadcast - RFC919"
    """
    if DEBUG_MODE:
        logger.debug(f"Classifying network: {network}")
    
    # Get the network address for classification
    net_addr = network.network_address

    # Check for specific special ranges
    if net_addr in ipaddress.IPv4Network('127.0.0.0/8'):
        result = f'RFC 3330 Loopback ({REPO_URL}/blob/main/docs/RFC.md#rfc-3330---loopback-addresses)'
    elif net_addr in ipaddress.IPv4Network('169.254.0.0/16'):
        result = f'RFC 3927 Link-local ({REPO_URL}/blob/main/docs/RFC.md#rfc-3927---link-local-addresses)'
    elif net_addr in ipaddress.IPv4Network('224.0.0.0/4'):
        result = f'RFC 5771 Multicast ({REPO_URL}/blob/main/docs/RFC.md#rfc-5771---multicast-addresses)'
    elif net_addr in ipaddress.IPv4Network('0.0.0.0/8') and network.prefixlen > 0:
        # Only classify as unspecified if it's not the default route (0.0.0.0/0)
        result = f'RFC 1122 Unspecified ({REPO_URL}/blob/main/docs/RFC.md#rfc-1122---unspecified-addresses)'
    elif network.network_address == ipaddress.IPv4Address('255.255.255.255'):
        result = f'RFC 919 Broadcast ({REPO_URL}/blob/main/docs/RFC.md#rfc-919---broadcast-address)'
    else:
        result = ''
    
    if DEBUG_MODE:
        logger.debug(f"Network {network} classified as: {result if result else 'unicast'}")
    
    return result


@debug_log
def is_special_range(message: str) -> bool:
    """Check if the message indicates a special range."""
    result = bool(message.strip())
    if DEBUG_MODE:
        logger.debug(f"Message '{message}' indicates special range: {result}")
    return result


def _compute_network_sync(ip: str, prefix: int) -> dict:
    """
    Synchronous version of network computation for use in thread pool.
    
    This is the core computation logic that can be run in a separate thread.
    """
    if DEBUG_MODE:
        logger.debug(f"Starting network computation for {ip}/{prefix}")
    
    # Validate inputs
    validate_ip(ip)
    validate_prefix(str(prefix))

    # Create network object
    net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    total = net.num_addresses

    if DEBUG_MODE:
        logger.debug(f"Network {net} has {total} total addresses")

    # Classify the range
    message = classify_ipv4_range(net)
    is_special = is_special_range(message)

    # Calculate host range
    if is_special:
        # For special ranges, handle differently based on type
        if net.network_address in ipaddress.IPv4Network('127.0.0.0/8'):
            # Loopback: calculate actual host range for the subnet
            if total > 2:
                hostmin = ipaddress.IPv4Address(int(net.network_address) + 1)
                hostmax = ipaddress.IPv4Address(int(net.broadcast_address) - 1)
                hostmin_str = str(hostmin)
                hostmax_str = str(hostmax)
                hosts_str = str(total - 2)
            else:
                hostmin_str = str(net.network_address)
                hostmax_str = str(net.broadcast_address)
                hosts_str = str(total)
            broadcast_str = "*"
        else:
            # For other special ranges, mark host addresses as "*"
            hostmin_str = "*"
            hostmax_str = "*"
            hosts_str = "*"
            broadcast_str = "*"
    elif total > 2:
        hostmin = ipaddress.IPv4Address(int(net.network_address) + 1)
        hostmax = ipaddress.IPv4Address(int(net.broadcast_address) - 1)
        hostmin_str = str(hostmin)
        hostmax_str = str(hostmax)
        hosts_str = str(total - 2)
        broadcast_str = str(net.broadcast_address)
    else:
        hostmin_str = str(net.network_address)
        hostmax_str = str(net.broadcast_address)
        hosts_str = f"{total}*"
        broadcast_str = str(net.broadcast_address)

    result = {
        "network": str(net.network_address),
        "prefix": f"/{prefix}",
        "netmask": str(net.netmask),
        "broadcast": broadcast_str,
        "hostmin": hostmin_str,
        "hostmax": hostmax_str,
        "hosts": hosts_str,
        "comment": message
    }
    
    if DEBUG_MODE:
        logger.debug(f"Computation completed for {ip}/{prefix}: {result}")
    
    return result


async def compute_async(ip: str, prefix: int) -> dict:
    """
    Asynchronous network computation function.
    
    This function runs the computation in a thread pool to avoid blocking
    the main event loop, especially useful for GUI applications.
    
    Args:
        ip: IPv4 address as string
        prefix: CIDR prefix as integer (0-32)

    Returns:
        Dictionary with network parameters
    """
    if DEBUG_MODE:
        logger.debug(f"Starting async computation for {ip}/{prefix}")
    
    # Check cache first
    cached_result = get_cached_result(ip, prefix)
    if cached_result:
        if DEBUG_MODE:
            logger.debug(f"Cache hit for {ip}/{prefix}")
        return cached_result
    
    # Run computation in thread pool
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_executor, _compute_network_sync, ip, prefix)
    
    # Cache the result
    set_cached_result(ip, prefix, result)
    
    if DEBUG_MODE:
        logger.debug(f"Async computation completed for {ip}/{prefix}")
    
    return result


@debug_log
def compute(ip: str, prefix: int) -> dict:
    """
    Core network computation function.

    Args:
        ip: IPv4 address as string
        prefix: CIDR prefix as integer (0-32)

    Returns:
        Dictionary with network parameters:
        - Network: network address
        - Prefix: CIDR prefix with slash
        - Netmask: subnet mask
        - Broadcast: broadcast address (or "*" for special ranges)
        - Hostmin: first usable host (or "*" for special ranges)
        - Hostmax: last usable host (or "*" for special ranges)
        - Hosts: number of usable hosts (or "*" for special ranges)
        - message: message for special ranges (empty for unicast)

    Raises:
        ValueError: if IP or prefix is invalid
    """
    # Check cache first
    cached_result = get_cached_result(ip, prefix)
    if cached_result:
        if DEBUG_MODE:
            logger.debug(f"Cache hit for {ip}/{prefix}")
        return cached_result
    
    # Perform computation
    result = _compute_network_sync(ip, prefix)
    
    # Cache the result
    set_cached_result(ip, prefix, result)
    
    return result


@debug_log
def validate_cidr_format(cidr_str: str) -> tuple[str, str]:
    """
    Validate CIDR format and provide detailed error messages.

    Args:
        cidr_str: CIDR notation string

    Returns:
        Tuple of (ip, prefix_str) if valid

    Raises:
        ValueError: with specific error message about what's wrong
    """
    if DEBUG_MODE:
        logger.debug(f"Validating CIDR format: {cidr_str}")
    
    if not cidr_str or not cidr_str.strip():
        raise ValueError("Empty input. Please provide an address in CIDR format (e.g., 192.168.1.1/24)")

    cidr_str = cidr_str.strip()

    # Check if it contains the slash separator
    if '/' not in cidr_str:
        raise ValueError(f"Missing '/' separator. Expected format: IP/PREFIX (e.g., 192.168.1.1/24), got: {cidr_str}")

    # Split into IP and prefix parts
    parts = cidr_str.split('/')
    if len(parts) != 2:
        raise ValueError(f"Invalid format. Expected exactly one '/' separator, got: {cidr_str}")

    ip_part, prefix_part = parts

    # Validate IP part format
    if not ip_part.strip():
        raise ValueError("IP address part is empty. Expected format: IP/PREFIX (e.g., 192.168.1.1/24)")

    if not prefix_part.strip():
        raise ValueError("Prefix part is empty. Expected format: IP/PREFIX (e.g., 192.168.1.1/24)")

    result = (ip_part.strip(), prefix_part.strip())
    if DEBUG_MODE:
        logger.debug(f"CIDR format validation successful: {result}")
    
    return result


@debug_log
def parse_cidr(cidr_str: str) -> tuple[str, int]:
    """
    Parse CIDR notation (e.g., "192.168.1.1/24") into IP and prefix.

    Args:
        cidr_str: CIDR notation string

    Returns:
        Tuple of (ip, prefix)

    Raises:
        ValueError: if CIDR format is invalid
    """
    if DEBUG_MODE:
        logger.debug(f"Parsing CIDR: {cidr_str}")
    
    # First validate the format and get parts
    ip_part, prefix_part = validate_cidr_format(cidr_str)

    # Validate IP address format
    try:
        validate_ip(ip_part)
    except ValueError as e:
        raise ValueError(f"Invalid IP address '{ip_part}': {str(e)}")

    # Validate prefix
    try:
        prefix = validate_prefix(prefix_part)
    except ValueError as e:
        raise ValueError(f"Invalid prefix '{prefix_part}': {str(e)}")

    result = (ip_part, prefix)
    if DEBUG_MODE:
        logger.debug(f"CIDR parsing successful: {result}")
    
    return result


@debug_log
def compute_from_cidr(cidr_str: str) -> dict:
    """
    Compute network parameters from CIDR notation.

    Args:
        cidr_str: CIDR notation string (e.g., "192.168.1.1/24")

    Returns:
        Dictionary with network parameters

    Raises:
        ValueError: if CIDR format is invalid
    """
    ip, prefix = parse_cidr(cidr_str)
    return compute(ip, prefix)


async def compute_from_cidr_async(cidr_str: str) -> dict:
    """
    Asynchronous version of compute_from_cidr.
    
    Args:
        cidr_str: CIDR notation string (e.g., "192.168.1.1/24")

    Returns:
        Dictionary with network parameters

    Raises:
        ValueError: if CIDR format is invalid
    """
    ip, prefix = parse_cidr(cidr_str)
    return await compute_async(ip, prefix)


def clear_cache() -> None:
    """Clear the computation cache."""
    with _cache_lock:
        _computation_cache.clear()
    if DEBUG_MODE:
        logger.debug("Computation cache cleared")


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics."""
    with _cache_lock:
        return {
            "size": len(_computation_cache),
            "enabled": CACHE_ENABLED,
            "max_workers": MAX_WORKERS
        }


def main():
    pass


if __name__ == '__main__':
    main()
