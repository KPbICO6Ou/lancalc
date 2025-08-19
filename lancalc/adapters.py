#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
External system adapters for LanCalc.

This module handles all external interactions:
- Network interface detection
- External IP retrieval
- System-specific network operations
"""
import json
import logging
import socket
import subprocess
import sys
import platform
import re
import traceback
import urllib.request
import urllib.error
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any


logging.basicConfig(
    handlers=[logging.StreamHandler(sys.stderr)],
    level=logging.WARNING,
    format="%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s.%(funcName)s) - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Thread pool for async operations
_network_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="NetworkAdapter")


def get_internal_ip() -> str:
    """Return the primary local IPv4 address without external libs."""
    start_time = time.time()
    
    try:
        logger.debug("Detecting internal IP address...")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            logger.debug(f"Internal IP detected via socket: {ip}")
            return ip
        except Exception as e:
            logger.warning(f"Socket method failed: {e}")
            # Fallback: hostname resolution (may return 127.0.0.1 in some setups)
            try:
                ip = socket.gethostbyname(socket.gethostname())
                logger.debug(f"Internal IP detected via hostname: {ip}")
                return ip
            except Exception as e:
                logger.error(f"Hostname method failed: {e}")
                logger.debug("Using fallback IP: 127.0.0.1")
                return "127.0.0.1"
        finally:
            s.close()
    except Exception as e:
        logger.error(f"Internal IP detection failed: {type(e).__name__} {str(e)}")
        return "127.0.0.1"
    finally:
        elapsed = (time.time() - start_time) * 1000
        logger.debug(f"Internal IP detection completed in {elapsed:.2f}ms")


async def get_internal_ip_async() -> str:
    """Asynchronous version of get_internal_ip."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_network_executor, get_internal_ip)


def get_external_ip() -> str:
    """Return the external/public IPv4 address using ifconfig.me service."""
    start_time = time.time()
    
    try:
        logger.debug("Retrieving external IP address...")
        
        # Use ifconfig.me service to get external IP
        with urllib.request.urlopen("https://ifconfig.me/ip", timeout=10) as response:
            external_ip = response.read().decode("utf-8").strip()
            # Basic validation that it looks like an IP
            if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", external_ip):
                raise ValueError(f"Invalid IP format returned: {external_ip}")
            
            elapsed = (time.time() - start_time) * 1000
            logger.debug(f"External IP retrieved: {external_ip} in {elapsed:.2f}ms")
            return external_ip

    except urllib.error.URLError as e:
        logger.error(
            f"Failed to get external IP from ifconfig.me: {type(e).__name__} {str(e)}"
        )
        raise ValueError("Failed to retrieve external IP address") from e
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error getting external IP: {e.code} {e.reason}")
        raise ValueError("Failed to retrieve external IP address") from e
    except socket.timeout as e:
        logger.error(f"Timeout getting external IP: {str(e)}")
        raise ValueError("Timeout retrieving external IP address") from e
    except Exception as e:
        logger.error(
            f"Unexpected error getting external IP: {type(e).__name__} {str(e)}"
        )
        raise ValueError("Failed to retrieve external IP address") from e


async def get_external_ip_async() -> str:
    """Asynchronous version of get_external_ip."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_network_executor, get_external_ip)


def cidr_from_netmask(mask: str) -> int:
    """Convert netmask to CIDR prefix."""
    start_time = time.time()
    
    try:
        logger.debug(f"Converting netmask to CIDR: {mask}")
        
        parts = [int(x) for x in mask.split(".")]
        if len(parts) != 4:
            raise ValueError(f"Invalid netmask format: {mask}")

        # Validate netmask (must be consecutive 1s followed by 0s)
        binary = "".join(f"{p:08b}" for p in parts)
        if "01" in binary:  # Check for 1s after 0s
            raise ValueError(f"Invalid netmask: {mask}")

        cidr = sum(bin(p).count("1") for p in parts)
        
        elapsed = (time.time() - start_time) * 1000
        logger.debug(f"Netmask {mask} converted to CIDR /{cidr} in {elapsed:.2f}ms")
        return cidr
        
    except Exception as e:
        logger.error(f"Netmask conversion failed: {type(e).__name__} {str(e)}")
        raise ValueError(f"Invalid netmask: {mask}") from e


def get_cidr(ip: str) -> int:
    """Best-effort CIDR detection using system tools; defaults to /24."""
    start_time = time.time()
    
    try:
        logger.debug(f"Detecting CIDR for IP: {ip}")
        
        system = platform.system()
        
        if system == "Linux":
            # Linux: use ip route
            try:
                result = subprocess.run(
                    ["ip", "route", "get", ip],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Parse output like: "192.168.1.0/24 dev eth0 src 192.168.1.100 uid 1000"
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", result.stdout)
                    if match:
                        cidr = int(match.group(2))
                        elapsed = (time.time() - start_time) * 1000
                        logger.debug(f"CIDR detected via ip route: /{cidr} in {elapsed:.2f}ms")
                        return cidr
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                logger.warning(f"ip route failed: {e}")
            
            # Fallback: try ifconfig/ipconfig
            try:
                result = subprocess.run(
                    ["ifconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Parse ifconfig output for netmask
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'netmask' in line.lower():
                            match = re.search(r"netmask\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                            if match:
                                netmask = match.group(1)
                                cidr = cidr_from_netmask(netmask)
                                elapsed = (time.time() - start_time) * 1000
                                logger.debug(f"CIDR detected via ifconfig: /{cidr} in {elapsed:.2f}ms")
                                return cidr
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                logger.warning(f"ifconfig failed: {e}")
        
        elif system == "Darwin":  # macOS
            try:
                result = subprocess.run(
                    ["ifconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Parse ifconfig output for netmask
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'netmask' in line.lower():
                            match = re.search(r"netmask\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                            if match:
                                netmask = match.group(1)
                                cidr = cidr_from_netmask(netmask)
                                elapsed = (time.time() - start_time) * 1000
                                logger.debug(f"CIDR detected via ifconfig: /{cidr} in {elapsed:.2f}ms")
                                return cidr
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                logger.warning(f"ifconfig failed: {e}")
        
        elif system == "Windows":
            try:
                result = subprocess.run(
                    ["ipconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Parse ipconfig output for subnet mask
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'subnet mask' in line.lower():
                            match = re.search(r"subnet mask[:\s]+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                            if match:
                                netmask = match.group(1)
                                cidr = cidr_from_netmask(netmask)
                                elapsed = (time.time() - start_time) * 1000
                                logger.debug(f"CIDR detected via ipconfig: /{cidr} in {elapsed:.2f}ms")
                                return cidr
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                logger.warning(f"ipconfig failed: {e}")
        
        # Default fallback
        logger.debug("Using default CIDR: /24")
        return 24
        
    except Exception as e:
        logger.error(f"CIDR detection failed: {type(e).__name__} {str(e)}")
        return 24
    finally:
        elapsed = (time.time() - start_time) * 1000
        logger.debug(f"CIDR detection completed in {elapsed:.2f}ms")


async def get_cidr_async(ip: str) -> int:
    """Asynchronous version of get_cidr."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_network_executor, get_cidr, ip)


def get_network_info() -> Dict[str, Any]:
    """Get comprehensive network information."""
    start_time = time.time()
    
    try:
        logger.debug("Getting comprehensive network information...")
        
        info = {
            "internal_ip": None,
            "external_ip": None,
            "cidr": None,
            "system": platform.system(),
            "platform": platform.platform(),
        }
        
        # Get internal IP
        try:
            info["internal_ip"] = get_internal_ip()
        except Exception as e:
            logger.warning(f"Failed to get internal IP: {e}")
        
        # Get CIDR if we have internal IP
        if info["internal_ip"]:
            try:
                info["cidr"] = get_cidr(info["internal_ip"])
            except Exception as e:
                logger.warning(f"Failed to get CIDR: {e}")
        
        # Get external IP (this might take longer)
        try:
            info["external_ip"] = get_external_ip()
        except Exception as e:
            logger.warning(f"Failed to get external IP: {e}")
        
        elapsed = (time.time() - start_time) * 1000
        logger.debug(f"Network info collected in {elapsed:.2f}ms")
        
        return info
        
    except Exception as e:
        logger.error(f"Network info collection failed: {type(e).__name__} {str(e)}")
        return {
            "error": str(e),
            "system": platform.system(),
            "platform": platform.platform(),
        }


async def get_network_info_async() -> Dict[str, Any]:
    """Asynchronous version of get_network_info."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_network_executor, get_network_info)


def validate_network_connectivity() -> Dict[str, bool]:
    """Validate network connectivity to various services."""
    start_time = time.time()
    
    try:
        logger.debug("Validating network connectivity...")
        
        results = {
            "local_network": False,
            "internet": False,
            "dns": False,
        }
        
        # Test local network connectivity
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            s.close()
            results["local_network"] = True
            logger.debug("Local network connectivity: OK")
        except Exception as e:
            logger.warning(f"Local network connectivity failed: {e}")
        
        # Test DNS resolution
        try:
            socket.gethostbyname("google.com")
            results["dns"] = True
            logger.debug("DNS resolution: OK")
        except Exception as e:
            logger.warning(f"DNS resolution failed: {e}")
        
        # Test internet connectivity
        try:
            with urllib.request.urlopen("https://httpbin.org/get", timeout=5) as response:
                if response.status == 200:
                    results["internet"] = True
                    logger.debug("Internet connectivity: OK")
        except Exception as e:
            logger.warning(f"Internet connectivity failed: {e}")
        
        elapsed = (time.time() - start_time) * 1000
        logger.debug(f"Network connectivity validation completed in {elapsed:.2f}ms")
        
        return results
        
    except Exception as e:
        logger.error(f"Network connectivity validation failed: {type(e).__name__} {str(e)}")
        return {
            "local_network": False,
            "internet": False,
            "dns": False,
            "error": str(e)
        }


async def validate_network_connectivity_async() -> Dict[str, bool]:
    """Asynchronous version of validate_network_connectivity."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_network_executor, validate_network_connectivity)
