#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command-line interface for LanCalc.
"""
import argparse
import json
import logging
import os
import sys
import typing
import traceback
import asyncio
import time


# Configure logging
logging.basicConfig(
    handlers=[logging.StreamHandler(sys.stderr)],
    level=logging.WARNING,
    format='%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s.%(funcName)s) - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from . import __version__ as VERSION
    from . import core
    from . import adapters
except ImportError:
    try:
        from lancalc import __version__ as VERSION
        import core
        import adapters
    except Exception as e:
        logger.warning(f"{type(e).__name__} {str(e)}\n{traceback.format_exc()}")
        VERSION = "0.0.0"

logger.debug(f"LanCalc {VERSION} starting...")


def print_result_stdout(res: typing.Dict[str, str], show_timing: bool = False, timing_info: dict = None) -> None:
    """Print result to stdout in human-readable format."""
    if show_timing and timing_info:
        print(f"⏱️  Computation time: {timing_info.get('computation_time', 0):.3f}ms")
        if timing_info.get('cache_hit'):
            print(f"📋 Cache hit: {timing_info['cache_hit']}")
        print()
    
    for k in ("network", "prefix", "netmask", "broadcast", "hostmin", "hostmax", "hosts"):
        print(f"{k.capitalize()}: {res[k]}")

    # Print comment if present for special ranges
    if res.get("comment"):
        print(f"Comment: {res['comment']}")


def print_result_json(res: typing.Dict[str, str], show_timing: bool = False, timing_info: dict = None) -> None:
    """Print result as valid JSON to stdout."""
    # Filter out type and empty comment fields for cleaner JSON output
    filtered_res = res.copy()
    if filtered_res.get("comment") == "":
        filtered_res.pop("comment", None)
    filtered_res.pop("type", None)
    
    # Add timing information if requested
    if show_timing and timing_info:
        filtered_res["_timing"] = timing_info
    
    print(json.dumps(filtered_res))


def print_internal_ip_info(json_output: bool = False, debug: bool = False) -> None:
    """Print information about detected network interfaces."""
    start_time = time.time()
    
    try:
        if debug:
            logger.debug("Getting internal IP address...")
        
        ip = adapters.get_internal_ip()
        cidr = adapters.get_cidr(ip)
        
        timing_info = {"computation_time": (time.time() - start_time) * 1000}

        if json_output:
            interface_info = {
                "address": ip,
                "prefix": f"/{cidr}",
            }
            if debug:
                interface_info["_timing"] = timing_info
            print(json.dumps(interface_info))
        else:
            if debug:
                print(f"⏱️  Detection time: {timing_info['computation_time']:.3f}ms")
            print(f"Address: {ip}")
            print(f"Prefix: /{cidr}")

    except Exception as e:
        logger.error(f"{type(e).__name__} {str(e)}\n{traceback.format_exc()}")
        error_msg = f"Failed to get internal IP: {e}"
        if json_output:
            error_data = {"error": error_msg}
            if debug:
                error_data["_timing"] = {"computation_time": (time.time() - start_time) * 1000}
            print(json.dumps(error_data))
        else:
            print(error_msg, file=sys.stderr)


def print_external_ip_info(json_output: bool = False, debug: bool = False) -> None:
    """Print information about external/public IP address."""
    start_time = time.time()
    
    try:
        if debug:
            logger.debug("Getting external IP address...")
        
        external_ip = adapters.get_external_ip()
        
        timing_info = {"computation_time": (time.time() - start_time) * 1000}

        if json_output:
            external_info = {
                "external_ip": external_ip,
            }
            if debug:
                external_info["_timing"] = timing_info
            print(json.dumps(external_info))
        else:
            if debug:
                print(f"⏱️  Detection time: {timing_info['computation_time']:.3f}ms")
            print(f"External IP: {external_ip}")

    except Exception as e:
        logger.error(f"{type(e).__name__} {str(e)}\n{traceback.format_exc()}")
        error_msg = f"Failed to get external IP: {e}"
        if json_output:
            error_data = {"error": error_msg}
            if debug:
                error_data["_timing"] = {"computation_time": (time.time() - start_time) * 1000}
            print(json.dumps(error_data))
        else:
            print(error_msg, file=sys.stderr)


async def run_cli_async(address: str, json_output: bool = False, debug: bool = False) -> int:
    """
    Run CLI mode with given address using async computation.

    Args:
        address: IPv4 address in CIDR notation
        json_output: Whether to output JSON format
        debug: Whether to show debug information

    Returns:
        Exit code (0 for success, 1 for error)
    """
    start_time = time.time()
    
    try:
        if debug:
            logger.debug(f"Starting async computation for: {address}")
        
        result = await core.compute_from_cidr_async(address)
        
        computation_time = (time.time() - start_time) * 1000
        timing_info = {
            "computation_time": computation_time,
            "cache_hit": False  # Will be updated if cache was used
        }
        
        # Get cache stats for debug info
        if debug:
            cache_stats = core.get_cache_stats()
            timing_info["cache_stats"] = cache_stats
        
        if json_output:
            print_result_json(result, debug, timing_info)
        else:
            print_result_stdout(result, debug, timing_info)
        return 0

    except ValueError as e:
        logger.error(f"{type(e).__name__} {str(e)}\n{traceback.format_exc()}")
        # Log validation errors to stderr only
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def run_cli(address: str, json_output: bool = False, debug: bool = False) -> int:
    """
    Run CLI mode with given address.

    Args:
        address: IPv4 address in CIDR notation
        json_output: Whether to output JSON format
        debug: Whether to show debug information

    Returns:
        Exit code (0 for success, 1 for error)
    """
    start_time = time.time()
    
    try:
        if debug:
            logger.debug(f"Starting computation for: {address}")
        
        result = core.compute_from_cidr(address)
        
        computation_time = (time.time() - start_time) * 1000
        timing_info = {
            "computation_time": computation_time,
            "cache_hit": False  # Will be updated if cache was used
        }
        
        # Get cache stats for debug info
        if debug:
            cache_stats = core.get_cache_stats()
            timing_info["cache_stats"] = cache_stats
        
        if json_output:
            print_result_json(result, debug, timing_info)
        else:
            print_result_stdout(result, debug, timing_info)
        return 0

    except ValueError as e:
        logger.error(f"{type(e).__name__} {str(e)}\n{traceback.format_exc()}")
        # Log validation errors to stderr only
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def main(argv: typing.Optional[list] = None) -> int:
    """
    Main CLI entry point.

    Args:
        argv: Command line arguments (uses sys.argv[1:] if None)

    Returns:
        Exit code (0 for success, 1 for error)
    """
    if argv is None:
        # Exclude program name when parsing args
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="lancalc",
        description="LanCalc: IPv4 subnet calculator",
        epilog="Examples:\n  lancalc 192.168.1.1/24\n  lancalc 10.0.0.1/8 --json\n  lancalc --external\n  lancalc 192.168.1.1/24 --debug",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "address",
        nargs="?",
        help="IPv4 address in CIDR notation (e.g., 192.168.1.1/24)"
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="Output result in JSON format"
    )
    parser.add_argument("--version", "-v", action="version", version=f"LanCalc {VERSION}")
    parser.add_argument(
        "--internal",
        "-i",
        action="store_true",
        help="Show internal IP address"
    )
    parser.add_argument(
        "--external",
        "-e",
        action="store_true",
        help="Show external/public IP address"
    )
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Enable debug mode with detailed logging and timing information"
    )
    parser.add_argument(
        "--async-mode",
        "-a",
        action="store_true",
        dest="async_mode",
        help="Use asynchronous computation (useful for GUI integration)"
    )
    parser.add_argument(
        "--cache-stats",
        action="store_true",
        help="Show cache statistics and exit"
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear computation cache and exit"
    )

    args = parser.parse_args(argv)

    # Setup debug mode if requested
    if args.debug:
        core.setup_logging(debug=True)
        logger.debug("Debug mode enabled")

    # Handle cache operations
    if args.cache_stats:
        stats = core.get_cache_stats()
        if args.json:
            print(json.dumps(stats))
        else:
            print("Cache Statistics:")
            print(f"  Size: {stats['size']}")
            print(f"  Enabled: {stats['enabled']}")
            print(f"  Max Workers: {stats['max_workers']}")
        return 0

    if args.clear_cache:
        core.clear_cache()
        if not args.json:
            print("Cache cleared successfully")
        return 0

    # Handle multiple info requests
    info_requests = []
    if args.internal:
        info_requests.append(("internal", print_internal_ip_info))
    if args.external:
        info_requests.append(("external", print_external_ip_info))

    # If any info requests, process them
    if info_requests:
        for info_type, print_func in info_requests:
            print_func(args.json, args.debug)
            # Add separator between multiple outputs (except for last one)
            if info_requests.index((info_type, print_func)) < len(info_requests) - 1:
                print()  # Empty line separator
        return 0

    # If address is provided, process it
    if args.address:
        if args.async_mode:
            # Use async computation
            return asyncio.run(run_cli_async(args.address, args.json, args.debug))
        else:
            # Use sync computation
            return run_cli(args.address, args.json, args.debug)

    # For CLI mode without address, show help
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
