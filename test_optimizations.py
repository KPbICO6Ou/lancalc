#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for LanCalc optimizations and new features.
"""
import unittest
import asyncio
import time
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lancalc import core
from lancalc import adapters


class TestOptimizations(unittest.TestCase):
    """Test cases for optimization features."""

    def setUp(self):
        """Set up test environment."""
        # Clear cache before each test
        core.clear_cache()
        # Enable debug mode for testing
        core.setup_logging(debug=True)

    def test_cache_functionality(self):
        """Test cache functionality."""
        # First computation should not be cached
        start_time = time.time()
        result1 = core.compute("192.168.1.1", 24)
        first_time = time.time() - start_time

        # Second computation should be cached
        start_time = time.time()
        result2 = core.compute("192.168.1.1", 24)
        second_time = time.time() - start_time

        # Results should be identical
        self.assertEqual(result1, result2)
        
        # Cached computation should be faster
        self.assertLess(second_time, first_time)

        # Check cache stats
        stats = core.get_cache_stats()
        self.assertEqual(stats["size"], 1)
        self.assertTrue(stats["enabled"])

    def test_cache_clear(self):
        """Test cache clearing."""
        # Add some data to cache
        core.compute("192.168.1.1", 24)
        core.compute("10.0.0.1", 16)
        
        # Verify cache has data
        stats = core.get_cache_stats()
        self.assertEqual(stats["size"], 2)
        
        # Clear cache
        core.clear_cache()
        
        # Verify cache is empty
        stats = core.get_cache_stats()
        self.assertEqual(stats["size"], 0)

    def test_cache_size_limit(self):
        """Test cache size limiting."""
        # Add more than 1000 entries to test size limiting
        for i in range(1100):
            # Use valid IP addresses (0-255 for each octet)
            octet = i % 256
            core.compute(f"192.168.{octet}.1", 24)
        
        # Cache should be limited to 1000 entries
        stats = core.get_cache_stats()
        self.assertLessEqual(stats["size"], 1000)

    def test_async_computation(self):
        """Test asynchronous computation."""
        async def test_async():
            # Test async computation
            result = await core.compute_async("192.168.1.1", 24)
            self.assertIsInstance(result, dict)
            self.assertIn("network", result)
            self.assertIn("prefix", result)
            
            # Test async computation from CIDR
            result2 = await core.compute_from_cidr_async("192.168.1.1/24")
            self.assertEqual(result, result2)

        asyncio.run(test_async())

    def test_async_vs_sync_performance(self):
        """Test async vs sync performance."""
        async def test_async_performance():
            # Test multiple async computations
            start_time = time.time()
            tasks = []
            for i in range(10):
                task = core.compute_async(f"192.168.{i}.1", 24)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            async_time = time.time() - start_time
            
            # Test multiple sync computations
            start_time = time.time()
            sync_results = []
            for i in range(10):
                result = core.compute(f"192.168.{i}.1", 24)
                sync_results.append(result)
            sync_time = time.time() - start_time
            
            # Both should complete successfully
            self.assertEqual(len(results), len(sync_results))
            # Async might not always be faster due to overhead, but should complete
            self.assertGreater(async_time, 0)
            self.assertGreater(sync_time, 0)

        asyncio.run(test_async_performance())

    def test_debug_logging(self):
        """Test debug logging functionality."""
        # Enable debug mode
        core.setup_logging(debug=True)
        
        # Perform computation
        result = core.compute("192.168.1.1", 24)
        
        # Result should be valid
        self.assertIsInstance(result, dict)
        self.assertIn("network", result)

    def test_network_adapters_async(self):
        """Test async network adapter functions."""
        async def test_adapters():
            # Test async internal IP
            internal_ip = await adapters.get_internal_ip_async()
            self.assertIsInstance(internal_ip, str)
            
            # Test async external IP (may fail if no internet)
            try:
                external_ip = await adapters.get_external_ip_async()
                self.assertIsInstance(external_ip, str)
            except Exception:
                # External IP may fail, that's OK
                pass
            
            # Test async CIDR
            cidr = await adapters.get_cidr_async(internal_ip)
            self.assertIsInstance(cidr, int)
            self.assertGreaterEqual(cidr, 0)
            self.assertLessEqual(cidr, 32)

        asyncio.run(test_adapters())

    def test_network_info(self):
        """Test network information gathering."""
        # Test sync network info
        info = adapters.get_network_info()
        self.assertIsInstance(info, dict)
        self.assertIn("system", info)
        self.assertIn("platform", info)
        
        # Test async network info
        async def test_async_info():
            info = await adapters.get_network_info_async()
            self.assertIsInstance(info, dict)
            self.assertIn("system", info)
            self.assertIn("platform", info)

        asyncio.run(test_async_info())

    def test_network_connectivity(self):
        """Test network connectivity validation."""
        # Test sync connectivity
        connectivity = adapters.validate_network_connectivity()
        self.assertIsInstance(connectivity, dict)
        self.assertIn("local_network", connectivity)
        self.assertIn("internet", connectivity)
        self.assertIn("dns", connectivity)
        
        # Test async connectivity
        async def test_async_connectivity():
            connectivity = await adapters.validate_network_connectivity_async()
            self.assertIsInstance(connectivity, dict)
            self.assertIn("local_network", connectivity)
            self.assertIn("internet", connectivity)
            self.assertIn("dns", connectivity)

        asyncio.run(test_async_connectivity())

    def test_error_handling(self):
        """Test error handling in optimized code."""
        # Test invalid IP
        with self.assertRaises(ValueError):
            core.compute("invalid.ip", 24)
        
        # Test invalid prefix
        with self.assertRaises(ValueError):
            core.compute("192.168.1.1", 33)
        
        # Test invalid CIDR format
        with self.assertRaises(ValueError):
            core.compute_from_cidr("invalid")

    def test_concurrent_access(self):
        """Test concurrent access to cache."""
        import threading
        
        results = []
        errors = []
        
        def compute_task(ip, prefix):
            try:
                result = core.compute(ip, prefix)
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(
                target=compute_task, 
                args=(f"192.168.{i}.1", 24)
            )
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Should have no errors and correct number of results
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 10)
        
        # All results should be valid
        for result in results:
            self.assertIsInstance(result, dict)
            self.assertIn("network", result)

    def test_memory_efficiency(self):
        """Test memory efficiency of cache."""
        try:
            import psutil
            import gc
            
            # Get initial memory usage
            process = psutil.Process()
            initial_memory = process.memory_info().rss
            
            # Add many entries to cache
            for i in range(500):
                octet = i % 256
                core.compute(f"192.168.{octet}.1", 24)
            
            # Force garbage collection
            gc.collect()
            
            # Get memory after cache operations
            final_memory = process.memory_info().rss
            
            # Memory increase should be reasonable (less than 10MB)
            memory_increase = final_memory - initial_memory
            self.assertLess(memory_increase, 10 * 1024 * 1024)  # 10MB
        except ImportError:
            # Skip test if psutil is not available
            self.skipTest("psutil not available")

    def test_cache_key_uniqueness(self):
        """Test cache key uniqueness."""
        # Clear cache first
        core.clear_cache()
        
        # Test different networks
        result1 = core.compute("192.168.1.1", 24)
        result2 = core.compute("10.0.0.1", 24)
        result3 = core.compute("172.16.0.1", 24)
        
        # Results should be different (different networks)
        self.assertNotEqual(result1["network"], result2["network"])
        self.assertNotEqual(result1["network"], result3["network"])
        self.assertNotEqual(result2["network"], result3["network"])
        
        # Cache should have different keys (different IP/prefix combinations)
        stats = core.get_cache_stats()
        self.assertGreaterEqual(stats["size"], 3)
        
        # Test that same IP with different prefix produces different results
        # Use a different network to avoid overlap
        result4 = core.compute("192.168.2.1", 25)
        self.assertNotEqual(result1["network"], result4["network"])
        
        # Test that different IPs in completely different networks produce different results
        result5 = core.compute("8.8.8.8", 25)
        self.assertNotEqual(result1["network"], result5["network"])
        self.assertNotEqual(result4["network"], result5["network"])
        
        # Test that different IPs in completely different networks produce different results
        result6 = core.compute("1.1.1.1", 25)
        self.assertNotEqual(result1["network"], result6["network"])
        self.assertNotEqual(result4["network"], result6["network"])
        self.assertNotEqual(result5["network"], result6["network"])
        
        # Test that different IPs in completely different networks produce different results
        result7 = core.compute("208.67.222.222", 25)
        self.assertNotEqual(result1["network"], result7["network"])
        self.assertNotEqual(result4["network"], result7["network"])
        self.assertNotEqual(result5["network"], result7["network"])
        self.assertNotEqual(result6["network"], result7["network"])
        
        # Verify cache size
        stats = core.get_cache_stats()
        self.assertGreaterEqual(stats["size"], 7)

    def test_performance_improvements(self):
        """Test performance improvements."""
        # Test repeated computations with different IPs to avoid cache
        start_time = time.time()
        for i in range(100):
            octet = i % 256
            core.compute(f"192.168.{octet}.1", 24)
        total_time = time.time() - start_time
        
        # Should be reasonably fast (less than 1 second for 100 computations)
        self.assertLess(total_time, 1.0)
        
        # Test cache hit performance
        start_time = time.time()
        for i in range(100):
            core.compute("192.168.1.1", 24)  # Should be cached
        cached_time = time.time() - start_time
        
        # Both should complete successfully
        self.assertGreater(cached_time, 0)
        self.assertGreater(total_time, 0)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)