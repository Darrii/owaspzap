"""
Test suite for VulnerabilityTaxonomy caching functionality.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnerability_chains.core.taxonomy import VulnerabilityTaxonomy


def test_cache_basic():
    """Test that cache is created and works"""
    taxonomy = VulnerabilityTaxonomy()

    # First classification - cache miss
    result1 = taxonomy.classify("SQL Injection")
    cache_info = taxonomy.get_cache_info()
    assert cache_info['misses'] == 1
    assert cache_info['hits'] == 0

    # Second classification - cache hit
    result2 = taxonomy.classify("SQL Injection")
    cache_info = taxonomy.get_cache_info()
    assert cache_info['hits'] == 1
    assert cache_info['misses'] == 1

    # Results should be identical
    assert result1 == result2
    assert result1.specific_type == result2.specific_type

    print("✓ Basic cache test passed")


def test_cache_multiple():
    """Test cache with multiple different vulnerabilities"""
    taxonomy = VulnerabilityTaxonomy()

    vuln_names = [
        "SQL Injection",
        "Cross Site Scripting",
        "Cookie without HttpOnly flag set",
        "Missing X-Frame-Options header",
        "SSRF"
    ]

    # First pass - all misses
    for name in vuln_names:
        taxonomy.classify(name)

    cache_info = taxonomy.get_cache_info()
    assert cache_info['misses'] == 5
    assert cache_info['hits'] == 0

    # Second pass - all hits
    for name in vuln_names:
        taxonomy.classify(name)

    cache_info = taxonomy.get_cache_info()
    assert cache_info['hits'] == 5
    assert cache_info['misses'] == 5
    assert cache_info['hit_rate'] == 0.5

    print("✓ Multiple classification test passed")


def test_cache_clear():
    """Test cache clearing"""
    taxonomy = VulnerabilityTaxonomy()

    # Populate cache
    taxonomy.classify("XSS")
    taxonomy.classify("XSS")  # Hit

    cache_info = taxonomy.get_cache_info()
    assert cache_info['hits'] == 1
    assert cache_info['currsize'] == 1

    # Clear cache
    taxonomy.clear_cache()

    cache_info = taxonomy.get_cache_info()
    assert cache_info['hits'] == 0
    assert cache_info['misses'] == 0
    assert cache_info['currsize'] == 0

    # Classify again - should be miss
    taxonomy.classify("XSS")
    cache_info = taxonomy.get_cache_info()
    assert cache_info['misses'] == 1

    print("✓ Cache clear test passed")


def test_cache_fuzzy_matching():
    """Test that fuzzy matching is also cached"""
    taxonomy = VulnerabilityTaxonomy()

    # Classify a vulnerability name not in exact taxonomy
    name = "Possible SQL Injection Attack Detected"

    result1 = taxonomy.classify(name)
    result2 = taxonomy.classify(name)

    # Both should return same result
    assert result1 is result2  # Same object due to cache

    cache_info = taxonomy.get_cache_info()
    assert cache_info['hits'] >= 1

    print("✓ Fuzzy matching cache test passed")


def test_performance_improvement():
    """Measure cache performance improvement"""
    import time

    taxonomy = VulnerabilityTaxonomy()

    vuln_name = "SQL Injection vulnerability detected"

    # Measure first call (uncached)
    taxonomy.clear_cache()
    start = time.perf_counter()
    for _ in range(1000):
        taxonomy.clear_cache()
        taxonomy.classify(vuln_name)
    uncached_time = time.perf_counter() - start

    # Measure cached calls
    taxonomy.clear_cache()
    taxonomy.classify(vuln_name)  # Prime cache
    start = time.perf_counter()
    for _ in range(1000):
        taxonomy.classify(vuln_name)
    cached_time = time.perf_counter() - start

    speedup = uncached_time / cached_time if cached_time > 0 else float('inf')

    print(f"✓ Performance test:")
    print(f"  Uncached: {uncached_time*1000:.2f}ms for 1000 calls")
    print(f"  Cached:   {cached_time*1000:.2f}ms for 1000 calls")
    print(f"  Speedup:  {speedup:.1f}×")

    # Cache should be significantly faster
    assert speedup > 10, f"Expected >10× speedup, got {speedup:.1f}×"


if __name__ == "__main__":
    print("Running Taxonomy Cache Tests\n")

    test_cache_basic()
    test_cache_multiple()
    test_cache_clear()
    test_cache_fuzzy_matching()
    test_performance_improvement()

    print("\n✅ All tests passed!")
