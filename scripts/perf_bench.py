#!/usr/bin/env python3
"""
Simple HTTP benchmark for list/search/summary endpoints.
"""

import argparse
import statistics
import time
import urllib.parse
import urllib.request


def request_once(url: str) -> float:
    start = time.perf_counter()
    with urllib.request.urlopen(url, timeout=30) as response:
        response.read()
    return (time.perf_counter() - start) * 1000.0


def run_case(url: str, repeat: int) -> None:
    samples = [request_once(url) for _ in range(repeat)]
    p95 = sorted(samples)[max(0, int(repeat * 0.95) - 1)]
    print(f"{url}")
    print(f"  avg={statistics.mean(samples):.2f}ms p95={p95:.2f}ms min={min(samples):.2f}ms max={max(samples):.2f}ms")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark WebShare endpoints")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--path", default="")
    parser.add_argument("--query", default="")
    parser.add_argument("--repeat", type=int, default=20)
    args = parser.parse_args()

    path = args.path.strip("/")
    encoded_path = "/".join(urllib.parse.quote(p) for p in path.split("/") if p)
    list_base = f"{args.base_url}/api/list/{encoded_path}" if encoded_path else f"{args.base_url}/api/list/"

    list_url = f"{list_base}?page=1&page_size=200&sort=name&order=asc&q={urllib.parse.quote(args.query)}"
    search_url = f"{args.base_url}/search?q={urllib.parse.quote(args.query or 'a')}"
    summary_url = f"{args.base_url}/api/dashboard/summary"

    run_case(list_url, args.repeat)
    run_case(search_url, args.repeat)
    run_case(summary_url, args.repeat)


if __name__ == "__main__":
    main()
