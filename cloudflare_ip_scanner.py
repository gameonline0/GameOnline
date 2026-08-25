"""
Game Online - Cloudflare IP Quality Scanner

Scans only administrator-approved Cloudflare IP ranges.
The scanner tests TCP reachability/latency on a configured port.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

CLOUDFLARE_IPV4 = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

CLOUDFLARE_IPV6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

DEFAULT_TIMEOUT = 1.5
DEFAULT_MAX_HOSTS = 256


def cloudflare_networks(version: int = 4):
    ranges = CLOUDFLARE_IPV4 if version == 4 else CLOUDFLARE_IPV6
    return [ipaddress.ip_network(x) for x in ranges]


def expand_cloudflare_targets(cidr: str, max_hosts: int = DEFAULT_MAX_HOSTS):
    requested = ipaddress.ip_network(cidr, strict=False)
    if not any(requested.subnet_of(net) for net in cloudflare_networks(requested.version)):
        raise ValueError("The requested range is not an approved Cloudflare range.")
    hosts = list(requested.hosts())
    if len(hosts) > max_hosts:
        raise ValueError(f"Range contains {len(hosts)} hosts; limit is {max_hosts}.")
    return [str(ip) for ip in hosts]


def check_ip(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    started = time.perf_counter()
    reachable = False
    error = None
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            reachable = True
    except OSError as exc:
        error = str(exc)
    return {
        "ip": ip,
        "provider": "Cloudflare",
        "port": port,
        "reachable": reachable,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "error": error,
    }


def scan(cidr: str, port: int, timeout: float = DEFAULT_TIMEOUT,
         max_hosts: int = DEFAULT_MAX_HOSTS, workers: int = 16):
    targets = expand_cloudflare_targets(cidr, max_hosts=max_hosts)
    if not (1 <= int(port) <= 65535):
        raise ValueError("Invalid TCP port.")
    workers = max(1, min(int(workers), 32))
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_ip, ip, int(port), timeout) for ip in targets]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda x: (not x["reachable"], x["latency_ms"], x["ip"]))


def best(results, limit: int = 5):
    good = [r for r in results if r["reachable"]]
    return sorted(good, key=lambda r: r["latency_ms"])[:max(1, int(limit))]
