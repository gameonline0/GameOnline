"""
Game Online - IP Quality Scanner

Safety boundary:
- Scan only IPs/ranges explicitly configured by the administrator.
- No arbitrary Internet-wide scanning.
- Checks a single configured TCP port and measures connection latency.
- Results can be used by the UI to choose an IP from an administrator-approved pool.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

DEFAULT_TIMEOUT = 1.5
DEFAULT_MAX_HOSTS = 256


def expand_targets(cidr: str, max_hosts: int = DEFAULT_MAX_HOSTS) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    if len(hosts) > max_hosts:
        raise ValueError(f"Range contains {len(hosts)} hosts; limit is {max_hosts}.")
    return [str(ip) for ip in hosts]


def check_ip(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    started = time.perf_counter()
    ok = False
    error = None
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            ok = True
    except OSError as exc:
        error = str(exc)
    latency_ms = round((time.perf_counter() - started) * 1000, 1)
    return {
        "ip": ip,
        "port": port,
        "reachable": ok,
        "latency_ms": latency_ms,
        "error": error,
    }


def scan(cidr: str, port: int, timeout: float = DEFAULT_TIMEOUT,
         max_hosts: int = DEFAULT_MAX_HOSTS, workers: int = 16) -> list[dict]:
    if not (1 <= int(port) <= 65535):
        raise ValueError("Invalid TCP port.")
    targets = expand_targets(cidr, max_hosts=max_hosts)
    workers = max(1, min(int(workers), 32))
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_ip, ip, int(port), timeout) for ip in targets]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda x: (not x["reachable"], x["latency_ms"], x["ip"]))


def best(results: Iterable[dict], limit: int = 5) -> list[dict]:
    good = [r for r in results if r.get("reachable")]
    return sorted(good, key=lambda r: r["latency_ms"])[:max(1, int(limit))]
