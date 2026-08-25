# Cloudflare IP Scanner Integration

The scanner is restricted to Cloudflare-owned IP ranges defined in
`cloudflare_ip_scanner.py`.

UI flow:
1. Admin opens **Cloudflare IP Scanner**.
2. Selects an approved Cloudflare CIDR and TCP port.
3. Runs a bounded latency/reachability test.
4. Results are sorted by latency.
5. Admin explicitly selects an IP; automatic insertion into configurations is disabled by default.

Cloudflare publishes its current IP ranges at:
https://www.cloudflare.com/ips/
