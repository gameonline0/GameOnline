# Game Online IP Scanner

The scanner is intentionally restricted to administrator-approved CIDR ranges.

## Setup
Add only IP ranges that you own or are explicitly authorized to test to
`ip_scanner_config.json` under `allowed_cidrs`.

Example:
```json
{
  "allowed_cidrs": ["192.0.2.0/28"],
  "default_port": 443
}
```

The scanner checks TCP reachability and latency on the configured port.
It does not perform Internet-wide discovery or port sweeps.

`auto_apply_to_configs` is disabled by default. A result should be reviewed
before being copied into a configuration.
