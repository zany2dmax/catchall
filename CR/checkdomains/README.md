# checkdomains

`checkdomains` (aka `sitecheck.go`) is a concurrent Go utility for checking whether a list of domains have active websites.  
It probes each domain with HTTP(S) requests, collects DNS/TLS info, and outputs results in CSV or JSONL.  

---

## Features

- **Concurrent scanning** of many domains at once (configurable worker count).
- **DNS diagnostics**: A/AAAA/CNAME lookup.
- **HTTP/HTTPS probing**: tries HTTPS first, then falls back to HTTP.
- **Redirect support**: follows up to 10 redirects.
- **TLS info capture**: issuer, server name, DNS SANs.
- **Active site detection**: considers 2xx–3xx as active.
- **Exclude parked domains**: optional flag to mark GoDaddy-parked pages as inactive.
- **Flexible output**: CSV (default) or JSONL.

---

## Installation

Clone the repo and build:

```bash
git clone https://github.com/yourname/checkdomains.git
cd checkdomains
go build -o checkdomains sitecheck.go
