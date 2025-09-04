# checkdomains

`checkdomains` (aka `sitecheck.go`) is a concurrent Go utility for checking whether a lisof domains have active websites.
It probes each domain with HTTP(S), collects DNS/TLS information, detects registrar lander/parked pages, and outputs results in CSV or JSONL.

---

## Features

- **Concurrent scanning** of many domains at once (configurable worker count).
- **DNS diagnostics**: A/AAAA/CNAME lookup.
- **HTTP/HTTPS probing**: tries HTTPS first, falls back to HTTP.
- **Redirect support**: follows up to 10 redirects.
- **TLS info capture**: issuer, server name, DNS SANs.
- **Active site detection**: considers 2xx–3xx responses as active.
- **Registrar lander detection**: optional exclusion of GoDaddy-style parked pages (via `-excludeparked`).
- **Flexible output**: CSV (default) or JSONL.
- **Filter output**: optional suppression of excluded/parked rows (`-excludeoutput`).

---

## Installation

Clone and build:

```bash
git clone https://github.com/yourname/checkdomains.git
cd checkdomains
go build -o checkdomains sitecheck.go```

OR run directly without building:
```go run sitecheck.go -in domains.txt -format csv```

##Usage
Prepare a domains.txt file, one domain per line:
```example.com
madeupdomain.com```

##Run via Makefile
```make build      # Build binary into ./sitecheck and copy to ~/bin
make run        # Run the compiled binary
make scan       # Run static analysis (staticcheck)
make lint       # Run linter (golangci-lint)
make clean      # Remove binaries from repo and ~/bin```

##Flags
Flag
Default
Description
-in
stdin
Input file with one domain per line (if omitted, reads from stdin).
-out
stdout
Output file (if omitted, writes to stdout).
-path
/
Path to request (e.g., /, /lander).
-timeout
7s
Per-request timeout.
-retries
0
Number of retries per scheme (http/https).
-concurrency
50
Number of concurrent workers.
-format
csv
Output format: csv or jsonl.
-useragent
string
Custom User-Agent header.
-excludeparked
false
If true, checks for registrar “lander” pages and marks them excluded.
-exclude-substr
(list)
Comma-separated substrings for parked detection. Defaults include:godaddy, wsimg.com, secureservercdn.net, godaddysites.com, myftpupload.com.
-excludeoutput
false
Suppress output of rows flagged as excluded/parked.

## Examples
basic Run
```go run sitecheck.go -in domains.txt -format csv > results.csv```
