# checkdomains

`checkdomains` (aka `sitecheck.go`) is a concurrent Go utility for checking whether a list of domains have active websites.  
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
go build -o checkdomains sitecheck.go
```

Or run directly without building:

```bash
go run sitecheck.go -in domains.txt -format csv
```

---

## Usage

Prepare a `domains.txt` file, one domain per line:

```text
example.com
builderspecialties.net
google.com
```

Run the checker:

```bash
go run sitecheck.go -in domains.txt -format csv > results.csv
```

---

## Run via Makefile

A `Makefile` is included for convenience:

```make
make build      # Build binary into ./sitecheck and copy to ~/bin
make run        # Run the compiled binary
make scan       # Run static analysis (staticcheck)
make lint       # Run linter (golangci-lint)
make clean      # Remove binaries from repo and ~/bin
```

---

## Flags

| Flag              | Default | Description                                                                 |
|-------------------|---------|-----------------------------------------------------------------------------|
| `-in`             | stdin   | Input file with one domain per line (if omitted, reads from stdin).         |
| `-out`            | stdout  | Output file (if omitted, writes to stdout).                                 |
| `-path`           | `/`     | Path to request (e.g., `/`, `/lander`).                                     |
| `-timeout`        | `7s`    | Per-request timeout.                                                        |
| `-retries`        | `0`     | Number of retries per scheme (http/https).                                  |
| `-concurrency`    | `50`    | Number of concurrent workers.                                               |
| `-format`         | `csv`   | Output format: `csv` or `jsonl`.                                            |
| `-useragent`      | string  | Custom User-Agent header.                                                   |
| `-excludeparked`  | `false` | If true, checks for registrar “lander” pages and marks them excluded.       |
| `-exclude-substr` | *(list)*| Comma-separated substrings for parked detection. Defaults include:<br>`godaddy, wsimg.com, secureservercdn.net, godaddysites.com, myftpupload.com`. |
| `-excludeoutput`  | `false` | Suppress output of rows flagged as excluded/parked.                         |

---

## Examples

### Basic run

```bash
go run sitecheck.go -in domains.txt -format csv > results.csv
```

### Detect and mark registrar parked pages

```bash
go run sitecheck.go -in domains.txt -format csv -excludeparked > results.csv
```

Sample output (CSV):

```
domain,dns_ok,has_a,has_aaaa,cname,scheme,status,active,final_url,response_time_ms,tls_server_name,tls_issuer,error,excluded_parked
builderspecialties.net,true,true,false,,https,200,false,https://www.builderspecialties.net/lander,250,www.builderspecialties.net,R3,,true
```

### Suppress parked rows entirely

```bash
go run sitecheck.go -in domains.txt -format csv -excludeparked -excludeoutput > results.csv
```

Now only non-parked results are written.

### Override parked detection substrings

```bash
go run sitecheck.go -in domains.txt -format csv -excludeparked -exclude-substr "godaddy,bluehost,sedo,examplecdn.com" > results.csv
```

### JSONL output

```bash
go run sitecheck.go -in domains.txt -excludeparked -format jsonl
```

Output:

```json
{"domain":"builderspecialties.net","dns_ok":true,"has_a":true,"has_aaaa":false,"scheme":"https","status":200,"active":false,"final_url":"https://www.builderspecialties.net/lander","response_time_ms":245,"tls_server_name":"www.builderspecialties.net","tls_issuer":"R3","excluded_parked":true}
```

---

## Parked Domain Exclusion Details

When `-excludeparked` is enabled:

- The tool probes both the **apex** (`domain.com`) and the **www** host (`www.domain.com`).
- It also tries common lander paths (`/lander`, `/`) in addition to your requested `-path`.
- The response HTML, headers, and final URL host are scanned for parked indicators.
- If found, the domain is marked with `excluded_parked=true` and `active=false`.

---

## Notes

- When `-excludeparked` is **off**, the tool uses **Range requests** (fetches only the first bytes) for speed.  
- When `-excludeparked` is **on**, full responses (up to 1 MiB) are read to ensure detection.  
- This is a **reachability checker**, not a full crawler or uptime monitor.  
- Use `-exclude-substr` to customize detection heuristics if you encounter other registrars.

---

## License

MIT
