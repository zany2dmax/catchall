# checkdomains

`checkdomains` (aka `sitecheck.go`) is a concurrent Go utility for checking whether a list of domains have active websites and optional email/DNS posture.

It probes each domain with HTTP(S), collects DNS/TLS information, detects registrar lander/parked pages, and can optionally evaluate MX, SPF, DMARC, DKIM, and SMTP banner responses.

---

## Features

- Concurrent scanning (configurable worker count)
- DNS diagnostics (A / AAAA / CNAME)
- Active website detection (HTTP/HTTPS, redirect aware)
- TLS certificate inspection
- Registrar parked/lander detection (`-excludeparked`)
- Optional suppression of parked rows (`-excludeoutput`)
- Optional email/DNS posture checks:
  - MX record detection
  - Strict MX validation (`-mxstrict`)
  - SPF detection
  - DMARC detection
  - DKIM selector probing
  - Optional SMTP banner check
- CSV (default) or JSONL output

---

## Installation

Build locally:

    go build -o sitecheck sitecheck.go

Or run directly:

    go run sitecheck.go -in domains.txt -format csv

---

## Usage

Create a domains.txt file (one domain per line):

    example.com
    google.com
    madeupdomain.com

Basic run:

    go run sitecheck.go -in domains.txt -format csv > results.csv

---

## Email / DNS Checks

Enable full email posture analysis:

    go run sitecheck.go -in domains.txt -format csv -checkemail

Require MX to consider domain active:

    go run sitecheck.go -checkemail -requiremx

Require MX host resolution:

    go run sitecheck.go -checkemail -mxstrict

Check SMTP banner on first resolvable MX:

    go run sitecheck.go -checkemail -smtp

---

## Parked Domain Detection

Detect registrar lander pages:

    go run sitecheck.go -excludeparked

Suppress parked domains from output:

    go run sitecheck.go -excludeparked -excludeoutput

Override parked detection substrings:

    go run sitecheck.go -excludeparked -exclude-substr "godaddy,wsimg.com"

---

## Flags

-in               Input file (default stdin)
-out              Output file (default stdout)
-path             Path to request (default /)
-timeout          Per-request timeout (default 7s)
-retries          Retries per scheme
-concurrency      Worker count (default 50)
-format           csv or jsonl
-useragent        Custom User-Agent
-excludeparked    Detect registrar lander pages
-exclude-substr   Override parked detection substrings
-excludeoutput    Suppress excluded parked rows

Email / DNS flags:
-checkemail       Enable MX/SPF/DMARC/DKIM checks
-requiremx        Mark inactive if no MX
-mxstrict         Require MX host to resolve
-smtp             Attempt SMTP banner check
-smtp-port        SMTP port (default 25)
-smtp-timeout     SMTP connection timeout
-dkim-selectors   Comma-separated selectors to probe
-max-dkim         Max DKIM records to store

---

## Notes

- When -excludeparked is OFF, HTTP requests use Range headers for speed.
- When -excludeparked is ON, full responses (up to 1 MiB) are read.
- This is a reachability + posture tool, not a full vulnerability scanner.
- DNS-based email checks rely on public DNS resolution.

---

License: MIT
