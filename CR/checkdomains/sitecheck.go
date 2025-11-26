// sitecheck.go
// Concurrent checker to see if domains have an active website.
//
// Usage example: (test)
//
//	go run sitecheck.go -in domains.txt -out results.csv
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Domain         string        `json:"domain"`
	DNSOK          bool          `json:"dns_ok"`
	HasA           bool          `json:"has_a"`
	HasAAAA        bool          `json:"has_aaaa"`
	CNAME          string        `json:"cname,omitempty"`
	Scheme         string        `json:"scheme"`
	Status         int           `json:"status"`
	Active         bool          `json:"active"`
	FinalURL       string        `json:"final_url,omitempty"`
	RespTime       time.Duration `json:"response_time_ms"`
	TLSServerName  string        `json:"tls_server_name,omitempty"`
	TLSIssuer      string        `json:"tls_issuer,omitempty"`
	TLSDNSNames    []string      `json:"tls_dns_names,omitempty"`
	Error          string        `json:"error,omitempty"`
	ExcludedParked bool          `json:"excluded_parked,omitempty"`
}

type job struct{ domain string }

var excludeParked bool

// Default substrings that commonly appear on GoDaddy parked / builder pages.
// We scan both HTML body and response headers for these.
var defaultParkedIndicators = []string{
	"godaddy",
	"wsimg.com",
	"secureservercdn.net",
	"godaddysites.com",
	"myftpupload.com",
}
var excludeSubstrCSV string // optional user override like: "godaddy,wsimg.com"
var suppressExcluded bool

// Try common parked landing paths when -excludeparked is enabled.
var parkedProbePaths = []string{"/lander", "/"}

// Build the list of paths to probe (dedup, preserve order)
func buildProbePaths(reqPath string) []string {
	seen := make(map[string]bool, 3)
	out := make([]string, 0, 3)
	add := func(p string) {
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add(reqPath)
	for _, p := range parkedProbePaths {
		add(p)
	}
	return out
}

// Build the list of hostnames to probe for the given domain.
// When -excludeparked is on, also try the www. prefix, since many registrars park on www.
func buildProbeHosts(domain string) []string {
	if !excludeParked {
		return []string{domain}
	}
	hosts := []string{}
	if !strings.HasPrefix(strings.ToLower(domain), "www.") {
		hosts = append(hosts, "www."+domain)
	}
	hosts = append(hosts, domain)
	return hosts
}

func main() {
	in := flag.String("in", "", "input file of domains (default: stdin)")
	out := flag.String("out", "", "output file (default: stdout)")
	path := flag.String("path", "/", "path to request")
	timeout := flag.Duration("timeout", 7*time.Second, "per-request timeout")
	retries := flag.Int("retries", 0, "retries per scheme")
	conc := flag.Int("concurrency", 50, "number of workers")
	format := flag.String("format", "csv", "output format: csv or jsonl")
	ua := flag.String("useragent", "sitecheck/1.0 (+https://example.local)", "User-Agent header")
	flag.BoolVar(&excludeParked, "excludeparked", false, "exclude parked pages containing 'godaddy'")
	flag.StringVar(&excludeSubstrCSV, "exclude-substr", "", "comma-separated substrings to treat as parked indicators (overrides defaults)")
	flag.BoolVar(&suppressExcluded, "excludeoutput", false, "suppress output of parked/excluded rows")
	flag.Parse()

	domains, err := readDomains(*in)
	if err != nil {
		fatalf("read input: %v", err)
	}
	if len(domains) == 0 {
		fatalf("no domains provided")
	}

	outw, closer, err := writerFor(*out)
	if err != nil {
		fatalf("open output: %v", err)
	}
	defer closer()

	resCh := make(chan Result, len(domains))
	wg := &sync.WaitGroup{}

	jobs := make(chan job)
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				resCh <- checkDomain(j.domain, *path, *timeout, *retries, *ua)
			}
		}()
	}

	go func() {
		for _, d := range domains {
			jobs <- job{domain: d}
		}
		close(jobs)
		wg.Wait()
		close(resCh)
	}()

	switch strings.ToLower(*format) {
	case "csv":
		writeCSV(outw, resCh)
	case "jsonl":
		writeJSONL(outw, resCh)
	default:
		fatalf("unknown format: %s", *format)
	}
}
func buildIndicators() []string {
	if strings.TrimSpace(excludeSubstrCSV) == "" {
		return defaultParkedIndicators
	}
	parts := strings.Split(excludeSubstrCSV, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
func fatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func readDomains(path string) ([]string, error) {
	var r io.Reader
	if path == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		r = f
		defer f.Close()
	}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []string
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if u, err := url.Parse(line); err == nil && u.Host != "" {
			line = u.Host
		}
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		line = strings.Split(line, "/")[0]
		out = append(out, line)
	}
	return out, s.Err()
}

func writerFor(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	return f, func() { _ = f.Close() }, nil
}

func checkDomain(domain, reqPath string, timeout time.Duration, retries int, ua string) Result {
	res := Result{Domain: domain}

	// DNS diagnostics (for the base domain only)
	cname, _ := net.LookupCNAME(domain)
	if cname != "" && !strings.EqualFold(cname, domain+".") {
		res.CNAME = strings.TrimSuffix(cname, ".")
	}
	if addrs, err := net.LookupIP(domain); err == nil {
		res.DNSOK = true
		for _, a := range addrs {
			if a.To4() != nil {
				res.HasA = true
			}
			if a.To16() != nil && a.To4() == nil {
				res.HasAAAA = true
			}
		}
	}

	hosts := buildProbeHosts(domain)
	paths := []string{reqPath}
	if excludeParked {
		paths = buildProbePaths(reqPath)
	}

	var last Result
	var bestActive *Result

	for _, h := range hosts {
		for _, p := range paths {
			// HTTPS first
			r := tryOne(h, "https", p, timeout, retries, ua)
			if !(r.Active || r.Status > 0) {
				// then HTTP
				r2 := tryOne(h, "http", p, timeout, retries, ua)
				if r2.Active || r2.Status > 0 || (r2.Error != "" && r.Error == "") {
					r = r2
				}
			}

			// If we detected a parked page, return immediately.
			if r.ExcludedParked {
				mergeResult(&res, r)
				return res
			}

			if r.Active {
				if !excludeParked {
					// In normal mode, return the first active we find.
					mergeResult(&res, r)
					return res
				}
				// In excludeParked mode, remember the active result but keep probing
				// other host×path combos to see if any are parked.
				tmp := r
				bestActive = &tmp
			}

			last = r
		}
	}

	// If no parked pages found, prefer an active result if we saw one.
	if bestActive != nil {
		mergeResult(&res, *bestActive)
		return res
	}

	// Nothing active (or only errors) found; return the last observation.
	mergeResult(&res, last)
	return res
}

// isParked returns true if the response looks like a GoDaddy parked/builder page.
// We scan the HTML body and key headers for common GoDaddy asset/host markers.
// To reduce false positives from just a GoDaddy-issued cert, we only use the TLS issuer
// as a *weak* signal (i.e., require at least one content/header match as well).
func isParked(bodyLower string, resp *http.Response, tlsIssuer string, indicators []string) bool {
	// 1) Body check
	for _, k := range indicators {
		if strings.Contains(bodyLower, k) {
			return true
		}
	}

	// 2) Header check (common places where CDNs/hosts appear)
	//    We concatenate header values and scan once.
	var hdrBuf strings.Builder
	// A few likely headers:
	for _, h := range []string{"Content-Security-Policy", "Link", "Set-Cookie", "Referrer-Policy", "Report-To"} {
		if v := resp.Header.Get(h); v != "" {
			hdrBuf.WriteString(strings.ToLower(v))
			hdrBuf.WriteString("\n")
		}
	}
	headerStr := hdrBuf.String()
	for _, k := range indicators {
		if strings.Contains(headerStr, k) {
			return true
		}
	}

	// 3) Final URL host (some builders redirect to hosted domains)
	if resp.Request != nil && resp.Request.URL != nil {
		host := strings.ToLower(resp.Request.URL.Host)
		for _, k := range indicators {
			if strings.Contains(host, k) {
				return true
			}
		}
	}

	// 4) TLS issuer alone is not enough (many legit sites use GoDaddy CAs),
	//    but if issuer contains "go daddy" *and* we found at least one weak hint
	//    above (already returned), we'd have already returned true. So here it doesn't flip it.
	//    Keep this as a no-op to avoid false positives.

	return false
}

func lastErrString(err error) string {
	if err == nil {
		return ""
	}
	// shorten common noise
	msg := err.Error()
	msg = strings.ReplaceAll(msg, "Get \"", "")
	msg = strings.ReplaceAll(msg, "\"", "")
	return msg
}

func mergeResult(dst *Result, src Result) {
	dst.Scheme = src.Scheme
	dst.Status = src.Status
	dst.Active = src.Active
	dst.FinalURL = src.FinalURL
	dst.RespTime = src.RespTime
	dst.TLSServerName = src.TLSServerName
	dst.TLSIssuer = src.TLSIssuer
	dst.TLSDNSNames = src.TLSDNSNames
	dst.Error = src.Error
	dst.ExcludedParked = src.ExcludedParked
}
func tryOne(domain, scheme, reqPath string, timeout time.Duration, retries int, ua string) Result {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConnsPerHost: 64,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}

	u := &url.URL{Scheme: scheme, Host: domain, Path: reqPath}

	var lastErr error
	start := time.Now()
	for attempt := 0; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		req.Header.Set("User-Agent", ua)
		if !excludeParked {
			req.Header.Set("Range", "bytes=0-65535")
		}
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		// Read up to ~1 MiB so we can search for indicators.
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		bodyStr := strings.ToLower(string(bodyBytes))

		rr := Result{
			Domain:   domain,
			Scheme:   scheme,
			Status:   resp.StatusCode,
			Active:   resp.StatusCode >= 200 && resp.StatusCode <= 399,
			FinalURL: resp.Request.URL.String(),
			RespTime: time.Since(start),
		}

		// Capture TLS details
		if resp.TLS != nil {
			rr.TLSServerName = resp.TLS.ServerName
			if len(resp.TLS.PeerCertificates) > 0 {
				iss := resp.TLS.PeerCertificates[0].Issuer
				rr.TLSIssuer = iss.CommonName
				if rr.TLSIssuer == "" && len(iss.Organization) > 0 {
					rr.TLSIssuer = iss.Organization[0]
				}
			}
			for _, cert := range resp.TLS.PeerCertificates {
				rr.TLSDNSNames = append(rr.TLSDNSNames, cert.DNSNames...)
			}
		}

		// Parked detection (HTML + headers + final URL host)
		if excludeParked {
			if isParked(bodyStr, resp, rr.TLSIssuer, buildIndicators()) {
				rr.Active = false
				rr.ExcludedParked = true
			}
		}

		return rr
	}

	return Result{Domain: domain, Scheme: scheme, Error: lastErrString(lastErr)}
}
func writeCSV(w io.Writer, ch <-chan Result) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"domain", "dns_ok", "has_a", "has_aaaa", "cname", "scheme", "status", "active",
		"final_url", "response_time_ms", "tls_server_name", "tls_issuer", "error", "excluded_parked",
	})
	for r := range ch {
		if suppressExcluded && r.ExcludedParked {
			continue // skip parked rows if suppression is on
		}
		row := []string{
			r.Domain,
			fmt.Sprintf("%t", r.DNSOK),
			fmt.Sprintf("%t", r.HasA),
			fmt.Sprintf("%t", r.HasAAAA),
			r.CNAME,
			r.Scheme,
			fmt.Sprintf("%d", r.Status),
			fmt.Sprintf("%t", r.Active),
			r.FinalURL,
			fmt.Sprintf("%d", r.RespTime.Milliseconds()),
			r.TLSServerName,
			r.TLSIssuer,
			r.Error,
			fmt.Sprintf("%t", r.ExcludedParked),
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}
func writeJSONL(w io.Writer, ch <-chan Result) {
	enc := json.NewEncoder(w)
	for r := range ch {
		if suppressExcluded && r.ExcludedParked {
			continue
		}
		_ = enc.Encode(r)
	}
}
