// sitecheck.go
// Concurrent checker to see if domains have an active website.
//
// Usage example:
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
	"io/ioutil"
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

// When excluding parked sites, probe a short list of common landing paths.
// Order: the requested -path first, then /lander, then /.
var parkedProbePaths = []string{"/lander", "/"}

func buildProbePaths(reqPath string) []string {
	// Deduplicate while preserving order; ensure reqPath is first.
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

	// DNS diagnostics
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

	// Build paths to try. If excludeParked is on, probe a couple of common parked paths too.
	paths := []string{reqPath}
	if excludeParked {
		paths = buildProbePaths(reqPath)
	}

	var lastR Result
	for _, p := range paths {
		// Try HTTPS first
		r := tryOne(domain, "https", p, timeout, retries, ua)
		// If HTTPS didn't yield anything meaningful, try HTTP
		if !(r.Active || r.Status > 0 || r.Error == "") {
			// do nothing; but we still try HTTP below
		}
		if !(r.Active || r.Status > 0) {
			r2 := tryOne(domain, "http", p, timeout, retries, ua)
			// Prefer r2 if it has any signal
			if r2.Active || r2.Status > 0 || (r2.Error != "" && r.Error == "") {
				r = r2
			}
		}

		// If we detected a parked page, return immediately (this is the point of the multi-path probe).
		if r.ExcludedParked {
			mergeResult(&res, r)
			return res
		}

		// If we found an active site (not parked), return it.
		if r.Active {
			mergeResult(&res, r)
			return res
		}

		// Otherwise, keep the most recent result to return if nothing better shows up.
		lastR = r
	}

	// Nothing active (or only parked) was found; return the last observed result (includes status/error/URL).
	mergeResult(&res, lastR)
	return res
}

func tryOne(domain, scheme, reqPath string, timeout time.Duration, retries int, ua string) Result {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // we'll record cert, not validate for reachability
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
		// Only use a tiny range when we are NOT scanning for parked content.
		// When excludeParked is on, fetch a normal response so we can inspect enough of the HTML.
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

		// Read some of the body so we can search for "godaddy"
		bodyBytes, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		bodyStr := strings.ToLower(string(bodyBytes))

		rr := Result{
			Domain:   domain,
			Scheme:   scheme,
			Status:   resp.StatusCode,
			Active:   resp.StatusCode >= 200 && resp.StatusCode <= 399,
			FinalURL: resp.Request.URL.String(),
			RespTime: time.Since(start),
		}
		// If excludeParked flag is set, and the body contains "godaddy", mark it as excluded
		if excludeParked && strings.Contains(bodyStr, "godaddy") {
			rr.Active = false
			rr.ExcludedParked = true
		}
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
		return rr
	}

	return Result{Domain: domain, Scheme: scheme, Error: lastErrString(lastErr)}
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

func writeCSV(w io.Writer, ch <-chan Result) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"domain", "dns_ok", "has_a", "has_aaaa", "cname", "scheme", "status", "active", "final_url", "response_time_ms", "tls_server_name", "tls_issuer", "error", "excluded_parked"})
	for r := range ch {
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
		_ = enc.Encode(r)
	}
}
