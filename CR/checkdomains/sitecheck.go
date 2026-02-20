// sitecheck.go
// Concurrent checker to see if domains have an active website (and optional email/DNS posture).
//
// Examples:
//   go run sitecheck.go -in domains.txt -format csv > results.csv
//   go run sitecheck.go -in domains.txt -format csv -excludeparked -excludeoutput > results.csv
//   go run sitecheck.go -in domains.txt -format csv -checkemail -mxstrict -requiremx > results.csv
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
	"sort"
	"strings"
	"sync"
	"time"
)

type Result struct {
	// Web + DNS basics
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

	// Email / DNS posture (optional)
	HasMX          bool     `json:"has_mx"`
	MXHosts        []string `json:"mx_hosts,omitempty"`
	HasSPF         bool     `json:"has_spf,omitempty"`
	SPFRecord      string   `json:"spf_record,omitempty"`
	HasDMARC       bool     `json:"has_dmarc,omitempty"`
	DMARCRecord    string   `json:"dmarc_record,omitempty"`
	HasDKIM        bool     `json:"has_dkim,omitempty"`
	DKIMSelectors  []string `json:"dkim_selectors,omitempty"`
	DKIMRecords    []string `json:"dkim_records,omitempty"`
	SMTPChecked    bool     `json:"smtp_checked,omitempty"`
	SMTPHost       string   `json:"smtp_host,omitempty"`
	SMTPPort       int      `json:"smtp_port,omitempty"`
	SMTPBanner     string   `json:"smtp_banner,omitempty"`
	EmailCheckNote string   `json:"email_check_note,omitempty"`
}

type job struct{ domain string }

var (
	// Parked detection
	excludeParked    bool
	excludeSubstrCSV string
	suppressExcluded bool

	// Email/DNS checks
	checkEmail     bool
	requireMX      bool
	mxStrict       bool
	checkSMTP      bool
	smtpPort       int
	smtpTimeout    time.Duration
	dkimSelectors  string
	maxDKIMRecords int
)

var defaultParkedIndicators = []string{
	"godaddy",
	"wsimg.com",
	"secureservercdn.net",
	"godaddysites.com",
	"myftpupload.com",
}

// Common parked landing paths (when -excludeparked is enabled)
var parkedProbePaths = []string{"/lander", "/"}

func main() {
	in := flag.String("in", "", "input file of domains (default: stdin)")
	out := flag.String("out", "", "output file (default: stdout)")
	path := flag.String("path", "/", "path to request")
	timeout := flag.Duration("timeout", 7*time.Second, "per-request timeout")
	retries := flag.Int("retries", 0, "retries per scheme")
	conc := flag.Int("concurrency", 50, "number of workers")
	format := flag.String("format", "csv", "output format: csv or jsonl")
	ua := flag.String("useragent", "sitecheck/1.0 (+https://example.local)", "User-Agent header")

	// Parked detection + output filtering
	flag.BoolVar(&excludeParked, "excludeparked", false, "detect registrar parked/lander pages and mark them excluded")
	flag.StringVar(&excludeSubstrCSV, "exclude-substr", "", "comma-separated substrings to treat as parked indicators (overrides defaults)")
	flag.BoolVar(&suppressExcluded, "excludeoutput", false, "suppress output rows flagged as excluded_parked=true")

	// Email/DNS posture checks
	flag.BoolVar(&checkEmail, "checkemail", false, "enable MX/SPF/DMARC/DKIM checks (DNS)")
	flag.BoolVar(&requireMX, "requiremx", false, "when -checkemail is enabled, mark Active=false if no MX records are found")
	flag.BoolVar(&mxStrict, "mxstrict", false, "treat MX as 'active' only if MX host resolves to at least one IP")
	flag.BoolVar(&checkSMTP, "smtp", false, "attempt SMTP banner check against first resolvable MX host (requires -checkemail)")
	flag.IntVar(&smtpPort, "smtp-port", 25, "SMTP port for -smtp (commonly 25 or 587)")
	flag.DurationVar(&smtpTimeout, "smtp-timeout", 3*time.Second, "timeout for SMTP banner probe")
	flag.StringVar(&dkimSelectors, "dkim-selectors", "default,selector1,selector2,google,mail,s1,s2",
		"comma-separated DKIM selectors to probe (selector._domainkey.domain TXT)")
	flag.IntVar(&maxDKIMRecords, "max-dkim", 4, "max DKIM records to store (to keep output small)")

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

// Build the list of paths to probe (dedup, preserve order)
func buildProbePaths(reqPath string) []string {
	seen := make(map[string]bool, 4)
	out := make([]string, 0, 4)

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

	if excludeParked {
		// prioritize common parked paths first
		for _, p := range parkedProbePaths {
			add(p)
		}
	}
	add(reqPath)
	return out
}

// Build the list of hostnames to probe for the given domain.
// When -excludeparked is on, try www. first (many registrars park on www).
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

func parseCSVList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	// de-dupe
	seen := map[string]bool{}
	final := []string{}
	for _, p := range out {
		if !seen[p] {
			seen[p] = true
			final = append(final, p)
		}
	}
	return final
}

func checkDomain(domain, reqPath string, timeout time.Duration, retries int, ua string) Result {
	res := Result{Domain: domain}

	// DNS diagnostics (base domain only)
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

	// Email/DNS posture checks (optional)
	if checkEmail {
		populateEmailPosture(&res)
		if requireMX && !res.HasMX {
			// Still do web checks, but consider it not "active" at the end.
			res.EmailCheckNote = "requiremx enabled: no MX records found"
		}
		if checkSMTP && res.HasMX {
			res.SMTPChecked = true
			h, banner, ok := smtpBannerFirst(res.MXHosts, smtpPort, smtpTimeout)
			if ok {
				res.SMTPHost = h
				res.SMTPPort = smtpPort
				res.SMTPBanner = banner
			}
		} else if checkSMTP && !checkEmail {
			res.EmailCheckNote = "smtp enabled without checkemail (ignored)"
		}
	}

	hosts := buildProbeHosts(domain)
	paths := buildProbePaths(reqPath)

	var last Result
	var bestActive *Result

	for _, h := range hosts {
		for _, p := range paths {
			r := tryOne(h, "https", p, timeout, retries, ua)
			if !(r.Active || r.Status > 0) {
				r2 := tryOne(h, "http", p, timeout, retries, ua)
				if r2.Active || r2.Status > 0 || (r2.Error != "" && r.Error == "") {
					r = r2
				}
			}

			if r.ExcludedParked {
				mergeResult(&res, r)
				finalizeActive(&res)
				return res
			}

			if r.Active {
				if !excludeParked {
					mergeResult(&res, r)
					finalizeActive(&res)
					return res
				}
				tmp := r
				bestActive = &tmp
			}

			last = r
		}
	}

	if bestActive != nil {
		mergeResult(&res, *bestActive)
		finalizeActive(&res)
		return res
	}

	mergeResult(&res, last)
	finalizeActive(&res)
	return res
}

// Apply final policy adjustments (e.g., requiremx).
func finalizeActive(res *Result) {
	if checkEmail && requireMX && !res.HasMX {
		res.Active = false
	}
}

func tryOne(domain, scheme, reqPath string, timeout time.Duration, retries int, ua string) Result {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // reachability, not validation
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

		// Speed-up only when not doing parked/content checks
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

		// Read up to ~1 MiB to allow content/header heuristics
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		bodyLower := strings.ToLower(string(bodyBytes))

		rr := Result{
			Domain:   domain,
			Scheme:   scheme,
			Status:   resp.StatusCode,
			Active:   resp.StatusCode >= 200 && resp.StatusCode <= 399,
			FinalURL: resp.Request.URL.String(),
			RespTime: time.Since(start),
		}

		// TLS details
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

		// Parked detection
		if excludeParked {
			if isParked(bodyLower, resp, buildIndicators()) {
				rr.Active = false
				rr.ExcludedParked = true
			}
		}

		return rr
	}

	return Result{Domain: domain, Scheme: scheme, Error: lastErrString(lastErr)}
}

// isParked returns true if the response looks like a registrar parked/builder page.
// We scan HTML body, selected headers, and final URL host for known indicators.
func isParked(bodyLower string, resp *http.Response, indicators []string) bool {
	// Body scan
	for _, k := range indicators {
		if strings.Contains(bodyLower, k) {
			return true
		}
	}

	// Header scan (a few likely headers where CDNs/domains appear)
	var b strings.Builder
	for _, h := range []string{"Content-Security-Policy", "Link", "Set-Cookie", "Referrer-Policy", "Report-To", "Server"} {
		if v := resp.Header.Get(h); v != "" {
			b.WriteString(strings.ToLower(v))
			b.WriteString("\n")
		}
	}
	hdrLower := b.String()
	for _, k := range indicators {
		if strings.Contains(hdrLower, k) {
			return true
		}
	}

	// Final URL host scan (redirects to hosted builder domains)
	if resp.Request != nil && resp.Request.URL != nil {
		host := strings.ToLower(resp.Request.URL.Host)
		for _, k := range indicators {
			if strings.Contains(host, k) {
				return true
			}
		}
	}

	return false
}

func lastErrString(err error) string {
	if err == nil {
		return ""
	}
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
	_ = cw.Write([]string{
		"domain",
		"dns_ok", "has_a", "has_aaaa", "cname",
		"has_mx", "mx_hosts",
		"has_spf", "spf_record",
		"has_dmarc", "dmarc_record",
		"has_dkim", "dkim_selectors", "dkim_records",
		"smtp_checked", "smtp_host", "smtp_port", "smtp_banner",
		"scheme", "status", "active", "final_url", "response_time_ms",
		"tls_server_name", "tls_issuer",
		"error", "excluded_parked",
		"email_check_note",
	})

	for r := range ch {
		if suppressExcluded && r.ExcludedParked {
			continue
		}
		row := []string{
			r.Domain,
			fmt.Sprintf("%t", r.DNSOK),
			fmt.Sprintf("%t", r.HasA),
			fmt.Sprintf("%t", r.HasAAAA),
			r.CNAME,

			fmt.Sprintf("%t", r.HasMX),
			strings.Join(r.MXHosts, ";"),

			fmt.Sprintf("%t", r.HasSPF),
			r.SPFRecord,

			fmt.Sprintf("%t", r.HasDMARC),
			r.DMARCRecord,

			fmt.Sprintf("%t", r.HasDKIM),
			strings.Join(r.DKIMSelectors, ";"),
			strings.Join(r.DKIMRecords, " || "),

			fmt.Sprintf("%t", r.SMTPChecked),
			r.SMTPHost,
			fmt.Sprintf("%d", r.SMTPPort),
			r.SMTPBanner,

			r.Scheme,
			fmt.Sprintf("%d", r.Status),
			fmt.Sprintf("%t", r.Active),
			r.FinalURL,
			fmt.Sprintf("%d", r.RespTime.Milliseconds()),
			r.TLSServerName,
			r.TLSIssuer,

			r.Error,
			fmt.Sprintf("%t", r.ExcludedParked),

			r.EmailCheckNote,
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

// ---------------------- Email/DNS posture helpers ----------------------

func populateEmailPosture(res *Result) {
	// MX lookup
	mxRecs, mxErr := net.LookupMX(res.Domain)
	if mxErr == nil && len(mxRecs) > 0 {
		hosts := make([]string, 0, len(mxRecs))
		for _, mx := range mxRecs {
			h := strings.TrimSuffix(mx.Host, ".")
			if h == "" {
				continue
			}
			hosts = append(hosts, h)
		}
		hosts = dedupeStrings(hosts)

		if mxStrict {
			// Only keep MX hosts that resolve to at least one IP.
			active := make([]string, 0, len(hosts))
			for _, h := range hosts {
				if ips, err := net.LookupIP(h); err == nil && len(ips) > 0 {
					active = append(active, h)
				}
			}
			hosts = dedupeStrings(active)
		}

		if len(hosts) > 0 {
			res.HasMX = true
			res.MXHosts = hosts
		}
	}

	// SPF: TXT on apex containing v=spf1
	if txts, err := net.LookupTXT(res.Domain); err == nil {
		for _, t := range txts {
			low := strings.ToLower(strings.TrimSpace(t))
			if strings.HasPrefix(low, "v=spf1") {
				res.HasSPF = true
				res.SPFRecord = t
				break
			}
		}
	}

	// DMARC: TXT on _dmarc.domain containing v=DMARC1
	dmarcName := "_dmarc." + res.Domain
	if txts, err := net.LookupTXT(dmarcName); err == nil {
		for _, t := range txts {
			low := strings.ToLower(strings.TrimSpace(t))
			if strings.HasPrefix(low, "v=dmarc1") {
				res.HasDMARC = true
				res.DMARCRecord = t
				break
			}
		}
	}

	// DKIM: probe selectors: <selector>._domainkey.<domain>
	selectors := parseCSVList(dkimSelectors)
	foundSel := []string{}
	foundRec := []string{}

	for _, sel := range selectors {
		name := sel + "._domainkey." + res.Domain
		txts, err := net.LookupTXT(name)
		if err != nil || len(txts) == 0 {
			continue
		}
		for _, t := range txts {
			low := strings.ToLower(strings.TrimSpace(t))
			if strings.Contains(low, "v=dkim1") || strings.HasPrefix(low, "v=dkim1") {
				foundSel = append(foundSel, sel)
				foundRec = append(foundRec, t)
				break
			}
		}
		if len(foundRec) >= maxDKIMRecords {
			break
		}
	}

	if len(foundSel) > 0 {
		res.HasDKIM = true
		res.DKIMSelectors = dedupeStrings(foundSel)
		// keep record order aligned-ish; we can keep as-is, then de-dupe
		res.DKIMRecords = dedupeStrings(foundRec)
	}
}

// smtpBannerFirst tries to connect to port on each host (in order) and read the first banner line.
func smtpBannerFirst(hosts []string, port int, timeout time.Duration) (host string, banner string, ok bool) {
	for _, h := range hosts {
		// Ensure host resolves (some MX hostnames may not resolve due to strict mode off)
		if ips, err := net.LookupIP(h); err != nil || len(ips) == 0 {
			continue
		}

		addr := fmt.Sprintf("%s:%d", h, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		br := bufio.NewReader(conn)
		line, _ := br.ReadString('\n')
		_ = conn.Close()

		line = strings.TrimSpace(line)
		if line != "" {
			return h, line, true
		}
	}
	return "", "", false
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// stable output helps diffs
	sort.Strings(out)
	return out
}
