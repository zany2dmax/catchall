package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"getOpenPorts/internal/qualysclient"
)

func main() {
	baseURL := flag.String("base-url", "", "Qualys API base URL")
	ipSingle := flag.String("ip", "", "Single IP to lookup")
	ipsFile := flag.String("ip-file", "", "File with one IP per line")
	batch := flag.Bool("batch", false, "Batch mode: use IN operator")

	tokenFlag := flag.String("token", "", "Qualys JWT token (optional)")
	timeout := flag.Duration("timeout", 30*time.Second, "HTTP timeout")
	portFilter := flag.Int("port", 0, "If non-zero, only show this port")
	flag.Parse()

	if *baseURL == "" {
		log.Fatal("missing -base-url")
	}
	if (*ipSingle == "" && *ipsFile == "") || (*ipSingle != "" && *ipsFile != "") {
		log.Fatal("specify exactly one of -ip or -ip-file")
	}

	client := &qualysclient.Client{
		BaseURL:    *baseURL,
		Token:      firstNonEmpty(*tokenFlag, os.Getenv("QUALYS_TOKEN")),
		Username:   os.Getenv("QUALYS_USERNAME"),
		Password:   os.Getenv("QUALYS_PASSWORD"),
		HTTPClient: qualysclient.NewHTTPClient(*timeout),
	}

	fmt.Println("ip,port,protocol,service")

	if *ipSingle != "" {
		querySingleIP(client, *ipSingle, *portFilter)
		return
	}

	ips, err := readIPs(*ipsFile)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}

	if *batch {
		queryBatchIPs(client, ips, *portFilter)
	} else {
		for _, ip := range ips {
			querySingleIP(client, ip, *portFilter)
		}
	}
}

func readIPs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, scanner.Err()
}

func querySingleIP(client *qualysclient.Client, ip string, portFilter int) {
	assets, err := client.SearchAssetsByIP(ip)
	if err != nil {
		log.Printf("error: %v", err)
		return
	}
	printPortsForIP(ip, assets, portFilter)
}

func queryBatchIPs(client *qualysclient.Client, ips []string, portFilter int) {
	assets, err := client.SearchAssetsByIPBatch(ips)
	if err != nil {
		log.Fatalf("batch search failed: %v", err)
	}

	ipMap := make(map[string][]qualysclient.Asset)
	for _, a := range assets {
		for _, nic := range a.NetworkInterfaceListData.Interfaces {
			if nic.AddressIPv4 != "" {
				ipMap[nic.AddressIPv4] = append(ipMap[nic.AddressIPv4], a)
			}
		}
	}

	for _, ip := range ips {
		printPortsForIP(ip, ipMap[ip], portFilter)
	}
}

func printPortsForIP(ip string, assets []qualysclient.Asset, portFilter int) {
	for _, a := range assets {
		for _, p := range a.OpenPortListData.OpenPorts {
			if portFilter != 0 && p.Port != portFilter {
				continue
			}
			service := ""
			if p.DetectedService != nil {
				service = *p.DetectedService
			}
			s := strings.ReplaceAll(service, "\"", "\"\"")
			fmt.Printf("%s,%d,%s,\"%s\"\n", ip, p.Port, p.Protocol, s)
		}
	}
}
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
