package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

// compareIPs compares two IP addresses byte-by-byte.
func compareIPs(ip1, ip2 net.IP) int {
	ip1 = ip1.To4()
	ip2 = ip2.To4()

	for i := 0; i < 4; i++ {
		if ip1[i] < ip2[i] {
			return -1
		}
		if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}

// isIPv4 checks if a given string is a valid IPv4 address.
func isIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

// prefixSize calculates the largest possible prefix size for a given range.
func prefixSize(start, end net.IP) int {
	size := 32
	for i := range start {
		diff := start[i] ^ end[i]
		if diff != 0 {
			for diff != 0 {
				size--
				diff >>= 1
			}
			break
		}
	}
	return size
}

// incrementIP increments an IP address by 1.
func incrementIP(ip net.IP) net.IP {
	inc := make(net.IP, len(ip))
	copy(inc, ip)
	for i := len(inc) - 1; i >= 0; i-- {
		inc[i]++
		if inc[i] > 0 {
			break
		}
	}
	return inc
}

// getCIDR generates CIDR ranges for a given start and end IP range.
func getCIDR(startIP, endIP string) ([]*net.IPNet, error) {
	start := net.ParseIP(startIP).To4()
	end := net.ParseIP(endIP).To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	var cidrs []*net.IPNet
	for compareIPs(start, end) <= 0 {
		size := prefixSize(start, end)
		_, cidr, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", start, size))
		cidrs = append(cidrs, cidr)

		start = incrementIP(lastIP(cidr))
		if start == nil {
			break
		}
	}
	return cidrs, nil
}

// lastIP calculates the last IP address in a CIDR block.
func lastIP(cidr *net.IPNet) net.IP {
	ip := cidr.IP.To4()
	mask := cidr.Mask

	last := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		last[i] = ip[i] | ^mask[i]
	}
	return last
}

// cidrToRange converts a CIDR block to a range of IPs (start and end).
func cidrToRange(cidr string) (string, string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", fmt.Errorf("invalid CIDR: %s", cidr)
	}

	start := ipNet.IP
	end := lastIP(ipNet)

	return start.String(), end.String(), nil
}

// isCIDR checks if the input string is a valid CIDR block.
func isCIDR(input string) bool {
	_, _, err := net.ParseCIDR(input)
	return err == nil
}

// processInput processes each line of input and handles both ranges and CIDR blocks.
func processInput(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	if isCIDR(line) {
		start, end, err := cidrToRange(line)
		if err != nil {
			return fmt.Sprintf("Failed to process CIDR: %s. SKIPPED.", line)
		}
		return fmt.Sprintf("%s-%s", start, end)
	}

	ipBlock := strings.Split(line, "-")
	if len(ipBlock) == 2 {
		startIP := strings.TrimSpace(ipBlock[0])
		endIP := strings.TrimSpace(ipBlock[1])

		cidrs, err := getCIDR(startIP, endIP)
		if err != nil {
			return fmt.Sprintf("Failed to process range: %s. SKIPPED.", line)
		}

		cidrStrings := make([]string, len(cidrs))
		for i, cidr := range cidrs {
			cidrStrings[i] = cidr.String()
		}
		return strings.Join(cidrStrings, ", ")
	}

	if isIPv4(line) {
		singleIP := line
		return singleIP + "/32"
	} else {
		return fmt.Sprintf("Invalid input: %s. SKIPPED.", line)
	}
}

// processRanges reads input and processes each line to convert ranges or CIDRs.
func processRanges(input *os.File, output *os.File) {
	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	for scanner.Scan() {
		line := scanner.Text()
		result := processInput(line)
		if result != "" {
			fmt.Fprintln(writer, result)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(writer, "Error reading input: %s\n", err)
	}
}

func main() {
	inputFile := flag.String("i", "", "Input file (optional, defaults to stdin if not provided)")
	outputFile := flag.String("o", "", "Output file (optional, defaults to stdout if not provided)")
	help := flag.Bool("h", false, "Print help message")
	flag.Parse()

	if *help {
		fmt.Println("Usage:", os.Args[0], "[options]")
		fmt.Println("Options:")
		fmt.Println("  -i string    Input file (optional, defaults to stdin if not provided)")
		fmt.Println("  -o string    Output file (optional, defaults to stdout if not provided)")
		fmt.Println("  -h           Print help message")
		fmt.Println("\n", os.Args[0], " is a small utility to convert IP ranges to CIDR format, and CIDR format to ranges.")
		os.Exit(0)
	}

	var input *os.File
	var err error
	if *inputFile != "" {
		input, err = os.Open(*inputFile)
		if err != nil {
			fmt.Printf("Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer input.Close()
	} else {
		input = os.Stdin
	}

	var output *os.File
	if *outputFile != "" {
		output, err = os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	processRanges(input, output)
}
