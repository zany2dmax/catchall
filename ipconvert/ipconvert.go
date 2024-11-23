package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

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

// getCIDR generates CIDR ranges for a given start and end IP range.
func getCIDR(startIP, endIP string) ([]*net.IPNet, error) {
	start := net.ParseIP(startIP).To4() // Ensure IPv4 address
	end := net.ParseIP(endIP).To4()     // Ensure IPv4 address
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	//fmt.Println("Start: ", start)
	//fmt.Println("End: ", end)
	var cidrs []*net.IPNet
	for compareIPs(start, end) <= 0 { // Ensure we exit when start > end
		size := prefixSize(start, end)
		_, cidr, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", start, size))
		cidrs = append(cidrs, cidr)

		// Increment start to the next IP after the current CIDR block
		start = incrementIP(lastIP(cidr))
		if start == nil { // Safety check for invalid increment
			break
		}
	}
	return cidrs, nil
}

// prefixSize calculates the prefix size for CIDR blocks.
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

// incrementIP increments an IP address.
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

func lastIP(cidr *net.IPNet) net.IP {
	ip := cidr.IP.To4()
	mask := cidr.Mask

	last := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		last[i] = ip[i] | ^mask[i]
	}
	return last
}

// processRanges processes the input and converts ranges to CIDR blocks.
func processRanges(input *os.File, output *os.File) {
	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		//fmt.Println(line)
		if line == "" {
			continue
		}

		ipBlock := strings.Split(line, "-")
		var startIP, endIP string
		if len(ipBlock) == 2 {
			startIP = strings.TrimSpace(ipBlock[0])
			endIP = strings.TrimSpace(ipBlock[1])
		} else {
			startIP = strings.TrimSpace(ipBlock[0])
			endIP = startIP
		}
		//fmt.Println(startIP)
		//fmt.Println(endIP)

		cidrs, err := getCIDR(startIP, endIP)
		if err != nil {
			fmt.Fprintf(writer, "Failed to process: %s. SKIPPED.\n", line)
			continue
		}

		for _, cidr := range cidrs {
			fmt.Fprintln(writer, cidr.String())
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

	// Print help message if -h flag is set
	if *help {
		fmt.Println("Usage:", os.Args[0], "[options]")
		fmt.Println("Options:")
		fmt.Println("  -i string    Input file (optional, defaults to stdin if not provided)")
		fmt.Println("  -o string    Output file (optional, defaults to stdout if not provided)")
		fmt.Println("  -h           Print help message")
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
