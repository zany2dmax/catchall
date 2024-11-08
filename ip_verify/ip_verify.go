package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/likexian/whois"
)

// Function to check if an IP address is a valid IPv4 address
func isValidIPv4(ip string) bool {
	return net.ParseIP(ip) != nil && strings.Count(ip, ":") < 2
}

// Function to ping an IP address and check if it is reachable
func pingIP(ip string) bool {
	cmd := exec.Command("ping", "-c", "3", "-t", "5", ip) // -c: count, -t: timeout
	err := cmd.Run()
	return err == nil
}

// Function to perform whois lookup
func whoisLookup(ip string) (string, error) {
	result, err := whois.Whois(ip)
	if err != nil {
		return "", err
	}
	return result, nil
}

// Function to perform reverse DNS lookup
func reverseLookup(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}
	if len(names) > 0 {
		return names[0], nil
	}
	return "No host name found", nil
}

func main() {
	inputFile := flag.String("i", "", "Input file (optional, defaults to stdin if not provided)")
	outputFile := flag.String("o", "", "Output file (optional, defaults to stdout if not provided)")
	whoisFlag := flag.Bool("w", false, "Whois Flag, enables Whois check")
	revLookupFlag := flag.Bool("r", false, "Reverse Lookup Flag, enables Reverse Lookup check")
	help := flag.Bool("h", false, "Print help message")

	flag.Parse()

	if *help {
		fmt.Println("Usage: program [options]")
		fmt.Println("Options:")
		fmt.Println("  -i string")
		fmt.Println("        Input file (optional, defaults to stdin if not provided)")
		fmt.Println("  -o string")
		fmt.Println("        Output file (optional, defaults to stdout if not provided)")
		fmt.Println("  -w    Whois Check, defaults to false")
		fmt.Println("  -r    Reverse Lookup Check, defaults to false")
		fmt.Println("  -h    Print help message")
		os.Exit(0)
	}
	if *whoisFlag {
		*whoisFlag = true
	}
	if *revLookupFlag {
		*revLookupFlag = true
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

	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())

		if isValidIPv4(ip) {
			fmt.Fprintf(writer, "IP %s is valid IPv4", ip)
			if pingIP(ip) {
				fmt.Fprintf(writer, " and is up\n")
			} else {
				fmt.Fprintf(writer, " and is down\n")
			}

			// Perform whois lookup
			if *whoisFlag {
				whoisInfo, err := whoisLookup(ip)
				if err != nil {
					fmt.Fprintf(writer, "Whois lookup failed for IP %s: %v\n", ip, err)
				} else {
					fmt.Fprintf(writer, "Whois information for IP %s:\n%s\n", ip, whoisInfo)
				}
			}

			// Perform reverse DNS lookup
			if *revLookupFlag {
				hostName, err := reverseLookup(ip)
				if err != nil {
					fmt.Fprintf(writer, "Reverse DNS lookup failed for IP %s: %v\n", ip, err)
				} else {
					fmt.Fprintf(writer, "Reverse DNS host name for IP %s: %s\n", ip, hostName)
				}
			}
		} else {
			fmt.Fprintf(writer, "IP %s is not a valid IPv4 address\n", ip)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}
}
