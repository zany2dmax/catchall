package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
//	"time"

	"github.com/likexian/whois"
)

// Check if an IP address is a valid IPv4 address
func isValidIPv4(ip string) bool {
	return net.ParseIP(ip) != nil && strings.Count(ip, ":") < 2
}

// Perform a ping to check if an IP address is reachable
func pingIP(ip string, ch chan<- string) {
	cmd := exec.Command("ping", "-c", "3", "-t", "5", ip)
	err := cmd.Run()
	if err != nil {
		ch <- fmt.Sprintf("IP %s is down", ip)
	} else {
		ch <- fmt.Sprintf("IP %s is up", ip)
	}
}

// Perform a whois lookup
func whoisLookup(ip string, ch chan<- string) {
	result, err := whois.Whois(ip)
	if err != nil {
		ch <- fmt.Sprintf("Whois lookup failed for IP %s: %v", ip, err)
	} else {
		ch <- fmt.Sprintf("Whois information for IP %s:\n%s", ip, result)
	}
}

// Perform a reverse DNS lookup
func reverseLookup(ip string, ch chan<- string) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		ch <- fmt.Sprintf("Reverse DNS lookup failed for IP %s: %v", ip, err)
	} else if len(names) > 0 {
		ch <- fmt.Sprintf("Reverse DNS host name for IP %s: %s", ip, names[0])
	} else {
		ch <- fmt.Sprintf("No host name found for IP %s", ip)
	}
}

func main() {
	// Define the flags
	inputFile := flag.String("i", "", "Input file (optional, defaults to stdin if not provided)")
	outputFile := flag.String("o", "", "Output file (optional, defaults to stdout if not provided)")
	help := flag.Bool("h", false, "Print help message")
	whoisCheck := flag.Bool("w", false, "Enable whois lookup check")
	reverseCheck := flag.Bool("r", false, "Enable reverse DNS lookup check")

	flag.Parse()

	// Print help message if -h flag is set
	if *help {
		fmt.Println("Usage: program [options]")
		fmt.Println("Options:")
		fmt.Println("  -i string    Input file (optional, defaults to stdin if not provided)")
		fmt.Println("  -o string    Output file (optional, defaults to stdout if not provided)")
		fmt.Println("  -h           Print help message")
		fmt.Println("  -w           Enable whois lookup check")
		fmt.Println("  -r           Enable reverse DNS lookup check")
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

	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	// Create a wait group to handle concurrent goroutines
	var wg sync.WaitGroup

	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if !isValidIPv4(ip) {
			fmt.Fprintf(writer, "IP %s is not a valid IPv4 address\n", ip)
			continue
		}

		fmt.Fprintf(writer, "Checking IP %s...\n", ip)

		// Create channels to gather results from concurrent functions
		pingCh := make(chan string, 1)
		var whoisCh, reverseCh chan string

		// Increment wait group counter
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			pingIP(ip, pingCh)
		}(ip)

		// Only create and run whois lookup if -w flag is set
		if *whoisCheck {
			whoisCh = make(chan string, 1)
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				whoisLookup(ip, whoisCh)
			}(ip)
		}

		// Only create and run reverse lookup if -r flag is set
		if *reverseCheck {
			reverseCh = make(chan string, 1)
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				reverseLookup(ip, reverseCh)
			}(ip)
		}

		// Use a goroutine to wait for all checks to complete, then close channels
		go func() {
			wg.Wait()
			close(pingCh)
			if whoisCh != nil {
				close(whoisCh)
			}
			if reverseCh != nil {
				close(reverseCh)
			}
		}()

		// Collect and print results from channels
		for result := range pingCh {
			fmt.Fprintln(writer, result)
		}
		if whoisCh != nil {
			for result := range whoisCh {
				fmt.Fprintln(writer, result)
			}
		}
		if reverseCh != nil {
			for result := range reverseCh {
				fmt.Fprintln(writer, result)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}
}
