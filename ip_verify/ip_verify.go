package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Function to check if an IP address is a valid IPv4 address
func isValidIPv4(ip string) bool {
	return net.ParseIP(ip) != nil && strings.Count(ip, ":") < 2
}

// Function to ping an IP address and check if it is reachable
func pingIP(ip string) bool {
	// On Linux/macOS, we use the ping command
	cmd := exec.Command("ping", "-c", "3", "-t", "5", ip) // -c: count, -t: timeout
	err := cmd.Run()
	return err == nil
}

func main() {
	// Define the flags
	inputFile := flag.String("i", "", "Input file (optional, defaults to stdin if not provided)")
	outputFile := flag.String("o", "", "Output file (optional, defaults to stdout if not provided)")
	help := flag.Bool("h", false, "Print help message")

	flag.Parse()

	// Print help message if -h flag is set
	if *help {
		fmt.Println("Usage: program [options]")
		fmt.Println("Options:")
		fmt.Println("  -i string")
		fmt.Println("        Input file (optional, defaults to stdin if not provided)")
		fmt.Println("  -o string")
		fmt.Println("        Output file (optional, defaults to stdout if not provided)")
		fmt.Println("  -h    Print help message")
		os.Exit(0)
	}
	// Determine input source: file or stdin
	if *inputFile != "" {
		input, err := os.Open(*inputFile)
		if err != nil {
			fmt.Printf("Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer input.Close()
	} else {
		input = os.Stdin
	}
	// Determine output source: file or stdout
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
			// Ping the IP address
			if pingIP(ip) {
				fmt.Fprintf(writer, " and is up\n")
			} else {
				fmt.Fprintf(writer, " and is down\n")
			}
		} else {
			fmt.Fprintf(writer, "IP %s is not a valid IPv4 address\n", ip)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}
}
