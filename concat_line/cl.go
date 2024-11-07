package main

// simple tool to concatenate a file of lines into one line separated by a delimeter
import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// Define the flags
	inputFile := flag.String("i", "", "Input file (optional, defaults to stdin if not provided)")
	outputFile := flag.String("o", "", "Output file (optional, defaults to stdout if not provided)")
	delimiter := flag.String("d", ",", "Delimiter (optional, defaults to \",\" if not provided)")
	help := flag.Bool("h", false, "Print help message")

	flag.Parse()

	// Print help message if -h flag is set
	if *help {
		fmt.Println("Usage: ", os.Args[0], "[options]")
		fmt.Println("Options:")
		fmt.Println("  -i string")
		fmt.Println("        Input file (optional, defaults to stdin if not provided)")
		fmt.Println("  -o string")
		fmt.Println("        Output file (optional, defaults to stdout if not provided)")
		fmt.Println("  -d delimiter")
		fmt.Println("        delimiter (optional, defaults to \",\" if not provided)")
		fmt.Println("  -h    Print help message")
		os.Exit(0)
	}

	// Determine input source: file or stdin
	var input *os.File
	if *inputFile != "" {
		var err error
		input, err = os.Open(*inputFile) // Open the input file if provided
		if err != nil {
			fmt.Printf("Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer input.Close()
	} else {
		input = os.Stdin // Default to stdin if no input file is provided
	}

	// Determine output source: file or stdout
	var output *os.File
	if *outputFile != "" {
		var err error
		output, err = os.Create(*outputFile) // Create the output file if provided
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer output.Close()
	} else {
		output = os.Stdout // Default to stdout if no output file is provided
	}

	// Scanner to read from input (file or stdin)
	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	result := strings.Join(lines, *delimiter)
	fmt.Fprintln(writer, result)
}
