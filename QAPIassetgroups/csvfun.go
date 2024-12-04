package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
)

/* func SplitCSVbyLine(FileLine string) (ItemArray []string) {
	ItemArray = strings.Split(FileLine, ",")
	return ItemArray
} */

func main() {
	file, err := os.Open("./csvtest.csv")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer file.Close()

	//scanner := bufio.NewScanner(file)
	reader := csv.NewReader(bufio.NewReader(file))
	//for scanner.Scan() {

	for {
		line, error := reader.Read()
		if error == io.EOF {
			break
		} else if error != nil {
			log.Fatal(error)
		}
		fmt.Println("WebAppName: " + line[0])
		fmt.Println("WebAppURL: " + line[1])

	}
	/* fmt.Println(scanner.Text())
	s := scanner.Text() */
	/* fmt.Println(s) */
	//lineElements := SplitCSVbyLine(scanner.Text())

	//}
	//fmt.Println()

	//if err := scanner.Err(); err != nil {
	//	log.Fatal(err)
}
