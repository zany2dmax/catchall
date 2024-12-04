package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func Get_Credential_Hash(User string, Password string) string {

	return base64.StdEncoding.EncodeToString([]byte(User + ":" + Password))
}

func Usage() {
	fmt.Println("usage: QAPIAssetGroup [-user -password -APIURL [-download|-upload] [-csv|-xml] -filename]")
	fmt.Println("\nNOTE: -download and -upload are mutually exclusive, only set one, ditto for -csv and -xml")
	fmt.Println("    -filename is optional, if not used, default will be assetgroups.csv in local directory")
	fmt.Println("                            This is for the upload flag only - CSV used for uploading")
	fmt.Println("/nDownload filenames will be AGDownloadOutput.csv or AGDownloadOutput.xml, depending on which chosen")
}

func Get_Command_Line_Args() (string, string, string, bool, bool, bool, bool, string) {
	/* Get cmd line paramters */
	UserPtr := flag.String("user", "XXXXXX", "Qualys Account User Name")
	PasswordPtr := flag.String("password", "XXXXXX", "Qualys Account password")
	APIURLPtr := flag.String("APIURL", "https://qualysapi.qg3.apps.qualys.com", "Qualys API endpoint")
	DLPtr := flag.Bool("download", false, "Use to Download AG's - mutually exclusive to -upload")
	ULPtr := flag.Bool("upload", false, "Use to UPload AG's - mutually exclusive to -download")
	CSVPtr := flag.Bool("csv", false, "Use to Download in CSV format - mutually exclusive to XML")
	XMLPtr := flag.Bool("xml", false, "Use to Download in XML format - mutually exclusive to CSV")
	CSVName := flag.String("filename", "assetgroups.csv", "Asset Groups File")

	flag.Parse()

	return *UserPtr, *PasswordPtr, *APIURLPtr, *DLPtr, *ULPtr, *CSVPtr, *XMLPtr, *CSVName
}

func DL_Asset_Group_List(User string, Password string, APIURL string, DLTYPE string) {

	encodedcred := Get_Credential_Hash(User, Password)
	OutputFile := "./AGDownloadOutput.xml"
	if DLTYPE == "csv" {
		OutputFile = "./AGDownloadOutput.csv"
	}
	/* This next section builds the HTTP POST request properly */
	resource := "/api/2.0/fo/asset/group/"
	data := url.Values{}
	data.Set("action", "list")
	data.Add("show_attributes", "ALL")
	data.Add("output_format", DLTYPE)
	u, _ := url.ParseRequestURI(APIURL)
	u.Path = resource
	u.RawQuery = data.Encode()
	urlStr := fmt.Sprintf("%v", u)
	fmt.Println("Calling API:", urlStr)
	/* Now we prepare the HTTP headers and make the call */
	client := &http.Client{}
	req, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	req.Header.Add("X-requested-With", "GOLANG")
	req.Header.Add("authorization", "Basic "+encodedcred)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, _ := client.Do(req)
	respStatus := response.Status
	defer response.Body.Close()
	fmt.Println(respStatus)

	/* Keep the XML for posterity and  */
	/* later add more error checking for respStatus and make sure we got a 200 OK */
	/* but for now just write the contents out to the XMLfile */

	file, err := os.Create(OutputFile)
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(file, response.Body)
	if err != nil {
		log.Fatal(err)
	}
	file.Close()
	fmt.Println("Downloaded and Saved File: !", OutputFile)
}

func SplitCSVbyLine(FileLine string) (ItemArray []string) {
	ItemArray = strings.Split(FileLine, ",")
	return ItemArray
}

func UL_Asset_Group_list(User string, Password string, APIURL string, InputFile string) int {
	/* The format of the CSV is "TITLE","IPS" */

	encodedcred := Get_Credential_Hash(User, Password)

	file, err := os.Open(InputFile)
	if err != nil {
		log.Fatal(err)
		return -1
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		CSVlineElements := SplitCSVbyLine(line)
		agname := CSVlineElements[0]
		ips := CSVlineElements[1]
		//fmt.Print(CSVlineElements[i], ":")
		fmt.Println()

		//* This next section builds the HTTP POST request properly *//
		resource := "/api/2.0/fo/asset/group/"
		data := url.Values{}
		data.Set("action", "add")
		data.Set("ips", ips)
		data.Set("title", agname)
		u, _ := url.ParseRequestURI(APIURL)
		u.Path = resource
		u.RawQuery = data.Encode()
		urlStr := fmt.Sprintf("%v", u)
		fmt.Println("Calling API:", urlStr)
		/* Now we prepare the HTTP headers and make the call */
		client := &http.Client{}
		req, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
		req.Header.Add("X-requested-With", "GOLANG")
		req.Header.Add("authorization", "Basic "+encodedcred)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		response, _ := client.Do(req)
		respStatus := response.Status
		defer response.Body.Close()
		fmt.Println(respStatus)
		body, err := io.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("client: could not read response body: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("client: response body: %s\n", body)
	}
	return 0
}

func main() {
	User, Password, APIURL, Download, Upload, CSV, XML, CSVOutputFilename := Get_Command_Line_Args()
	DLTYPE := ""
	if Download && Upload || !Download && !Upload { /* set one or other not both */
		Usage()
		os.Exit(1)
	} else {
		if CSV {
			DLTYPE = "csv"
		} else if XML {
			DLTYPE = "xml"
		}
		if Download {
			DL_Asset_Group_List(User, Password, APIURL, DLTYPE)
			os.Exit(1)
		}
		if Upload {
			UL_Asset_Group_list(User, Password, APIURL, CSVOutputFilename)

			//fmt.Println("Uploading:", CSVOutputFilename)
		}
	}
}
