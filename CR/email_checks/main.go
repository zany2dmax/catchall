package main

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"
)

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
}

// User represents a simplified structure for user data
type User struct {
	DisplayName                string `json:"displayName"`
	UserPrincipalName          string `json:"userPrincipalName"`
	LastPasswordChangeDateTime string `json:"lastPasswordChangeDateTime"`
	AccountEnabled             bool   `json:"accountEnabled"`
}

func setupLogging(logFilePath string) {
	// Open the log file for writing
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Errorf("Failed to open log file: %v", err)
	}
	// Set the log output to the file
	log.SetOutput(logFile)
	// Optional: Add date and time to each log message
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Print a message to indicate logging has started
	log.Println("Logging started")
}
func getBearerToken(tenantID, clientID, clientSecret string) (string, error) {
	// Azure AD OAuth2 token endpoint
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	// Build request body
	data := fmt.Sprintf(
		"client_id=%s&scope=https://graph.microsoft.com/.default&client_secret=%s&grant_type=client_credentials",
		clientID,
		clientSecret,
	)

	// Make HTTP POST request to get the token
	resp, err := http.Post(url, "application/x-www-form-urlencoded", bytes.NewBufferString(data))
	if err != nil {
		return "", fmt.Errorf("failed to request token:", err)
	}
	defer resp.Body.Close()

	// Parse the response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get token, status: %d, response: %s", resp.StatusCode, body)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	return tokenResponse.AccessToken, nil
}

func fetchUsers(bearerToken string) ([]User, error) {
	// Microsoft Graph API endpoint to list users
	baseURL := "https://graph.microsoft.com/v1.0/users"
	graphSelect := "?$top=999&$select=displayName,userPrincipalName,lastPasswordChangeDateTime,accountEnabled"
	url := baseURL + graphSelect
	var allUsers []User
	// Create HTTP request
	for url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+bearerToken)

		// Execute HTTP request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch users: %v", err)
		}
		defer resp.Body.Close()

		// Parse the response
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("failed to fetch users, status: %d, response: %s", resp.StatusCode, body)
		}
		var data struct {
			Value    []User `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, fmt.Errorf("failed to parse user response: %v", err)
		}
		// Append current page of users to the result
		allUsers = append(allUsers, data.Value...)
		// Set the URL to the next link for pagination
		url = data.NextLink
	}
	return allUsers, nil
}

func writeUsersToCSV(users []User, filePath string) error {
	// Create CSV file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV headers
	headers := []string{"UserPrincipalName", "DisplayName", "LastPasswordChangeDateTime", "AccountEnabled"}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV headers: %v", err)
	}

	// Write user data to CSV
	for _, user := range users {
		record := []string{
			user.UserPrincipalName,
			user.DisplayName,
			user.LastPasswordChangeDateTime,
			strconv.FormatBool(user.AccountEnabled),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %v", err)
		}
	}

	return nil
}

// sendEmail sends the CSV file as an email attachment
func sendEmail(smtpHost, smtpPort, senderEmail, senderPassword, recipientEmail, subject, body, filePath string) error {
	// Read the file content
	csvData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read CSV file: %v", err)
	}

	// Create the email headers
	boundary := "----=_Part_12345" // Unique boundary for multipart emails
	headers := make(map[string]string)
	headers["From"] = senderEmail
	headers["To"] = recipientEmail
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = fmt.Sprintf(`multipart/mixed; boundary="%s"`, boundary)

	// Create the email body
	var message bytes.Buffer
	for k, v := range headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	message.WriteString("\r\n") // End of headers

	// Add the plain text part
	message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	message.WriteString(`Content-Type: text/plain; charset="utf-8"` + "\r\n")
	message.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	message.WriteString(body + "\r\n")

	// Add the attachment
	message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	message.WriteString(fmt.Sprintf(`Content-Type: text/csv; name="%s"`+"\r\n", filepath.Base(filePath)))
	message.WriteString("Content-Transfer-Encoding: base64\r\n")
	message.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", filepath.Base(filePath)))
	encoded := base64.StdEncoding.EncodeToString(csvData)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		message.WriteString(encoded[i:end] + "\r\n")
	}
	message.WriteString(fmt.Sprintf("--%s--\r\n", boundary)) // End of message

	// Connect to the SMTP server
	auth := smtp.PlainAuth("", senderEmail, senderPassword, smtpHost)
	if err := smtp.SendMail(smtpHost+":"+smtpPort, auth, senderEmail, []string{recipientEmail}, message.Bytes()); err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}
	return nil
}

func main() {
	// Step 0 set up the environment
	logFilePath := "usersAD.log" // Path to the log file
	setupLogging(logFilePath)
	log.Println("Starting the program...")
	sendEmailFile := flag.String("f", "AzureAD_Users.csv", "name of the output email file as a .csv")
	//excludeDisabled := flag.Bool("e", false, "Exclude users with accountEnabled set to false")
	help := flag.Bool("h", false, "Print help message")
	flag.Parse()
	if *help {
		fmt.Println("Usage: ", os.Args[0], " [options]")
		fmt.Println("Options:")
		fmt.Println("  -f filename  Output filename, defaults to AzureAD_Users.csv")
		fmt.Println("  -h           Print help message")
		fmt.Println("  -e           Exclude users with accountEnabled set to false")
		os.Exit(0)
	}
	// Load .env files  .env.local takes precedence (if present)
	godotenv.Load(".env.local")
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env: %v", err)
	}
	clientID := os.Getenv("clientID")
	tenantID := os.Getenv("tenantID")
	clientSecret := os.Getenv("clientSecret")
	clientID := os.Getenv("clientID")
	tenantID := os.Getenv("tenantID")
	clientSecret := os.Getenv("clientSecret")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	senderEmail := os.Getenv("SMTP_EMAIL")
	senderPassword := os.Getenv("SMTP_PASSWORD")
	subject := "Azure AD Users CSV"
	body := "Attached is the Azure AD Users export in CSV format."
	// Step 1: Authenticate with Azure AD and get an OAuth token
	bearerToken, err := getBearerToken(tenantID, clientID, clientSecret)
	if err != nil {
		fmt.Errorf("Failed to get bearer token: %v", err)
	}
	// Step 2: Make an HTTP request to the Microsoft Graph API
	users, err := fetchUsers(bearerToken)
	if err != nil {
		fmt.Errorf("Failed to fetch users: %v", err)
	}
	// Step 3: Write user data to a CSV file
	if err := writeUsersToCSV(users, *sendEmailFile); err != nil {
		fmt.Errorf("Failed to write users to CSV: %v", err)
	}
	log.Printf("User export completed. File saved at: %s\n", *sendEmailFile)
	// Step 4: Mail the CSV data out
	if err := sendEmail(smtpHost, smtpPort, senderEmail, senderPassword, recipientEmail, subject, body, *sendEmailFile); err != nil {
		fmt.Errorf("Failed to send email: %v", err)
	}
}
