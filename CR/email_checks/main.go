package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
		return "", fmt.Errorf("failed to request token: %v", err)
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
	url := "https://graph.microsoft.com/v1.0/users"
	graphSelect := "?$top=999&$select=displayName,userPrincipalName,lastPasswordChangeDateTime,accountEnabled"
	graphAPIUser := url + graphSelect

	// Create HTTP request
	req, err := http.NewRequest("GET", graphAPIUser, nil)
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
		Value []User `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse user response: %v", err)
	}
	return data.Value, nil
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

func main() {
	// Step 0 set up the environment
	// Load .env files
	// .env.local takes precedence (if present)
	godotenv.Load(".env.local")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env: %v", err)
	}
	clientID := os.Getenv("clientID")
	tenantID := os.Getenv("tenantID")
	clientSecret := os.Getenv("clientSecret")
	//fmt.Println("%s\n%s\n%s\n", clientID, tenantID, clientSecret)
	// Step 1: Authenticate with Azure AD and get an OAuth token
	bearerToken, err := getBearerToken(tenantID, clientID, clientSecret)
	if err != nil {
		log.Fatalf("Failed to get bearer token: %v", err)
	}
	// Step 2: Make an HTTP request to the Microsoft Graph API
	users, err := fetchUsers(bearerToken)
	if err != nil {
		log.Fatalf("Failed to fetch users: %v", err)
	}
	// Step 3: Write user data to a CSV file
	outputFilePath := "AzureAD_Users.csv"
	if err := writeUsersToCSV(users, outputFilePath); err != nil {
		log.Fatalf("Failed to write users to CSV: %v", err)
	}

	fmt.Printf("User export completed. File saved at: %s\n", outputFilePath)
}
