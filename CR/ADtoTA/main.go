package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type DataPacket struct {
	SystemType string `json:"SystemType"`
	DataType   string `json:"DataType"`
	Data       string `json:"Data"`
	ChunkId    int    `json:"ChunkId"`
	LastChunk  bool   `json:"LastChunk"`
	RunKey     string `json:"RunKey"`
	TenantId   string `json:"TenantId"`
}

var (
	ldapURL            = "ldap://your-ad-server.local"
	ldapBindDN         = "CN=yourbinduser,CN=Users,DC=domain,DC=local"
	ldapBindPwd        = "yourpassword"
	baseDN             = "DC=domain,DC=local"
	pageSize           = uint32(1000)
	userAttributes     = []string{"givenName", "sn", "userPrincipalName", "sAMAccountName", "distinguishedName", "displayName"}
	computerAttributes = []string{"dNSHostName", "sAMAccountName", "distinguishedName", "name", "operatingSystem"}
)

func main() {
	subdomain := os.Getenv("SUBDOMAIN")
	token := os.Getenv("TOKEN")
	tenantID := os.Getenv("TENANT_ID")
	threatAwareUrl := fmt.Sprintf("https://%s.threataware.com/api/onprem/send-data", subdomain)

	runKey := time.Now().UTC().Format("200601021504")
	log.Printf("Sending data to; url: %s, job key: %s", threatAwareUrl, runKey)

	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		log.Fatalf("LDAP connect failed: %v", err)
	}
	defer conn.Close()

	err = conn.Bind(ldapBindDN, ldapBindPwd)
	if err != nil {
		log.Fatalf("LDAP bind failed: %v", err)
	}

	processData(conn, threatAwareUrl, token, tenantID, runKey, "users", "(objectClass=user)", userAttributes)
	processData(conn, threatAwareUrl, token, tenantID, runKey, "computers", "(objectClass=computer)", computerAttributes)
}

func processData(conn *ldap.Conn, url, token, tenantID, runKey, dataType, filter string, attributes []string) {
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	sr, err := conn.SearchWithPaging(searchReq, pageSize)
	if err != nil {
		log.Fatalf("LDAP search failed: %v", err)
	}

	chunk := []map[string]string{}
	chunkId := 1
	total := 0

	for _, entry := range sr.Entries {
		obj := make(map[string]string)
		for _, attr := range attributes {
			obj[attr] = strings.Join(entry.GetAttributeValues(attr), ",")
		}
		chunk = append(chunk, obj)
		total++

		if len(chunk) >= 1000 {
			err = sendData(url, token, tenantID, runKey, dataType, chunkId, chunk, false)
			if err != nil {
				log.Printf("Error sending chunk %d: %v", chunkId, err)
			}
			chunk = []map[string]string{}
			chunkId++
		}
	}

	if len(chunk) > 0 {
		err = sendData(url, token, tenantID, runKey, dataType, chunkId, chunk, true)
		if err != nil {
			log.Printf("Error sending final chunk %d: %v", chunkId, err)
		}
	}

	log.Printf("Completed %s; Total Sent: %d", dataType, total)
}

func sendData(url, token, tenantID, runKey, dataType string, chunkId int, data []map[string]string, lastChunk bool) error {
	payload := DataPacket{
		SystemType: "onpremad",
		DataType:   dataType,
		Data:       mustMarshal(data),
		ChunkId:    chunkId,
		LastChunk:  lastChunk,
		RunKey:     runKey,
		TenantId:   tenantID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	maxRetries := 3
	delay := 2 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ThreatAware-ApiKey", token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode >= 300 {
			if attempt < maxRetries {
				log.Printf("Retry sending chunk %d, attempt %d", chunkId, attempt+1)
				time.Sleep(delay)
				delay *= 2
				continue
			} else {
				if err == nil {
					err = fmt.Errorf("received status code %d", resp.StatusCode)
				}
				log.Printf("Failed sending chunk %d after %d attempts: %v", chunkId, maxRetries+1, err)
				return err
			}
		}
		// Successfully sent
		log.Printf(".... Sent; chunk: %d", chunkId)
		resp.Body.Close()
		return nil
	}
	return nil
}

func mustMarshal(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		log.Fatalf("JSON marshal failed: %v", err)
	}
	return string(b)
}
