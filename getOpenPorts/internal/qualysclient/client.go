package qualysclient

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type Client struct {
    BaseURL    string
    HTTPClient *http.Client
    Token      string
    Username   string
    Password   string
}

func NewHTTPClient(timeout time.Duration) *http.Client {
    return &http.Client{Timeout: timeout}
}
// getToken gets JWT or performs /auth if username/password are provided.
// Handles both JSON { "token": "..." } and plain-text token bodies.
func (c *Client) getToken() (string, error) {
    if c.Token != "" {
        return c.Token, nil
    }
    if c.Username == "" || c.Password == "" {
        return "", fmt.Errorf("no token provided and no username/password for /auth")
    }

    authURL := strings.TrimRight(c.BaseURL, "/") + "/auth"
    data := url.Values{}
    data.Set("username", c.Username)
    data.Set("password", c.Password)
    data.Set("token", "true")

    req, err := http.NewRequest("POST", authURL, strings.NewReader(data.Encode()))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return "", fmt.Errorf("auth request failed: %w", err)
    }
    defer resp.Body.Close()

    bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
    bodyStr := strings.TrimSpace(string(bodyBytes))

    // Try JSON first: { "token": "..." }
    var authResp struct {
        Token string `json:"token"`
    }
    if err := json.Unmarshal(bodyBytes, &authResp); err == nil && authResp.Token != "" {
        c.Token = authResp.Token
        return c.Token, nil
    }

    // Fallback: plain-text token in body (what you're seeing now)
    if bodyStr != "" && strings.Count(bodyStr, ".") >= 2 {
        // Very rough "looks like a JWT" check: header.payload.signature
        c.Token = bodyStr
        return c.Token, nil
    }

    return "", fmt.Errorf("auth failed: status %d, body: %s", resp.StatusCode, bodyStr)
}
