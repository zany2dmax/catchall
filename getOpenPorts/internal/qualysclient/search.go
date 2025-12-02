package qualysclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (c *Client) SearchAssetsByIP(ip string) ([]Asset, error) {
	f := FilterRequest{
		Filters: []FilterCriteria{
			{
				Field:    "interfaces.address",
				Operator: "EQUALS",
				Value:    ip,
			},
		},
	}
	return c.searchAssets(f)
}

func (c *Client) SearchAssetsByIPBatch(ips []string) ([]Asset, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	f := FilterRequest{
		Filters: []FilterCriteria{
			{
				Field:    "interfaces.address",
				Operator: "IN",
				Value:    ips,
			},
		},
	}
	return c.searchAssets(f)
}

// searchAssets executes /rest/2.0/search/am/asset with pagination, using the given filter.
func (c *Client) searchAssets(filter FilterRequest) ([]Asset, error) {
	token, err := c.getToken()
	if err != nil {
		return nil, err
	}

	base := strings.TrimRight(c.BaseURL, "/") + "/rest/2.0/search/am/asset"

	q := url.Values{}
	q.Set("includeFields", "address,networkInterface,openPort")

	var all []Asset
	var lastSeen *int64

	for {
		u := base + "?" + q.Encode()
		if lastSeen != nil {
			u = fmt.Sprintf("%s&lastSeenAssetId=%d", u, *lastSeen)
		}

		body, err := json.Marshal(filter)
		if err != nil {
			return nil, fmt.Errorf("marshal filter: %w", err)
		}

		req, err := http.NewRequest("POST", u, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("do request: %w", err)
		}
		defer resp.Body.Close()

		// Read body once per page
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := strings.TrimSpace(string(bodyBytes))

		// 204 or empty body = no assets (or no more assets)
		if resp.StatusCode == http.StatusNoContent || len(bodyBytes) == 0 {
			break
		}

		// Non-200 with some body → real error
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("search failed: status %d, body: %s", resp.StatusCode, bodyStr)
		}

		var r QualysSearchResponse
		if err := json.Unmarshal(bodyBytes, &r); err != nil {
			return nil, fmt.Errorf("decode response: %w; body: %s", err, bodyStr)
		}

		// If Qualys sends an explicit error
		if r.ResponseCode != "" && !strings.EqualFold(r.ResponseCode, "SUCCESS") {
			return nil, fmt.Errorf("Qualys error: %s (%s)", r.ResponseMessage, r.ResponseCode)
		}

		all = append(all, r.AssetListData.Assets...)

		if r.HasMore != 1 {
			break
		}
		lastSeen = &r.LastSeenAssetID
	}

	return all, nil
}
