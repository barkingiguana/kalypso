// Package kalypso provides a Go client for the Kalypso local dev SSL CA.
//
// Usage:
//
//	client := kalypso.NewClient("http://kalypso:8200")
//	cert, err := client.Issue(context.Background(), "myapp.local", "*.myapp.local")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	cert.Save("cert.pem", "key.pem")
package kalypso

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Certificate holds the PEM-encoded certificate bundle.
type Certificate struct {
	CertificatePEM   string   `json:"certificate"`
	PrivateKeyPEM    string   `json:"private_key"`
	CACertificatePEM string   `json:"ca_certificate"`
	Domains          []string `json:"domains"`
	NotAfter         string   `json:"not_after"`
}

// Save writes the certificate and key to files.
func (c *Certificate) Save(certPath, keyPath string) error {
	if err := os.WriteFile(certPath, []byte(c.CertificatePEM), 0644); err != nil {
		return fmt.Errorf("writing cert: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(c.PrivateKeyPEM), 0600); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	return nil
}

// SaveCA writes the CA certificate to a file.
func (c *Certificate) SaveCA(caPath string) error {
	return os.WriteFile(caPath, []byte(c.CACertificatePEM), 0644)
}

// Client communicates with a Kalypso CA server.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a new Kalypso client.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IssueRequest is the request body for issuing a certificate.
type IssueRequest struct {
	Domains     []string `json:"domains"`
	Hours       int      `json:"hours,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
}

// HealthResponse is the response from the health endpoint.
type HealthResponse struct {
	Status        string `json:"status"`
	CAInitialized bool   `json:"ca_initialized"`
	IssuedCount   int    `json:"issued_count"`
}

// Health checks the server health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var health HealthResponse
	if err := c.get(ctx, "/health", &health); err != nil {
		return nil, err
	}
	return &health, nil
}

// CACertificate returns the CA root certificate PEM.
func (c *Client) CACertificate(ctx context.Context) (string, error) {
	var resp struct {
		Certificate string `json:"certificate"`
	}
	if err := c.get(ctx, "/ca.pem", &resp); err != nil {
		return "", err
	}
	return resp.Certificate, nil
}

// Issue requests a new certificate for the given domains.
func (c *Client) Issue(ctx context.Context, domains ...string) (*Certificate, error) {
	return c.IssueWithOptions(ctx, IssueRequest{
		Domains: domains,
		Hours:   24,
	})
}

// IssueWithOptions requests a new certificate with full control over options.
func (c *Client) IssueWithOptions(ctx context.Context, req IssueRequest) (*Certificate, error) {
	var cert Certificate
	if err := c.post(ctx, "/certificates", req, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kalypso: %s %s returned %d: %s", req.Method, path, resp.StatusCode, body)
	}
	return json.Unmarshal(body, out)
}

func (c *Client) post(ctx context.Context, path string, payload, out interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kalypso: POST %s returned %d: %s", path, resp.StatusCode, body)
	}
	return json.Unmarshal(body, out)
}
