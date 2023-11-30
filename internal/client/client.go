package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/lllamnyp/oidc/internal/token"
)

type confidentialClient struct {
	clientID      string
	clientSecret  string
	tokenEndpoint string
}

func (c *confidentialClient) Token() token.Token {
	vals := url.Values{}
	vals.Add("client_id", c.clientID)
	vals.Add("client_secret", c.clientSecret)
	vals.Add("grant_type", "client_credentials")
	req, err := http.NewRequest(
		http.MethodPost,
		c.tokenEndpoint,
		strings.NewReader(vals.Encode()),
	)
	if err != nil {
		return token.Token{}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return token.Token{}
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	tok := token.Token{}
	err = dec.Decode(&tok)
	if err != nil {
		return token.Token{}
	}
	return tok
}

func NewConfidentialClient(clientID, clientSecret, issuerURL string) *confidentialClient {
	endpoint, err := getTokenEndpoint(issuerURL)
	if err != nil {
		return nil
	}
	return &confidentialClient{clientID, clientSecret, endpoint}
}

func getTokenEndpoint(issuerURL string) (string, error) {
	resp, err := http.Get(issuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	v := make(map[string]interface{})
	err = json.Unmarshal(b, &v)
	if err != nil {
		return "", err
	}
	endpointIface, ok := v["token_endpoint"]
	if !ok {
		return "", fmt.Errorf("could not get token endpoint")
	}
	endpointStr, ok := endpointIface.(string)
	if !ok {
		return "", fmt.Errorf("could not get token endpoint")
	}
	return endpointStr, nil
}
