package jdownloader

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/imroc/req/v3"
)

type Client struct {
	http    *req.Client
	crypto  crypto
	email   string
	session *session
}

type Credentials struct {
	Email    string
	Password string
}

func NewClient(credentials Credentials) *Client {
	s := newSession(credentials)
	client := &Client{
		http: req.NewClient().
			SetBaseURL("http://api.jdownloader.org").
			OnBeforeRequest(s.signRequest).
			OnAfterResponse(s.decodeResponse),
		email:   credentials.Email,
		session: &s,
	}
	return client
}

func (c *Client) Connect() error {
	res, err := c.http.R().
		Post(buildURL("/my/connect",
			"email", strings.ToLower(c.email),
			"appkey", "jdown",
		))
	if err != nil {
		return fmt.Errorf("failed to send req: %w", err)
	}

	var response struct {
		ResponseID   int64  `json:"rid"`
		SessionToken string `json:"sessiontoken"`
		RegainToken  string `json:"regaintoken"`
	}
	if err := res.UnmarshalJson(&response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if err := c.session.VerifyRequestID(response.ResponseID); err != nil {
		return err
	}
	c.session.Update(response.SessionToken, response.RegainToken)

	return nil
}

// buildURL builds a URL with the given path and query parameters.
// We cannot use url.Values because MyJDownloader API returns an error
// if the query parameters are not specified in the right order.
func buildURL(path string, query ...string) string {
	var out strings.Builder

	out.WriteString(path)

	if !strings.Contains(path, "?") {
		out.WriteString("?")
	} else {
		out.WriteString("&")
	}

	for i := 0; i < len(query); i += 2 {
		k := query[i]
		v := query[i+1]

		out.WriteString(url.QueryEscape(k))
		out.WriteString("=")
		out.WriteString(url.QueryEscape(v))

		if i+2 < len(query) {
			out.WriteString("&")
		}
	}
	return out.String()
}

func (c *Client) Reconnect() error {
	res, err := c.http.R().
		Get(buildURL("/my/reconnect",
			"sessiontoken", c.session.SessionToken,
			"regaintoken", c.session.RegainToken,
		))
	if err != nil {
		return fmt.Errorf("failed to send req: %w", err)
	}

	var response struct {
		ResponseID   int64  `json:"rid"`
		SessionToken string `json:"sessiontoken"`
		RegainToken  string `json:"regaintoken"`
	}
	if err := res.UnmarshalJson(&response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if err := c.session.VerifyRequestID(response.ResponseID); err != nil {
		return err
	}

	c.session.Update(response.SessionToken, response.RegainToken)

	return nil
}
