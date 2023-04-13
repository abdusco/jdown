package jdownloader

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/imroc/req/v3"
)

type Client struct {
	http         *req.Client
	requestID    int64
	crypto       crypto
	email        string
	sessionToken string
	regainToken  string
}

type Credentials struct {
	Email    string
	Password string
}

func NewClient(credentials Credentials) *Client {
	c := &Client{
		http:   req.NewClient().SetBaseURL("https://api.jdownloader.org"),
		crypto: newCrypto(credentials),
		email:  credentials.Email,
	}
	c.http.OnBeforeRequest(c.signRequest)
	c.http.OnAfterResponse(c.decodeResponse)
	return c
}

func (c *Client) signRequest(_ *req.Client, req *req.Request) error {
	if req.Method != http.MethodPost {
		return nil
	}
	req.SetContentType("application/aesjson-jd; charset=utf-8")

	nextReqID := atomic.AddInt64(&c.requestID, 1)
	req.AddQueryParam("rid", fmt.Sprintf("%d", nextReqID))

	uri := req.RawURL + "?" + req.QueryParams.Encode()
	signed := c.crypto.sign(uri)
	req.AddQueryParam("signature", signed)

	return nil
}

func (c *Client) decodeResponse(_ *req.Client, res *req.Response) error {
	encoded, err := res.ToString()
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("failed to decode body as base64: %w", err)
	}

	m, err := c.crypto.decrypt(body)
	if err != nil {
		return fmt.Errorf("failed to decrypt body: %w", err)
	}
	httpRes := res.Response
	httpRes.Body = io.NopCloser(bytes.NewReader(m))
	httpRes.Header.Set("content-type", "application/json; charset=utf-8")
	*res = req.Response{
		Response: httpRes,
		Err:      res.Err,
		Request:  res.Request,
	}
	return nil
}

func (c *Client) Connect() error {
	res, err := c.http.R().
		SetQueryParams(map[string]string{
			"email":  strings.ToLower(c.email),
			"appkey": "",
		}).
		Post("/my/connect")
	if err != nil {
		return fmt.Errorf("failed to send req: %w", err)
	}

	var response struct {
		ResponseID   int64  `json:"rid"`
		SessionToken string `json:"sessiontoken"`
		RegainToken  string `json:"regaintoken"`
	}
	if err := res.Into(&response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	c.sessionToken = response.SessionToken
	c.regainToken = response.RegainToken
	// TODO: compare request ids

	return nil
}
