package myjdownloader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/samber/lo"
	"golang.org/x/exp/slog"
)

type Client struct {
	http    *req.Client
	email   string
	session *session
}

type Credentials struct {
	Email    string
	Password string
}

const apiBaseURL = "https://api.jdownloader.org"
const appName = "jdown"

func NewClient(credentials Credentials) *Client {
	s := newSession(credentials)
	client := &Client{
		http: req.NewClient().
			SetUserAgent(appName).
			SetBaseURL(apiBaseURL).
			EnableDumpAll().
			WrapRoundTripFunc(func(rt req.RoundTripper) req.RoundTripFunc {
				return func(req *req.Request) (res *req.Response, err error) {
					return s.serverRoundTrip(rt, req)
				}
			}),
		email:   credentials.Email,
		session: &s,
	}
	return client
}

type encryptionKey struct{}

func (c *Client) Connect(ctx context.Context) error {
	ctx = context.WithValue(ctx, encryptionKey{}, c.session.LoginSecret())
	uri := newURL("/my/connect").
		AddQuery("email", strings.ToLower(c.email)).
		AddQuery("appkey", appName)

	res, err := c.http.R().
		SetContext(ctx).
		Post(uri.String())
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	var result struct {
		ResponseID   int64  `json:"rid"`
		SessionToken string `json:"sessiontoken"`
		RegainToken  string `json:"regaintoken"`
	}
	if err := res.UnmarshalJson(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if err := c.session.VerifyRequestID(result.ResponseID); err != nil {
		return err
	}
	c.session.Update(result.SessionToken, result.RegainToken)

	return nil
}

func (c *Client) Reconnect(ctx context.Context) error {
	uri := newURL("/my/reconnect").
		AddQuery("sessiontoken", c.session.SessionToken).
		AddQuery("regaintoken", c.session.RegainToken)
	res, err := c.http.R().
		SetContext(ctx).
		Get(uri.String())
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
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

func (c *Client) Disconnect(ctx context.Context) error {
	uri := newURL("/my/disconnect").
		AddQuery("sessiontoken", c.session.SessionToken)

	_, err := c.http.R().
		SetContext(ctx).
		Get(uri.String())
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	c.session = c.session.Clear()
	return nil
}

func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	uri := newURL("/my/listdevices").
		AddQuery("sessiontoken", c.session.SessionToken)
	res, err := c.http.R().
		SetContext(ctx).
		Get(uri.String())
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	var response struct {
		ResponseID int64    `json:"rid,omitempty"`
		Devices    []Device `json:"list"`
	}
	if err := res.UnmarshalJson(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return response.Devices, nil
}

var ErrDeviceNotFound = errors.New("device not found")

func (c *Client) Device(ctx context.Context, name string) (Device, error) {
	devices, err := c.ListDevices(ctx)
	if err != nil {
		return Device{}, fmt.Errorf("failed to list devices: %w", err)
	}
	for _, d := range devices {
		if d.Name == name {
			return d, nil
		}
	}
	return Device{}, fmt.Errorf("failed to get device %q: %w", name, ErrDeviceNotFound)
}

type Device struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type DeviceClient struct {
	device        Device
	session       *session
	http          *req.Client
	reconnectFunc func(ctx context.Context) error
	clockFunc     func() time.Time
}

func (c *Client) DeviceClient(d Device) *DeviceClient {
	return newDeviceClient(d, c)
}

type commaList []string

func (v commaList) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.Join(v, ","))
}

type addLinkParams struct {
	Links            commaList `json:"links"`
	PackageName      *string   `json:"packageName"`
	DownloadPassword *string   `json:"downloadPassword"`
	ArchivePassword  *string   `json:"extractPassword"`
	AutoStart        *bool     `json:"autostart"`
	DownloadDir      *string   `json:"destinationFolder"`
}

func newDeviceClient(d Device, c *Client) *DeviceClient {
	return &DeviceClient{
		http: req.NewClient().
			SetBaseURL(apiBaseURL).
			SetUserAgent(appName).
			EnableDumpAll().
			OnBeforeRequest(func(_ *req.Client, req *req.Request) error {
				if c.session.connectedAt != nil && time.Now().Sub(*c.session.connectedAt) > 30*time.Second {
					slog.Debug("refreshing tokens", "last_connected_at", *c.session.connectedAt)
					return c.Reconnect(req.Context())
				}
				return nil
			}).
			WrapRoundTripFunc(func(rt req.RoundTripper) req.RoundTripFunc {
				return func(req *req.Request) (*req.Response, error) {
					return c.session.deviceRoundTrip(rt, req, d)
				}
			}),
		reconnectFunc: c.Reconnect,
		clockFunc:     time.Now,
		device:        d,
		session:       c.session,
	}
}

func (c *DeviceClient) AddLink(ctx context.Context, packageName string, urls ...string) error {
	params := addLinkParams{
		Links:       urls,
		PackageName: &packageName,
		AutoStart:   lo.ToPtr(false),
	}
	res, err := c.http.R().
		SetContext(ctx).
		SetBodyJsonMarshal(params).
		Post("/linkgrabberv2/addLinks")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	type data struct {
		ID int64 `json:"id"`
	}

	var response struct {
		ResponseID int64  `json:"rid"`
		Data       data   `json:"data,omitempty"`
		Source     string `json:"src,omitempty"`
		Type       string `json:"type,omitempty"`
	}
	if err := res.UnmarshalJson(&response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	return nil
}

func (c *DeviceClient) StartDownload(ctx context.Context) error {
	_, err := c.http.R().
		SetContext(ctx).
		Post("/downloadcontroller/start")
	return err
}

func (c *DeviceClient) StopDownload(ctx context.Context) error {
	_, err := c.http.R().
		SetContext(ctx).
		Post("/downloadcontroller/stop")
	return err
}
