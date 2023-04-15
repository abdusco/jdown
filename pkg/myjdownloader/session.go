package myjdownloader

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/imroc/req/v3"
)

type session struct {
	connectedAt           *time.Time
	RequestID             int64
	SessionToken          string
	RegainToken           string
	ServerEncryptionToken []byte
	DeviceEncryptionToken []byte
	crypto                crypto
}

func newSession(c Credentials) session {
	s := session{crypto: crypto{c}}
	return s
}

func (s *session) NextRequestID() int64 {
	return atomic.AddInt64(&s.RequestID, 1)
}

var errRequestIDMismatch = errors.New("request id mismatch")

func (s *session) VerifyRequestID(id int64) error {
	if s.RequestID != id {
		return errRequestIDMismatch
	}
	return nil
}

func (s *session) Update(sessionToken string, regainToken string) {
	s.SessionToken = sessionToken
	s.RegainToken = regainToken

	token, _ := hex.DecodeString(sessionToken)

	if s.connectedAt == nil {
		s.ServerEncryptionToken = s.crypto.LoginSecret()
		s.DeviceEncryptionToken = s.crypto.DeviceSecret()
	}
	s.ServerEncryptionToken = s.sha256(append(s.ServerEncryptionToken, token...))
	s.DeviceEncryptionToken = s.sha256(append(s.DeviceEncryptionToken, token...))

	now := time.Now()
	s.connectedAt = &now
}

func (s *session) sha256(b []byte) []byte {
	hash := sha256.Sum256(b)
	return hash[:]
}

func (s *session) LoginSecret() []byte {
	return s.crypto.LoginSecret()
}

func (s *session) Clear() *session {
	return &session{crypto: s.crypto}
}

type wrappedPayload struct {
	APIVersion uint   `json:"apiVer"`
	URL        string `json:"url"`
	Params     []any  `json:"params"`
	RequestID  int64  `json:"rid"`
}

func (s *session) serverRoundTrip(rt req.RoundTripper, r *req.Request) (*req.Response, error) {
	uri := newURL(r.URL.String()).AddQuery("rid", s.NextRequestID())
	key, ok := r.Context().Value(encryptionKey{}).([]byte)
	if !ok {
		key = s.ServerEncryptionToken
	}
	signature := s.crypto.Sign(key, []byte(uri.URL().RequestURI()))
	uri.AddQuery("signature", signature)
	r.URL = uri.URL()

	if r.Method == http.MethodPost {
		r.SetContentType("application/aesjson-jd; charset=utf-8")
	}

	res, err := rt.RoundTrip(r)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	body, err := res.ToString()
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if res.IsErrorState() {
		var response struct {
			Source string `json:"src"`
			Type   string `json:"type"`
		}
		if err := res.UnmarshalJson(&response); err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response as json: %w", err)
		}
		return nil, fmt.Errorf("received HTTP %d response: error: %s", res.StatusCode, response.Type)
	}

	decodedBody, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode body as base64: %w", err)
	}

	plaintextBody, err := s.crypto.Decrypt(key[:], decodedBody)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt body: %w", err)
	}

	httpRes := res.Response
	httpRes.Body = io.NopCloser(bytes.NewReader(plaintextBody))
	httpRes.Header.Set("content-type", "application/json; charset=utf-8")
	return &req.Response{
		Response: httpRes,
		Err:      res.Err,
		Request:  res.Request,
	}, nil
}

func (s *session) deviceRoundTrip(rt req.RoundTripper, r *req.Request, device Device) (*req.Response, error) {
	action := r.URL.Path
	var params []any
	if len(r.Body) > 0 {
		params = []any{string(r.Body)}
	}
	payload := wrappedPayload{
		APIVersion: 1,
		URL:        action,
		Params:     params,
		RequestID:  s.NextRequestID(),
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal body: %w", err)
	}

	encrypted, err := s.crypto.Encrypt(s.DeviceEncryptionToken, b)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt body: %w", err)
	}

	r.SetBodyString(base64.StdEncoding.EncodeToString(encrypted))
	r.SetContentType("application/aesjson-jd; charset=utf-8")

	r.URL.Path = fmt.Sprintf(
		"/t_%s_%s%s",
		url.PathEscape(s.SessionToken),
		url.PathEscape(device.ID),
		r.URL.Path,
	)

	res, err := rt.RoundTrip(r)
	if err != nil {
		return res, fmt.Errorf("failed to send request: %w", err)
	}

	body, err := res.ToString()
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if !strings.HasPrefix(body, "{") {
		// not JSON, possibly still encrypted

		decodedBody, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("failed to decode body as base64: %w", err)
		}

		plaintextBody, err := s.crypto.Decrypt(s.DeviceEncryptionToken, decodedBody)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt body: %w", err)
		}
		// recreate response as plaintext JSON
		res.Response.Body = io.NopCloser(bytes.NewReader(plaintextBody))
		res = &req.Response{
			Response: res.Response,
			Err:      nil,
			Request:  r,
		}
		res.Header.Set("content-type", "application/json; charset=utf-8")
	}

	if res.IsErrorState() {
		var errorResult struct {
			Source string `json:"src"`
			Type   string `json:"type"`
		}
		if err := res.UnmarshalJson(&errorResult); err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response as json: %w", err)
		}
		return nil, fmt.Errorf("received HTTP %d response: error: %s", res.StatusCode, errorResult.Type)
	}

	var verifiable struct {
		RequestID int64 `json:"rid"`
	}
	if err := res.UnmarshalJson(&verifiable); err == nil {
		if err := s.VerifyRequestID(verifiable.RequestID); err != nil {
			return nil, err
		}
	}

	return res, nil
}
