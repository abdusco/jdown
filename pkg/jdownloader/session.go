package jdownloader

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"

	"github.com/imroc/req/v3"
)

func (s *session) signRequest(_ *req.Client, req *req.Request) error {
	req.RawURL = buildURL(req.RawURL, "rid", s.NextRequestID())

	key := s.Key()
	signed := s.crypto.Sign(key, req.RawURL)
	req.RawURL = buildURL(req.RawURL, "signature", url.QueryEscape(signed))

	if req.Method == http.MethodPost {
		req.SetContentType("application/aesjson-jd; charset=utf-8")
	}

	return nil
}

func (s *session) decodeResponse(_ *req.Client, res *req.Response) error {
	body, err := res.ToString()
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if res.IsErrorState() {
		var response struct {
			Source string `json:"src"`
			Type   string `json:"type"`
		}
		if err := res.UnmarshalJson(&response); err != nil {
			return fmt.Errorf("failed to unmarshal error response as json: %w", err)
		}
		return fmt.Errorf("received HTTP %d response: error: %s", res.StatusCode, response.Type)
	}

	decodedBody, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return fmt.Errorf("failed to decode body as base64: %w", err)
	}

	key := s.Key()
	plaintextBody, err := s.crypto.Decrypt(key[:], decodedBody)
	if err != nil {
		return fmt.Errorf("failed to decrypt body: %w", err)
	}

	httpRes := res.Response
	httpRes.Body = io.NopCloser(bytes.NewReader(plaintextBody))
	httpRes.Header.Set("content-type", "application/json; charset=utf-8")
	*res = req.Response{
		Response: httpRes,
		Err:      res.Err,
		Request:  res.Request,
	}

	return nil
}

type session struct {
	connected             bool
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

func (s *session) NextRequestID() string {
	return strconv.FormatInt(atomic.AddInt64(&s.RequestID, 1), 10)
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

	if !s.connected {
		s.ServerEncryptionToken = s.crypto.LoginSecret()
		s.DeviceEncryptionToken = s.crypto.DeviceSecret()
	}
	s.ServerEncryptionToken = s.sha256(append(s.ServerEncryptionToken, token...))
	s.DeviceEncryptionToken = s.sha256(append(s.DeviceEncryptionToken, token...))

	s.connected = sessionToken != ""
}

func (s *session) sha256(b []byte) []byte {
	hash := sha256.Sum256(b)
	return hash[:]
}

func (s *session) Key() []byte {
	if !s.connected {
		return s.crypto.LoginSecret()
	}
	return s.ServerEncryptionToken
}
