package jdownloader

import (
	"fmt"
	"net/url"
)

type urlWithOrderedQuery struct {
	url    *url.URL
	signed bool
}

func (u *urlWithOrderedQuery) URL() *url.URL {
	return u.url
}

func newURL(u string) *urlWithOrderedQuery {
	parsed, _ := url.Parse(u)
	return &urlWithOrderedQuery{
		url: parsed,
	}
}

func (u *urlWithOrderedQuery) String() string {
	return u.url.String()
}

func (u *urlWithOrderedQuery) AddQuery(k string, v any) *urlWithOrderedQuery {
	if u.signed {
		panic("cannot modify URL after signing it")
	}
	queryParam := fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(fmt.Sprintf("%v", v)))
	if u.url.RawQuery == "" {
		u.url.RawQuery = queryParam
	} else {
		u.url.RawQuery = u.url.RawQuery + "&" + queryParam
	}
	return u
}
