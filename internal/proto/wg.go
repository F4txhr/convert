package proto

import (
	"net/url"
	"strconv"
	"vpn-conv/internal/core"
)

type WGParser struct{}

func (p WGParser) Scheme() string {
	return "wg"
}

func (p WGParser) Parse(uri string) (core.Profile, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return core.Profile{}, err
	}

	port, _ := strconv.Atoi(u.Port())

	extra := make(map[string]string)
	query := u.Query()
	for key := range query {
		extra[key] = query.Get(key)
	}

	// The private key is typically the userinfo part of the URL
	// Some formats use it as username, some as password. We check both.
	privateKey := u.User.Username()

	return core.Profile{
		ID:     u.Fragment,
		Proto:  "wg",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"private_key": privateKey},
		Extra:  extra,
	}, nil
}
