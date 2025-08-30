package proto

import (
	"net/url"
	"strconv"
	"vpn-conv/internal/core"
)

type VlessParser struct{}

func (p VlessParser) Scheme() string {
	return "vless"
}

func (p VlessParser) Parse(uri string) (core.Profile, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return core.Profile{}, err
	}

	port, _ := strconv.Atoi(u.Port())

	// Create the Extra map and populate it with all query parameters
	extra := make(map[string]string)
	query := u.Query()
	for key := range query {
		extra[key] = query.Get(key)
	}

	// Also add the path from the URL, if it exists
	if u.Path != "" {
		extra["path"] = u.Path
	}

	return core.Profile{
		ID:     u.Fragment,
		Proto:  "vless",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"uuid": u.User.Username()},
		Extra:  extra,
	}, nil
}
