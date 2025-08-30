package proto

import (
	"net/url"
	"strconv"
	"vpn-conv/internal/core"
)

type TrojanParser struct{}

func (p TrojanParser) Scheme() string {
	return "trojan"
}

func (p TrojanParser) Parse(uri string) (core.Profile, error) {
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

	if u.Path != "" {
		extra["path"] = u.Path
	}

	return core.Profile{
		ID:     u.Fragment,
		Proto:  "trojan",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"password": u.User.Username()},
		Extra:  extra,
	}, nil
}
