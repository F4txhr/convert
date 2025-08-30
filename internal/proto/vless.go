package proto

import (
	"net/url"
	"strconv"
	"strings"
	"vpn-conv/internal/core"
)

type VlessParser struct{}

func (p VlessParser) Scheme() string {
	return "vless"
}

func (p VlessParser) Parse(uri string) (core.Profile, error) {
	raw := strings.TrimPrefix(uri, "vless://")
	u, err := url.Parse("vless://" + raw)
	if err != nil {
		return core.Profile{}, err
	}

	port, _ := strconv.Atoi(u.Port())

	return core.Profile{
		ID:     u.Fragment,
		Proto:  "vless",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"uuid": u.User.Username()},
		Extra:  map[string]string{"security": u.Query().Get("security")},
	}, nil
}
