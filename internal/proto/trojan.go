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
	query := u.Query()

	profile := core.Profile{
		ID:     u.Fragment,
		Proto:  "trojan",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"password": u.User.Username()},
	}

	// Trojan always implies TLS
	profile.TLS = &core.TLSSettings{
		Enabled:    true,
		ServerName: query.Get("sni"),
		Insecure:   query.Get("insecure") == "true",
	}

	// Populate structured Transport settings
	if transportType := query.Get("type"); transportType != "" {
		profile.Transport = &core.TransportSettings{
			Type:        transportType,
			Path:        query.Get("path"),
			Host:        query.Get("host"),
			ServiceName: query.Get("serviceName"),
		}
	}

	return profile, nil
}
