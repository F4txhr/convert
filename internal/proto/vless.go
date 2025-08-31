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
	query := u.Query()

	profile := core.Profile{
		ID:     u.Fragment,
		Proto:  "vless",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"uuid": u.User.Username()},
	}

	// Populate structured TLS settings
	if security := query.Get("security"); security == "tls" || security == "reality" {
		profile.TLS = &core.TLSSettings{
			Enabled:    true,
			ServerName: query.Get("sni"),
			Insecure:   query.Get("insecure") == "true",
		}
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
