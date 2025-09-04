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

	tag, _ := url.PathUnescape(u.Fragment)
	if tag == "" {
		tag = u.Hostname()
	}

	profile := core.Profile{
		ID:     tag,
		Proto:  "trojan",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"password": u.User.Username()},
		Extra:  make(map[string]interface{}),
	}

	// Trojan always implies TLS
	profile.TLS = &core.TLSSettings{
		Enabled:    true,
		ServerName: query.Get("sni"),
		Insecure:   query.Get("allowInsecure") == "1",
	}

	if fp := query.Get("fp"); fp != "" {
		profile.Extra["utls-fp"] = fp
	}
	if alpn := query.Get("alpn"); alpn != "" {
		profile.Extra["alpn"] = alpn
	}

	// Populate structured Transport settings
	if transportType := query.Get("type"); transportType != "" {
		host := query.Get("host")
		if host == "" {
			host = profile.TLS.ServerName
		}

		profile.Transport = &core.TransportSettings{
			Type:        transportType,
			Path:        query.Get("path"),
			Host:        host,
			ServiceName: query.Get("serviceName"),
		}
	}

	return profile, nil
}
