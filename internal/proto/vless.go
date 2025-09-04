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

	// The user's python script shows a more complex logic for the tag, let's use that.
	tag, _ := url.PathUnescape(u.Fragment)
	if tag == "" {
		tag = u.Hostname() // Fallback to hostname if fragment is empty
	}

	profile := core.Profile{
		ID:     tag,
		Proto:  "vless",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"uuid": u.User.Username()},
		Extra:  make(map[string]interface{}), // For extra fields like flow, reality, etc.
	}

	// Add all query params to Extra for the exporter to use
	for key, values := range query {
		if len(values) > 0 {
			profile.Extra[key] = values[0]
		}
	}

	// Populate structured TLS settings based on Python script logic
	if security := query.Get("security"); security != "" && security != "none" {
		sni := query.Get("sni")
		if sni == "" {
			sni = query.Get("peer") // fallback to 'peer'
		}

		profile.TLS = &core.TLSSettings{
			Enabled:    true,
			ServerName: sni,
			Insecure:   query.Get("allowInsecure") != "0", // Defaults to true if not "0"
		}
	}

	// Populate structured Transport settings based on Python script logic
	if transportType := query.Get("type"); transportType != "" {
		host := query.Get("host")
		if host == "" && profile.TLS != nil {
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
