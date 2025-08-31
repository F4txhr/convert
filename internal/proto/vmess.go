package proto

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"vpn-conv/internal/core"
)

type VmessParser struct{}

func (p VmessParser) Scheme() string {
	return "vmess"
}

func (p VmessParser) Parse(uri string) (core.Profile, error) {
	raw := strings.TrimPrefix(uri, "vmess://")
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return core.Profile{}, err
	}

	var vm map[string]interface{}
	if err := json.Unmarshal(data, &vm); err != nil {
		return core.Profile{}, err
	}

	getString := func(key string) string {
		if val, ok := vm[key].(string); ok {
			return val
		}
		return ""
	}

	var port int
	switch p := vm["port"].(type) {
	case string:
		port, _ = strconv.Atoi(p)
	case float64:
		port = int(p)
	}

	profile := core.Profile{
		ID:     getString("ps"),
		Proto:  "vmess",
		Server: getString("add"),
		Port:   port,
		Auth:   map[string]string{"uuid": getString("id")},
	}

	// Populate structured TLS settings from vm map
	if tlsType := getString("tls"); tlsType == "tls" || tlsType == "reality" {
		profile.TLS = &core.TLSSettings{
			Enabled:    true,
			ServerName: getString("sni"),
			// In vmess links, "verify": false means insecure
			Insecure:   getString("verify") == "false",
		}
	}

	// Populate structured Transport settings from vm map
	if netType := getString("net"); netType != "" {
		profile.Transport = &core.TransportSettings{
			Type:        netType,
			Path:        getString("path"),
			Host:        getString("host"),
			ServiceName: getString("serviceName"),
		}
	}

	return profile, nil
}
