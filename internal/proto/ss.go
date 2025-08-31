package proto

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"vpn-conv/internal/core"
)

type SSParser struct{}

func (p SSParser) Scheme() string {
	return "ss"
}

// parsePluginString takes a SIP002 plugin string and returns a map of options.
func parsePluginString(pluginStr string) map[string]string {
	opts := make(map[string]string)
	parts := strings.Split(pluginStr, ";")
	if len(parts) > 0 {
		opts["name"] = parts[0]
	}
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			opts[kv[0]] = kv[1]
		} else if len(kv) == 1 { // handles boolean flags like 'tls'
			opts[kv[0]] = "true"
		}
	}
	return opts
}

func (p SSParser) Parse(uri string) (core.Profile, error) {
	var fragment string
	if strings.Contains(uri, "#") {
		parts := strings.SplitN(uri, "#", 2)
		uri = parts[0]
		fragment = parts[1]
	}

	rawURL := strings.TrimPrefix(uri, "ss://")

	if !strings.Contains(rawURL, "@") {
		decoded, err := base64.RawStdEncoding.DecodeString(rawURL)
		if err != nil {
			return core.Profile{}, err
		}
		recursiveURI := "ss://" + string(decoded)
		if fragment != "" {
			recursiveURI += "#" + fragment
		}
		return p.Parse(recursiveURI)
	}

	parts := strings.SplitN(rawURL, "@", 2)
	userInfo := parts[0]
	hostInfo := parts[1]

	var method, password string
	decodedCreds, err := base64.RawStdEncoding.DecodeString(userInfo)
	toParse := userInfo
	if err == nil {
		toParse = string(decodedCreds)
	}
	credParts := strings.SplitN(toParse, ":", 2)
	if len(credParts) > 0 {
		method = credParts[0]
	}
	if len(credParts) > 1 {
		password = credParts[1]
	}

	u, err := url.Parse("ss://dummy@" + hostInfo)
	if err != nil {
		return core.Profile{}, err
	}
	port, _ := strconv.Atoi(u.Port())

	profile := core.Profile{
		ID:     fragment,
		Proto:  "ss",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"method": method, "password": password},
	}

	if pluginStr := u.Query().Get("plugin"); pluginStr != "" {
		pluginOpts := parsePluginString(pluginStr)
		profile.PluginOpts = pluginOpts

		// Populate structured fields from plugin options
		if name, ok := pluginOpts["name"]; ok && name == "v2ray-plugin" {
			profile.Transport = &core.TransportSettings{
				Type: "ws", // v2ray-plugin is typically for websockets
				Path: pluginOpts["path"],
				Host: pluginOpts["host"],
			}
		}

		if _, ok := pluginOpts["tls"]; ok {
			profile.TLS = &core.TLSSettings{
				Enabled:    true,
				ServerName: pluginOpts["host"], // In SS plugins, host is often used as SNI
			}
		}
	}

	return profile, nil
}
