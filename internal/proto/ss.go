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
		} else if len(kv) == 1 {
			opts[kv[0]] = "true"
		}
	}
	return opts
}

func (p SSParser) Parse(uri string) (core.Profile, error) {
	var decodedFragment string
	if strings.Contains(uri, "#") {
		parts := strings.SplitN(uri, "#", 2)
		uri = parts[0]
		decodedFragment, _ = url.PathUnescape(parts[1])
	}

	rawURL := strings.TrimPrefix(uri, "ss://")

	if !strings.Contains(rawURL, "@") {
		// Use RawURLEncoding to be lenient with padding
		decoded, err := base64.RawURLEncoding.DecodeString(rawURL)
		if err != nil {
			return core.Profile{}, err
		}
		recursiveURI := "ss://" + string(decoded)
		if decodedFragment != "" {
			recursiveURI += "#" + decodedFragment
		}
		return p.Parse(recursiveURI)
	}

	parts := strings.SplitN(rawURL, "@", 2)
	userInfoPart := parts[0]
	hostInfoPart := parts[1]

	cleanUserInfo, err := url.QueryUnescape(userInfoPart)
	if err != nil {
		cleanUserInfo = userInfoPart // fallback to raw
	}

	var method, password string
	// Use RawURLEncoding, which correctly handles missing or improper padding.
	decodedCreds, err := base64.RawURLEncoding.DecodeString(cleanUserInfo)
	toParse := cleanUserInfo
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

	u, err := url.Parse("ss://dummy@" + hostInfoPart)
	if err != nil {
		return core.Profile{}, err
	}
	port, _ := strconv.Atoi(u.Port())

	profile := core.Profile{
		ID:     decodedFragment,
		Proto:  "ss",
		Server: u.Hostname(),
		Port:   port,
		Auth:   map[string]string{"method": method, "password": password},
	}

	if pluginStr := u.Query().Get("plugin"); pluginStr != "" {
		pluginOpts := parsePluginString(pluginStr)
		profile.PluginOpts = pluginOpts

		if name, ok := pluginOpts["name"]; ok && name == "v2ray-plugin" {
			profile.Transport = &core.TransportSettings{
				Type: "ws",
				Path: pluginOpts["path"],
				Host: pluginOpts["host"],
			}
		}
		if _, ok := pluginOpts["tls"]; ok {
			profile.TLS = &core.TLSSettings{
				Enabled:    true,
				ServerName: pluginOpts["host"],
			}
		}
	}

	return profile, nil
}
