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
// Example: "v2ray-plugin;path=/ss-ws;host=cdn.domain.com"
func parsePluginString(pluginStr string) map[string]string {
	opts := make(map[string]string)
	parts := strings.Split(pluginStr, ";")

	if len(parts) > 0 {
		opts["plugin"] = parts[0]
	}

	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			opts[kv[0]] = kv[1]
		}
	}
	return opts
}

func (p SSParser) Parse(uri string) (core.Profile, error) {
	// Base64 decoding logic needs to handle the fragment correctly.
	// ss://BASE64PART#Fragment -> BASE64PART is `method:pass@host:port?plugin=...`
	var fragment string
	if strings.Contains(uri, "#") {
		parts := strings.SplitN(uri, "#", 2)
		uri = parts[0]
		fragment = parts[1]
	}

	rawURL := strings.TrimPrefix(uri, "ss://")

	// If no "@", assume base64 encoded string.
	if !strings.Contains(rawURL, "@") {
		decoded, err := base64.StdEncoding.DecodeString(rawURL)
		if err != nil {
			return core.Profile{}, err
		}
		// Re-attach fragment to the parsed content
		recursiveURI := "ss://" + string(decoded)
		if fragment != "" {
			recursiveURI += "#" + fragment
		}
		return p.Parse(recursiveURI)
	}

	// It's a plain URI now.
	fullURI := "ss://" + rawURL
	if fragment != "" {
		fullURI += "#" + fragment
	}
	u, err := url.Parse(fullURI)
	if err != nil {
		return core.Profile{}, err
	}

	port, _ := strconv.Atoi(u.Port())

	parts := strings.SplitN(u.User.Username(), ":", 2)
	method := ""
	password := ""
	if len(parts) > 0 {
		method = parts[0]
	}
	if len(parts) > 1 {
		password = parts[1]
	}

	extra := make(map[string]string)
	if pluginStr := u.Query().Get("plugin"); pluginStr != "" {
		pluginOpts := parsePluginString(pluginStr)
		for k, v := range pluginOpts {
			extra[k] = v
		}
	}

	return core.Profile{
		ID:     u.Fragment,
		Proto:  "ss",
		Server: u.Hostname(),
		Port:   port,
		Auth: map[string]string{
			"method":   method,
			"password": password,
		},
		Extra: extra,
	}, nil
}
