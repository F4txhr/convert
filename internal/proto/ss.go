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
	var fragment string
	if strings.Contains(uri, "#") {
		parts := strings.SplitN(uri, "#", 2)
		uri = parts[0]
		fragment = parts[1]
	}

	rawURL := strings.TrimPrefix(uri, "ss://")

	// If no "@" symbol, it's a fully base64 encoded URI body.
	if !strings.Contains(rawURL, "@") {
		decoded, err := base64.StdEncoding.DecodeString(rawURL)
		if err != nil {
			return core.Profile{}, err
		}
		recursiveURI := "ss://" + string(decoded)
		if fragment != "" {
			recursiveURI += "#" + fragment
		}
		return p.Parse(recursiveURI)
	}

	// At this point, we have a plain URI with an "@" symbol.
	fullURI := "ss://" + rawURL
	if fragment != "" {
		fullURI += "#" + fragment
	}
	u, err := url.Parse(fullURI)
	if err != nil {
		return core.Profile{}, err
	}

	port, _ := strconv.Atoi(u.Port())

	var method, password string
	if u.User != nil {
		// url.Parse is smart. If userinfo is `user:pass`, it splits them.
		// If there's no colon, the whole thing is the Username.
		pass, passSet := u.User.Password()
		if passSet {
			// Standard `method:password` format.
			method = u.User.Username()
			password = pass
		} else {
			// The whole userinfo is in the username field.
			// This part could be plain text or base64.
			userInfo := u.User.Username()
			toParse := userInfo
			// Try to decode it. If successful, use the decoded string.
			if decoded, err := base64.StdEncoding.DecodeString(userInfo); err == nil {
				toParse = string(decoded)
			}

			parts := strings.SplitN(toParse, ":", 2)
			if len(parts) > 0 {
				method = parts[0]
			}
			if len(parts) > 1 {
				password = parts[1]
			}
		}
	}

	// Parse plugin options from query parameters.
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
