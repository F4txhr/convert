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

func (p SSParser) Parse(uri string) (core.Profile, error) {
	// Ensure the URI has the prefix for consistent parsing, especially for recursive calls.
	if !strings.HasPrefix(uri, "ss://") {
		uri = "ss://" + uri
	}

	raw := strings.TrimPrefix(uri, "ss://")

	// ss://method:password@host:port
	// This part can also be base64 encoded.

	if strings.Contains(raw, "@") {
		u, err := url.Parse(uri)
		if err != nil {
			return core.Profile{}, err
		}

		port, _ := strconv.Atoi(u.Port())

		// Original code used `strings.Split(u.User.Username(), ":")` which is unsafe.
		// Using SplitN is safer.
		parts := strings.SplitN(u.User.Username(), ":", 2)
		method := ""
		password := ""
		if len(parts) > 0 {
			method = parts[0]
		}
		if len(parts) > 1 {
			password = parts[1]
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
		}, nil
	}

	// If no "@", assume base64 encoded string.
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return core.Profile{}, err
	}

	// Recursively parse the decoded content.
	return p.Parse(string(decoded))
}
