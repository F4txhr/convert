package proto

import (
	"encoding/base64"
	"log"
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
	log.Printf("[SSParser DEBUG] Received URI: %s", uri)

	var fragment string
	if strings.Contains(uri, "#") {
		parts := strings.SplitN(uri, "#", 2)
		uri = parts[0]
		fragment = parts[1]
	}

	rawURL := strings.TrimPrefix(uri, "ss://")

	// If no "@" symbol, it's a fully base64 encoded URI body.
	if !strings.Contains(rawURL, "@") {
		log.Printf("[SSParser DEBUG] No '@' found, assuming full base64 body.")
		decoded, err := base64.StdEncoding.DecodeString(rawURL)
		if err != nil {
			log.Printf("[SSParser DEBUG] Failed to decode full body: %v", err)
			return core.Profile{}, err
		}
		recursiveURI := "ss://" + string(decoded)
		if fragment != "" {
			recursiveURI += "#" + fragment
		}
		log.Printf("[SSParser DEBUG] Recursively parsing decoded URI: %s", recursiveURI)
		return p.Parse(recursiveURI)
	}

	// At this point, we have a plain URI with an "@" symbol.
	fullURI := "ss://" + rawURL
	if fragment != "" {
		fullURI += "#" + fragment
	}
	u, err := url.Parse(fullURI)
	if err != nil {
		log.Printf("[SSParser DEBUG] url.Parse failed: %v", err)
		return core.Profile{}, err
	}

	port, _ := strconv.Atoi(u.Port())

	var method, password string
	if u.User != nil {
		pass, passSet := u.User.Password()
		log.Printf("[SSParser DEBUG] url.Parse result: Username='%s', Password set: %v", u.User.Username(), passSet)

		if passSet {
			// Standard `method:password` format.
			method = u.User.Username()
			password = pass
			log.Printf("[SSParser DEBUG] Plain user:pass found. Method: %s, Pass: %s", method, password)
		} else {
			// The whole userinfo is in the username field.
			// This part could be plain text or base64.
			userInfo := u.User.Username()
			log.Printf("[SSParser DEBUG] No password found, userinfo is: '%s'. Attempting base64 decode.", userInfo)

			decoded, err := base64.StdEncoding.DecodeString(userInfo)
			toParse := userInfo
			if err == nil {
				toParse = string(decoded)
				log.Printf("[SSParser DEBUG] Base64 decode SUCCESS. Decoded string: '%s'", toParse)
			} else {
				log.Printf("[SSParser DEBUG] Base64 decode FAILED. Assuming plain text. Error: %v", err)
			}

			parts := strings.SplitN(toParse, ":", 2)
			if len(parts) > 0 {
				method = parts[0]
			}
			if len(parts) > 1 {
				password = parts[1]
			}
		}
	} else {
		log.Printf("[SSParser DEBUG] No user info found.")
	}

	log.Printf("[SSParser DEBUG] Final extracted credentials -> Method: '%s', Password: '%s'", method, password)


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
