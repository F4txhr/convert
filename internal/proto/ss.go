package proto

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"vpn-conv/internal/core"
)

type SSParser struct{}

func (p SSParser) Scheme() string {
	return "ss"
}

// fixB64Padding adds the required padding to a base64 string.
// This is a direct translation of the user's Python script's logic.
func fixB64Padding(s string) string {
	return s + strings.Repeat("=", (4-len(s)%4)%4)
}

// parsePluginString is a helper to parse the SS plugin string.
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
	var tag string
	if strings.Contains(uri, "#") {
		parts := strings.SplitN(uri, "#", 2)
		uri = parts[0]
		tag, _ = url.PathUnescape(parts[1])
	}

	param := strings.TrimPrefix(uri, "ss://")

	var method, password, server, query string
	var port int

	// This logic is inspired by the user's Python script to handle multiple SS formats.
	if !strings.Contains(param, "@") {
		// Case 1: Fully Base64 encoded URI body (ss://BASE64_BODY#tag)
		padded := fixB64Padding(param)
		decoded, err := base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return core.Profile{}, err
		}
		// Recursively call Parse on the decoded, now plain URI
		return p.Parse("ss://" + string(decoded) + "#" + tag)
	}

	// Case 2: URI with an @ symbol.
	// The user info part can be plain or base64.
	re := regexp.MustCompile(`(.*?)@(.*)`)
	matches := re.FindStringSubmatch(param)
	userInfoPart := matches[1]
	hostInfoPart := matches[2]

	// Try to decode the user info part
	cleanUserInfo, _ := url.QueryUnescape(userInfoPart)
	paddedUserInfo := fixB64Padding(cleanUserInfo)
	decodedCreds, err := base64.URLEncoding.DecodeString(paddedUserInfo)
	if err == nil {
		// Base64 decoding successful
		parts := strings.SplitN(string(decodedCreds), ":", 2)
		if len(parts) > 0 { method = parts[0] }
		if len(parts) > 1 { password = parts[1] }
	} else {
		// Fallback to plain text
		parts := strings.SplitN(cleanUserInfo, ":", 2)
		if len(parts) > 0 { method = parts[0] }
		if len(parts) > 1 { password = parts[1] }
	}

	// Parse the host info part
	hostPortAndQuery := strings.SplitN(hostInfoPart, "?", 2)
	hostPort := hostPortAndQuery[0]
	if len(hostPortAndQuery) > 1 {
		query = hostPortAndQuery[1]
	}

	hostPortParts := strings.SplitN(hostPort, ":", 2)
	server = hostPortParts[0]
	if len(hostPortParts) > 1 {
		port, _ = strconv.Atoi(hostPortParts[1])
	}

	// Construct the final profile
	profile := core.Profile{
		ID:     tag,
		Proto:  "ss",
		Server: server,
		Port:   port,
		Auth:   map[string]string{"method": method, "password": password},
	}

	// Parse query parameters for plugin/transport info
	parsedQuery, _ := url.ParseQuery(query)
	if pluginStr := parsedQuery.Get("plugin"); pluginStr != "" {
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
	} else {
		if transportType := parsedQuery.Get("type"); transportType != "" {
			profile.Transport = &core.TransportSettings{
				Type: transportType,
				Path: parsedQuery.Get("path"),
				Host: parsedQuery.Get("host"),
			}
		}
		if security := parsedQuery.Get("security"); security == "tls" {
			profile.TLS = &core.TLSSettings{
				Enabled:    true,
				ServerName: parsedQuery.Get("sni"),
			}
		}
	}

	return profile, nil
}
