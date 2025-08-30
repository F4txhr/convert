package export

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"vpn-conv/internal/core"
)

type SingboxExporter struct{}

func (s SingboxExporter) Name() string { return "singbox" }

// createSingboxProxy converts a core.Profile into a detailed Sing-box outbound map.
func createSingboxProxy(p core.Profile) map[string]interface{} {
	// Base proxy object
	proxy := map[string]interface{}{
		"type":            p.Proto,
		"tag":             p.ID,
		"server":          p.Server,
		"server_port":     p.Port,
		"domain_strategy": "ipv4_only", // Smart Default
	}

	// Protocol-specific fields
	switch p.Proto {
	case "vmess":
		proxy["uuid"] = p.Auth["uuid"]
		proxy["security"] = "zero"
		proxy["alter_id"] = 0
		proxy["packet_encoding"] = "xudp"
	case "vless":
		proxy["uuid"] = p.Auth["uuid"]
		proxy["packet_encoding"] = "xudp"
	case "trojan":
		proxy["password"] = p.Auth["password"]
	case "ss":
		// Per user request, generate the non-standard Clash-like format for SS
		proxy["method"] = p.Auth["method"]
		proxy["password"] = p.Auth["password"]
		if pluginName, ok := p.Extra["plugin"]; ok {
			proxy["plugin"] = pluginName

			// Build the plugin_opts string from Extra map
			var opts []string
			if mux, ok := p.Extra["mux"]; ok { // This is a hypothetical field for demo
				opts = append(opts, "mux="+mux)
			}
			if path, ok := p.Extra["path"]; ok {
				opts = append(opts, "path="+path)
			}
			if host, ok := p.Extra["host"]; ok {
				opts = append(opts, "host="+host)
			}
			if _, ok := p.Extra["tls"]; ok {
				opts = append(opts, "tls=1")
			}
			proxy["plugin_opts"] = strings.Join(opts, ";")
		}
		// Return early for SS as its structure is completely different
		return proxy
	case "wg":
		proxy["local_address"] = []string{"172.19.0.2/32"} // Smart Default
		proxy["private_key"] = p.Auth["private_key"]
		proxy["peer_public_key"] = p.Extra["publicKey"]
		// 'reserved' can be added if present in Extra
		return proxy // WG has a simpler structure, return early
	}

	// Common settings for VLESS, VMess, Trojan
	// TLS Settings
	if security, ok := p.Extra["security"]; ok && (security == "tls" || security == "reality") {
		tlsSettings := map[string]interface{}{
			"enabled":  true,
			"insecure": true, // Per user example
		}
		if sni, ok := p.Extra["sni"]; ok && sni != "" {
			tlsSettings["server_name"] = sni
		} else if host, ok := p.Extra["host"]; ok && host != "" {
			tlsSettings["server_name"] = host // Fallback to host for SNI
		}
		proxy["tls"] = tlsSettings
	}

	// Transport Settings (e.g., WebSocket)
	if transportType, ok := p.Extra["type"]; ok && transportType == "ws" {
		headers := make(map[string]string)
		if host, ok := p.Extra["host"]; ok {
			headers["Host"] = host
		}

		proxy["transport"] = map[string]interface{}{
			"type":                   "ws",
			"path":                   p.Extra["path"],
			"headers":                headers,
			"early_data_header_name": "Sec-WebSocket-Protocol", // Smart Default
		}
	}

	// Multiplex Settings
	proxy["multiplex"] = map[string]interface{}{
		"enabled":     true,
		"protocol":    "smux",
		"max_streams": 32,
	}

	return proxy
}

func (s SingboxExporter) Render(p core.Profile) (string, error) {
	log.Println("DEBUG: Using new Sing-box template exporter...")
	// 1. Read the template file
	templateBytes, err := os.ReadFile("configs/template_singbox.json")
	if err != nil {
		return "", fmt.Errorf("failed to read singbox template: %w", err)
	}

	// 2. Unmarshal into a map
	var config map[string]interface{}
	if err := json.Unmarshal(templateBytes, &config); err != nil {
		return "", fmt.Errorf("failed to parse singbox template: %w", err)
	}

	// 3. Create the new proxy outbound object
	newProxy := createSingboxProxy(p)

	// 4. Inject the new proxy into the main outbounds list
	outbounds, ok := config["outbounds"].([]interface{})
	if !ok {
		return "", fmt.Errorf("template 'outbounds' is not a list")
	}
	config["outbounds"] = append(outbounds, newProxy)

	// 5. Inject the proxy tag into the correct groups
	proxyTag := p.ID
	groupsToUpdate := []string{"Internet", "Best Latency 🚀"}
	if strings.Contains(proxyTag, "🇮🇩") {
		groupsToUpdate = append(groupsToUpdate, "Latency ID")
	}
	if strings.Contains(proxyTag, "🇸🇬") {
		groupsToUpdate = append(groupsToUpdate, "Latency SG")
	}

	// We need to modify the original slice, so we iterate with an index.
	for i, outboundInterface := range outbounds {
		group, isMap := outboundInterface.(map[string]interface{})
		if !isMap {
			continue
		}

		tag, hasTag := group["tag"].(string)
		if !hasTag {
			continue
		}

		for _, groupToUpdate := range groupsToUpdate {
			if tag == groupToUpdate {
				groupOutbounds, ok := group["outbounds"].([]interface{})
				if !ok {
					continue
				}
				group["outbounds"] = append(groupOutbounds, proxyTag)
				// Re-assign the modified map back to the slice
				outbounds[i] = group
			}
		}
	}

	// 5.5: Add direct fallback to empty url-test groups
	for i, outboundInterface := range outbounds {
		group, isMap := outboundInterface.(map[string]interface{})
		if !isMap {
			continue
		}

		groupType, hasType := group["type"].(string)
		if !hasType || groupType != "urltest" {
			continue
		}

		groupOutbounds, ok := group["outbounds"].([]interface{})
		if !ok || len(groupOutbounds) == 0 {
			group["outbounds"] = []interface{}{"direct 🚸"}
			outbounds[i] = group
		}
	}

	// 6. Marshal the modified config back to JSON
	finalJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal final singbox config: %w", err)
	}

	return string(finalJSON), nil
}
