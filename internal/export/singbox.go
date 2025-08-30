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
	proxy := map[string]interface{}{
		"type":        p.Proto,
		"tag":         p.ID,
		"server":      p.Server,
		"server_port": p.Port,
	}

	// Add protocol-specific auth details
	switch p.Proto {
	case "vless", "vmess":
		proxy["uuid"] = p.Auth["uuid"]
		if p.Proto == "vmess" {
			proxy["security"] = "auto"
			proxy["alter_id"] = 0
		}
	case "trojan":
		proxy["password"] = p.Auth["password"]
	case "ss":
		proxy["method"] = p.Auth["method"]
		proxy["password"] = p.Auth["password"]
	}

	// TLS Settings
	if security, ok := p.Extra["security"]; ok && security == "tls" {
		tlsSettings := map[string]interface{}{"enabled": true}
		if sni, ok := p.Extra["sni"]; ok {
			tlsSettings["server_name"] = sni
		}
		// Note: Sing-box doesn't typically have an 'insecure' option like Clash.
		// It might be handled by 'utls' or other settings if needed.
		proxy["tls"] = tlsSettings
	}

	// Transport Settings (e.g., WebSocket, gRPC)
	if transportType, ok := p.Extra["type"]; ok && (transportType == "ws" || transportType == "grpc") {
		transportSettings := map[string]interface{}{"type": transportType}
		if path, ok := p.Extra["path"]; ok {
			transportSettings["path"] = path
		}
		if host, ok := p.Extra["host"]; ok {
			transportSettings["headers"] = map[string]string{"Host": host}
		}
		if serviceName, ok := p.Extra["serviceName"]; ok {
			transportSettings["service_name"] = serviceName
		}
		proxy["transport"] = transportSettings
	}

	// Multiplex Settings (Smart Default for Trojan)
	if p.Proto == "trojan" {
		proxy["multiplex"] = map[string]interface{}{
			"enabled":     true,
			"protocol":    "smux",
			"max_streams": 32,
		}
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
