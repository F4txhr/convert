package export

import (
	"fmt"
	"log"
	"os"
	"strings"
	"vpn-conv/internal/core"

	"gopkg.in/yaml.v3"
)

type ClashExporter struct{}

func (c ClashExporter) Name() string { return "clash" }

// createClashProxy converts a core.Profile into a detailed Clash proxy map.
func createClashProxy(p core.Profile) map[string]interface{} {
	// Base proxy object
	proxy := map[string]interface{}{
		"name":   p.ID,
		"type":   p.Proto,
		"server": p.Server,
		"port":   p.Port,
	}

	// Protocol-specific fields and translations
	switch p.Proto {
	case "vmess":
		proxy["uuid"] = p.Auth["uuid"]
		proxy["alterId"] = 0
		proxy["cipher"] = "auto"
	case "vless":
		// Translate VLESS to Clash's vmess format
		proxy["type"] = "vmess"
		proxy["uuid"] = p.Auth["uuid"]
		proxy["alterId"] = 0
		proxy["cipher"] = "auto"
	case "trojan":
		proxy["password"] = p.Auth["password"]
		proxy["smux"] = true // Smart Default
	case "ss":
		proxy["cipher"] = p.Auth["method"]
		proxy["password"] = p.Auth["password"]
		if pluginName, ok := p.Extra["plugin"]; ok {
			proxy["plugin"] = pluginName

			// Build the plugin_opts string from Extra map, per user request
			var opts []string
			if mux, ok := p.Extra["mux"]; ok && mux != "0" {
				opts = append(opts, "mux")
			}
			if path, ok := p.Extra["path"]; ok {
				opts = append(opts, "path="+path)
			}
			if host, ok := p.Extra["host"]; ok {
				opts = append(opts, "host="+host)
			}
			if _, ok := p.Extra["tls"]; ok {
				opts = append(opts, "tls")
			}
			proxy["plugin-opts"] = strings.Join(opts, ";")
		}
		// Return early for SS as its structure is different
		return proxy
	case "wg":
		proxy["ip"] = "172.19.0.2" // Smart Default
		proxy["private-key"] = p.Auth["private_key"]
		proxy["public-key"] = p.Extra["publicKey"]
		// 'reserved' can be added if present in Extra
		return proxy // WG has a simpler structure, return early
	}

	// Common settings for VLESS, VMess, Trojan
	// TLS Settings
	if security, ok := p.Extra["security"]; ok && (security == "tls" || security == "reality") {
		proxy["tls"] = true
		if sni, ok := p.Extra["sni"]; ok && sni != "" {
			proxy["servername"] = sni
		} else if host, ok := p.Extra["host"]; ok && host != "" {
			proxy["servername"] = host // Fallback to host for SNI
		}

		// Per user example, insecure is often a requirement
		if insecure, ok := p.Extra["insecure"]; ok && insecure == "true" {
			proxy["skip-cert-verify"] = true
		}
	}

	// Transport Settings
	if transportType, ok := p.Extra["type"]; ok {
		proxy["network"] = transportType
		switch transportType {
		case "ws":
			wsOpts := make(map[string]interface{})
			if path, ok := p.Extra["path"]; ok {
				wsOpts["path"] = path
			}
			if host, ok := p.Extra["host"]; ok {
				wsOpts["headers"] = map[string]string{"Host": host}
			}
			proxy["ws-opts"] = wsOpts
		case "grpc":
			grpcOpts := make(map[string]interface{})
			if serviceName, ok := p.Extra["serviceName"]; ok {
				grpcOpts["grpc-service-name"] = serviceName
			}
			proxy["grpc-opts"] = grpcOpts
		}
	}

	return proxy
}

func (c ClashExporter) Render(p core.Profile) (string, error) {
	log.Println("DEBUG: Using new Clash template exporter...")
	// 1. Read the template file
	templateBytes, err := os.ReadFile("configs/template_clash.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to read clash template: %w", err)
	}

	// 2. Unmarshal into a map
	var config map[string]interface{}
	if err := yaml.Unmarshal(templateBytes, &config); err != nil {
		return "", fmt.Errorf("failed to parse clash template: %w", err)
	}

	// 3. Create the new proxy object
	newProxy := createClashProxy(p)

	// 4. Inject the new proxy into the main proxies list
	proxies, ok := config["proxies"].([]interface{})
	if !ok {
		proxies = []interface{}{}
	}
	config["proxies"] = append(proxies, newProxy)

	// 5. Inject the proxy name into the correct groups
	proxyName := p.ID
	groupsToUpdate := []string{"Internet", "Best Latency 🚀"}
	if strings.Contains(proxyName, "🇮🇩") {
		groupsToUpdate = append(groupsToUpdate, "Latency ID")
	}
	if strings.Contains(proxyName, "🇸🇬") {
		groupsToUpdate = append(groupsToUpdate, "Latency SG")
	}

	proxyGroups, ok := config["proxy-groups"].([]interface{})
	if !ok {
		return "", fmt.Errorf("template 'proxy-groups' is not a list")
	}

	for i, groupInterface := range proxyGroups {
		group, isMap := groupInterface.(map[string]interface{})
		if !isMap {
			continue
		}

		name, hasName := group["name"].(string)
		if !hasName {
			continue
		}

		for _, groupToUpdate := range groupsToUpdate {
			if name == groupToUpdate {
				groupProxies, ok := group["proxies"].([]interface{})
				if !ok {
					groupProxies = []interface{}{}
				}
				group["proxies"] = append(groupProxies, proxyName)
				proxyGroups[i] = group
			}
		}
	}

	// 5.5: Add direct fallback to empty url-test groups
	for i, groupInterface := range proxyGroups {
		group, isMap := groupInterface.(map[string]interface{})
		if !isMap {
			continue
		}

		groupType, hasType := group["type"].(string)
		if !hasType || groupType != "url-test" {
			continue
		}

		groupProxies, ok := group["proxies"].([]interface{})
		if !ok || len(groupProxies) == 0 {
			group["proxies"] = []interface{}{"direct 🚸"}
			proxyGroups[i] = group
		}
	}

	// 6. Marshal the modified config back to YAML
	finalYAML, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal final clash config: %w", err)
	}

	return string(finalYAML), nil
}
