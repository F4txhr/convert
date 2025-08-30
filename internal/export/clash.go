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

// createClashProxy converts a core.Profile into a Clash proxy map.
func createClashProxy(p core.Profile) map[string]interface{} {
	// Clash proxy type mapping
	clashType := p.Proto
	if p.Proto == "vless" {
		// VLESS is not a native type in Clash OSS, often configured as vmess
		clashType = "vmess"
	}

	proxy := map[string]interface{}{
		"name":   p.ID,
		"type":   clashType,
		"server": p.Server,
		"port":   p.Port,
	}

	switch p.Proto {
	case "vmess":
		proxy["uuid"] = p.Auth["uuid"]
		proxy["alterId"] = 0
		proxy["cipher"] = "auto"
	case "vless":
		proxy["uuid"] = p.Auth["uuid"]
		proxy["alterId"] = 0
		proxy["cipher"] = "auto"
		if network, ok := p.Extra["type"]; ok && network == "ws" {
			proxy["network"] = "ws"
		}
	case "trojan":
		proxy["password"] = p.Auth["password"]
		if sni, ok := p.Extra["sni"]; ok {
			proxy["sni"] = sni
		}
	case "ss":
		proxy["cipher"] = p.Auth["method"]
		proxy["password"] = p.Auth["password"]
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
