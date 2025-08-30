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

// createClashProxy converts a core.Profile into a detailed Clash proxy struct.
func createClashProxy(p core.Profile) interface{} {
	// Common settings for VLESS, VMess, Trojan
	var tlsConfig *TLSConfig
	if security, ok := p.Extra["security"]; ok && (security == "tls" || security == "reality") {
		tlsConfig = &TLSConfig{Enabled: true}
		if sni, ok := p.Extra["sni"]; ok && sni != "" {
			tlsConfig.ServerName = sni
		} else if host, ok := p.Extra["host"]; ok && host != "" {
			tlsConfig.ServerName = host // Fallback to host for SNI
		}
		if insecure, ok := p.Extra["insecure"]; ok && insecure == "true" {
			tlsConfig.Insecure = true
		}
	}

	var wsOpts *WSOpts
	if transportType, ok := p.Extra["type"]; ok && transportType == "ws" {
		wsOpts = &WSOpts{
			Path:    p.Extra["path"],
			Headers: WSHeaders{Host: p.Extra["host"]},
		}
	}
	// Note: gRPC opts and other transport types can be added here in a similar fashion.

	switch p.Proto {
	case "vmess":
		return VmessProxy{
			Type:       "vmess",
			Tag:        p.ID,
			Server:     p.Server,
			ServerPort: p.Port,
			UUID:       p.Auth["uuid"],
			AlterID:    0,
			Security:   "auto",
			TLS:        tlsConfig,
			Network:    p.Extra["type"],
			WSOpts:     wsOpts,
		}
	case "vless":
		// VLESS uses the same struct but is identified as 'vmess' type for Clash
		return VlessProxy{
			Type:       "vmess",
			Tag:        p.ID,
			Server:     p.Server,
			ServerPort: p.Port,
			UUID:       p.Auth["uuid"],
			TLS:        tlsConfig,
			Network:    p.Extra["type"],
			WSOpts:     wsOpts,
		}
	case "trojan":
		multiplex := &MultiplexConfig{Enabled: true} // smux for trojan
		return TrojanProxy{
			Type:       "trojan",
			Tag:        p.ID,
			Server:     p.Server,
			ServerPort: p.Port,
			Password:   p.Auth["password"],
			TLS:        tlsConfig,
			Multiplex:  multiplex,
			Network:    p.Extra["type"],
			WSOpts:     wsOpts,
		}
	case "ss":
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
			opts = append(opts, "tls=1")
		}

		return SSProxy{
			Type:       "ss",
			Tag:        p.ID,
			Server:     p.Server,
			ServerPort: p.Port,
			Method:     p.Auth["method"],
			Password:   p.Auth["password"],
			Plugin:     p.Extra["plugin"],
			PluginOpts: strings.Join(opts, ";"),
		}
	case "wg":
		return WGProxy{
			Type:          "wireguard",
			Tag:           p.ID,
			Server:        p.Server,
			ServerPort:    p.Port,
			PrivateKey:    p.Auth["private_key"],
			PeerPublicKey: p.Extra["publicKey"],
			IP:            "172.19.0.2",
		}
	}

	return nil // Should not happen
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
