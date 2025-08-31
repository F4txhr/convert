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
	// Translate the structured core.Profile to the output structs
	var tlsConfig *TLSConfig
	if p.TLS != nil && p.TLS.Enabled {
		tlsConfig = &TLSConfig{
			Enabled:    true,
			Insecure:   p.TLS.Insecure,
			ServerName: p.TLS.ServerName,
		}
	}

	var wsOpts *WSOpts
	var grpcOpts *GRPCOpts
	var networkType string
	if p.Transport != nil {
		networkType = p.Transport.Type
		switch p.Transport.Type {
		case "ws":
			wsOpts = &WSOpts{
				Path:    p.Transport.Path,
				Headers: WSHeaders{Host: p.Transport.Host},
			}
		case "grpc":
			grpcOpts = &GRPCOpts{
				ServiceName: p.Transport.ServiceName,
			}
		}
	}

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
			Network:    networkType,
			WSOpts:     wsOpts,
			GRPCOpts:   grpcOpts,
		}
	case "vless":
		return VlessProxy{
			Type:       "vmess", // VLESS uses 'vmess' type in Clash
			Tag:        p.ID,
			Server:     p.Server,
			ServerPort: p.Port,
			UUID:       p.Auth["uuid"],
			TLS:        tlsConfig,
			Network:    networkType,
			WSOpts:     wsOpts,
			GRPCOpts:   grpcOpts,
		}
	case "trojan":
		return TrojanProxy{
			Type:       "trojan",
			Tag:        p.ID,
			Server:     p.Server,
			ServerPort: p.Port,
			Password:   p.Auth["password"],
			TLS:        tlsConfig,
			Multiplex:  &MultiplexConfig{Enabled: true}, // smux for trojan
			Network:    networkType,
			WSOpts:     wsOpts,
			GRPCOpts:   grpcOpts,
		}
	case "ss":
		var opts []string
		if p.PluginOpts != nil {
			if mux, ok := p.PluginOpts["mux"]; ok && mux != "0" {
				opts = append(opts, "mux")
			}
			if path, ok := p.PluginOpts["path"]; ok {
				opts = append(opts, "path="+path)
			}
			if host, ok := p.PluginOpts["host"]; ok {
				opts = append(opts, "host="+host)
			}
			if _, ok := p.PluginOpts["tls"]; ok {
				opts = append(opts, "tls=1")
			}
		}

		return SSProxy{
			Type:       "ss",
			Tag:        p.ID,
			Server:     p.Server,
			ServerPort: p.Port,
			Method:     p.Auth["method"],
			Password:   p.Auth["password"],
			Plugin:     p.PluginOpts["name"],
			PluginOpts: strings.Join(opts, ";"),
		}
	case "wg":
		publicKey, _ := p.Extra["publicKey"].(string)
		return WGProxy{
			Type:          "wireguard",
			Tag:           p.ID,
			Server:        p.Server,
			ServerPort:    p.Port,
			PrivateKey:    p.Auth["private_key"],
			PeerPublicKey: publicKey,
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
