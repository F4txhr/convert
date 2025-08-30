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

// createSingboxProxy converts a core.Profile into a detailed Sing-box proxy struct.
func createSingboxProxy(p core.Profile) interface{} {
	// Common settings for VLESS, VMess, Trojan
	var tlsConfig *TLSConfig
	if security, ok := p.Extra["security"]; ok && (security == "tls" || security == "reality") {
		tlsConfig = &TLSConfig{
			Enabled:  true,
			Insecure: true, // Per user example
		}
		if sni, ok := p.Extra["sni"]; ok && sni != "" {
			tlsConfig.ServerName = sni
		} else if host, ok := p.Extra["host"]; ok && host != "" {
			tlsConfig.ServerName = host // Fallback to host for SNI
		}
	}

	var transport *SingboxTransport
	if transportType, ok := p.Extra["type"]; ok && transportType == "ws" {
		transport = &SingboxTransport{
			Type:                "ws",
			Path:                p.Extra["path"],
			Headers:             WSHeaders{Host: p.Extra["host"]},
			EarlyDataHeaderName: "Sec-WebSocket-Protocol",
		}
	}

	multiplex := &MultiplexConfig{
		Enabled:    true,
		Protocol:   "smux",
		MaxStreams: 32,
	}

	switch p.Proto {
	case "vmess":
		return VmessProxy{
			Type:           "vmess",
			Tag:            p.ID,
			DomainStrategy: "ipv4_only",
			Server:         p.Server,
			ServerPort:     p.Port,
			UUID:           p.Auth["uuid"],
			AlterID:        0,
			Security:       "zero",
			TLS:            tlsConfig,
			Transport:      transport,
			Multiplex:      multiplex,
			PacketEncoding: "xudp",
		}
	case "vless":
		return VlessProxy{
			Type:           "vless",
			Tag:            p.ID,
			DomainStrategy: "ipv4_only",
			Server:         p.Server,
			ServerPort:     p.Port,
			UUID:           p.Auth["uuid"],
			TLS:            tlsConfig,
			Transport:      transport,
			Multiplex:      multiplex,
			PacketEncoding: "xudp",
		}
	case "trojan":
		return TrojanProxy{
			Type:           "trojan",
			Tag:            p.ID,
			DomainStrategy: "ipv4_only",
			Server:         p.Server,
			ServerPort:     p.Port,
			Password:       p.Auth["password"],
			TLS:            tlsConfig,
			Transport:      transport,
			Multiplex:      multiplex,
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
			Type:       "shadowsocks",
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
			LocalAddress:  []string{"172.19.0.2/32"},
		}
	}

	return nil // Should not happen
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
