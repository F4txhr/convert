package service

import (
	"fmt"
	"net/url"
	"vpn-conv/internal/core"
	"vpn-conv/internal/export"
	"vpn-conv/internal/proto"
)

type Exporter interface {
	Name() string
	Render(core.Profile) (string, error)
}

type Renderer struct {
	exporters map[string]Exporter
	parsers   map[string]Parser
}

func NewRenderer() *Renderer {
	return &Renderer{
		exporters: map[string]Exporter{
			"clash":   export.ClashExporter{},
			"singbox": export.SingboxExporter{},
			"v2ray":   export.V2rayExporter{},
			"raw":     export.RawExporter{},
		},
		parsers: map[string]Parser{
			"vmess":  proto.VmessParser{},
			"vless":  proto.VlessParser{},
			"trojan": proto.TrojanParser{},
			"ss":     proto.SSParser{},
			"wg":     proto.WGParser{},
		},
	}
}

func (r *Renderer) Convert(uri, format string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid uri: %w", err)
	}
	scheme := u.Scheme
	if scheme == "" {
		return "", fmt.Errorf("uri missing scheme")
	}

	parser, ok := r.parsers[scheme]
	if !ok {
		return "", fmt.Errorf("unsupported uri scheme: '%s'", scheme)
	}

	profile, err := parser.Parse(uri)
	if err != nil {
		return "", err
	}

	exp, ok := r.exporters[format]
	if !ok {
		return "", fmt.Errorf("unsupported format: %s", format)
	}

	return exp.Render(profile)
}
