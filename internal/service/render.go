package service

import (
    "fmt"
    "strings"
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
}

func NewRenderer() *Renderer {
    return &Renderer{
        exporters: map[string]Exporter{
            "clash":   export.ClashExporter{},
            "singbox": export.SingboxExporter{},
            "v2ray":   export.V2rayExporter{},
            "raw":     export.RawExporter{},
        },
    }
}

func (r *Renderer) Convert(uri, format string) (string, error) {
    var profile core.Profile
    var err error

    switch {
    case strings.HasPrefix(uri, "vmess://"):
        profile, err = proto.ParseVMess(uri)
    case strings.HasPrefix(uri, "vless://"):
        profile, err = proto.ParseVLESS(uri)
    case strings.HasPrefix(uri, "trojan://"):
        profile, err = proto.ParseTrojan(uri)
    case strings.HasPrefix(uri, "ss://"):
        profile, err = proto.ParseSS(uri)
    case strings.HasPrefix(uri, "wg://"):
        profile, err = proto.ParseWG(uri)
    default:
        return "", fmt.Errorf("unsupported uri: %s", uri)
    }

    if err != nil {
        return "", err
    }

    exp, ok := r.exporters[format]
    if !ok {
        return "", fmt.Errorf("unsupported format: %s", format)
    }

    return exp.Render(profile)
}
