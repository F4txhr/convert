package export

import (
    "fmt"
    "strings"
    "vpn-conv/internal/core"
)

type ClashExporter struct{}

func (ClashExporter) Name() string { return "clash" }

func (ClashExporter) Render(p core.Profile) (string, error) {
    lines := []string{
        "proxies:",
        fmt.Sprintf("- name: \"%s\"", p.ID),
        fmt.Sprintf("  type: %s", clashType(p.Proto)),
        fmt.Sprintf("  server: %s", p.Server),
        fmt.Sprintf("  port: %d", p.Port),
    }

    if p.Proto == "vmess" || p.Proto == "vless" {
        lines = append(lines, fmt.Sprintf("  uuid: %s", p.Auth["uuid"]))
    }
    if p.Proto == "trojan" {
        lines = append(lines, fmt.Sprintf("  password: %s", p.Auth["password"]))
    }
    if p.Proto == "ss" {
        lines = append(lines, fmt.Sprintf("  cipher: %s", p.Auth["method"]))
        lines = append(lines, fmt.Sprintf("  password: %s", p.Auth["password"]))
    }

    return strings.Join(lines, "\n"), nil
}

func clashType(proto string) string {
    switch proto {
    case "trojan":
        return "trojan"
    case "ss":
        return "ss"
    default:
        return "vmess"
    }
}
