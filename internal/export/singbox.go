package export

import (
    "encoding/json"
    "vpn-conv/internal/core"
)

type SingboxExporter struct{}

func (SingboxExporter) Name() string { return "singbox" }

func (SingboxExporter) Render(p core.Profile) (string, error) {
    out := map[string]interface{}{
        "outbounds": []map[string]interface{}{
            {
                "type":        p.Proto,
                "server":      p.Server,
                "server_port": p.Port,
            },
        },
    }

    for k, v := range p.Auth {
        out["outbounds"].([]map[string]interface{})[0][k] = v
    }

    bytes, err := json.MarshalIndent(out, "", "  ")
    return string(bytes), err
}
