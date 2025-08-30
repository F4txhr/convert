package export

import (
    "encoding/json"
    "vpn-conv/internal/core"
)

type V2rayExporter struct{}

func (V2rayExporter) Name() string { return "v2ray" }

func (V2rayExporter) Render(p core.Profile) (string, error) {
    conf := map[string]interface{}{
        "outbounds": []map[string]interface{}{
            {
                "protocol": p.Proto,
                "settings": map[string]interface{}{
                    "vnext": []map[string]interface{}{
                        {
                            "address": p.Server,
                            "port":    p.Port,
                            "users": []map[string]interface{}{
                                {
                                    "id": p.Auth["uuid"],
                                },
                            },
                        },
                    },
                },
            },
        },
    }
    b, err := json.MarshalIndent(conf, "", "  ")
    return string(b), err
}
