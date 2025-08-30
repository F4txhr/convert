package export

import (
    "fmt"
    "vpn-conv/internal/core"
)

type Exporter interface {
    Name() string
    Render(profile core.Profile) (string, error)
}

// Dummy exporter
type RawExporter struct{}

func (RawExporter) Name() string { return "raw" }

func (RawExporter) Render(p core.Profile) (string, error) {
    return fmt.Sprintf("%s://%s:%d", p.Proto, p.Server, p.Port), nil
}
