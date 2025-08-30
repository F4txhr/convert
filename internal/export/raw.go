package export

import (
	"fmt"
	"vpn-conv/internal/core"
)

type RawExporter struct{}

func (RawExporter) Name() string { return "raw" }

func (RawExporter) Render(p core.Profile) (string, error) {
	return fmt.Sprintf("%+v", p), nil
}
