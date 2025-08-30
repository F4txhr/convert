package export

import (
    "vpn-conv/internal/core"
)

type Exporter interface {
    Name() string
    Render(profile core.Profile) (string, error)
}

