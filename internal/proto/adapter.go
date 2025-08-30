package proto

import "vpn-conv/internal/core"

type Adapter interface {
    Name() string
    Normalize(profile core.Profile) (core.Profile, error)
}
