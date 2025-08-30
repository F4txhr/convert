package service

import "vpn-conv/internal/core"

type Parser interface {
	Scheme() string
	Parse(uri string) (core.Profile, error)
}
