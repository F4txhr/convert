package proto

import (
    "net/url"
    "strconv"
    "strings"
    "vpn-conv/internal/core"
)

func ParseWG(uri string) (core.Profile, error) {
    raw := strings.TrimPrefix(uri, "wg://")
    u, err := url.Parse("wg://" + raw)
    if err != nil {
        return core.Profile{}, err
    }

    port, _ := strconv.Atoi(u.Port())

    return core.Profile{
        ID:     u.Fragment,
        Proto:  "wg",
        Server: u.Hostname(),
        Port:   port,
        Auth:   map[string]string{"private_key": u.Query().Get("privateKey")},
        Extra:  map[string]string{"public_key": u.Query().Get("publicKey")},
    }, nil
}
