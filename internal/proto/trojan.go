package proto

import (
    "net/url"
    "strconv"
    "strings"
    "vpn-conv/internal/core"
)

func ParseTrojan(uri string) (core.Profile, error) {
    raw := strings.TrimPrefix(uri, "trojan://")
    u, err := url.Parse("trojan://" + raw)
    if err != nil {
        return core.Profile{}, err
    }

    port, _ := strconv.Atoi(u.Port())

    return core.Profile{
        ID:     u.Fragment,
        Proto:  "trojan",
        Server: u.Hostname(),
        Port:   port,
        Auth:   map[string]string{"password": u.User.Username()},
        Extra:  map[string]string{"sni": u.Query().Get("sni")},
    }, nil
}
