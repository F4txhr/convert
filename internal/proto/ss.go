package proto

import (
    "encoding/base64"
    "net/url"
    "strconv"
    "strings"
    "vpn-conv/internal/core"
)

func ParseSS(uri string) (core.Profile, error) {
    raw := strings.TrimPrefix(uri, "ss://")
    // ss://method:password@host:port
    // bisa juga base64 encode

    if strings.Contains(raw, "@") {
        u, _ := url.Parse("ss://" + raw)
        port, _ := strconv.Atoi(u.Port())
        return core.Profile{
            ID:     u.Fragment,
            Proto:  "ss",
            Server: u.Hostname(),
            Port:   port,
            Auth: map[string]string{
                "method":   strings.Split(u.User.Username(), ":")[0],
                "password": strings.Split(u.User.Username(), ":")[1],
            },
        }, nil
    }

    // base64 decode
    decoded, _ := base64.StdEncoding.DecodeString(raw)
    return ParseSS(string(decoded))
}
