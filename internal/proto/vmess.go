package proto

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"vpn-conv/internal/core"
)

type VmessParser struct{}

func (p VmessParser) Scheme() string {
	return "vmess"
}

func (p VmessParser) Parse(uri string) (core.Profile, error) {
	raw := strings.TrimPrefix(uri, "vmess://")
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return core.Profile{}, err
	}

	var vm map[string]string
	if err := json.Unmarshal(data, &vm); err != nil {
		return core.Profile{}, err
	}

	port, _ := strconv.Atoi(vm["port"])

	return core.Profile{
		ID:     vm["ps"],
		Proto:  "vmess",
		Server: vm["add"],
		Port:   port,
		Auth:   map[string]string{"uuid": vm["id"]},
		Extra:  vm,
	}, nil
}
