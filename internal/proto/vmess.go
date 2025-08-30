package proto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	// Unmarshal into a flexible map to handle different value types
	var vm map[string]interface{}
	if err := json.Unmarshal(data, &vm); err != nil {
		return core.Profile{}, err
	}

	// Helper to safely get string values from the map
	getString := func(key string) string {
		if val, ok := vm[key].(string); ok {
			return val
		}
		return ""
	}

	// Port can be a string or a number in vmess links
	var port int
	switch p := vm["port"].(type) {
	case string:
		port, _ = strconv.Atoi(p)
	case float64:
		port = int(p)
	}

	// Populate Extra map with all string-representable values from the VMess JSON
	extra := make(map[string]string)
	for key, value := range vm {
		extra[key] = fmt.Sprintf("%v", value)
	}

	return core.Profile{
		ID:     getString("ps"),
		Proto:  "vmess",
		Server: getString("add"),
		Port:   port,
		Auth:   map[string]string{"uuid": getString("id")},
		Extra:  extra,
	}, nil
}
