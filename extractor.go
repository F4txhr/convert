package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// This logic is a direct translation of the user's Python script.
// It manually adds the correct padding to a base64 string.
func fixB64Padding(s string) string {
	return s + strings.Repeat("=", (4-len(s)%4)%4)
}

func main() {
	// Use the user's second, more complex URI for a better test
	uri := "ss://bm9uZTozYWJkYmJlMy0xNTliLTQ1ZWUtOGFkYi1mZjQwM2FjN2ExYjY%3D@plus-store.naver.com:80?encryption=none&type=ws&host=alya.yumicftigarun.web.id&security=none&sni=alya.yumicftigarun.web.id&path=%2F149.28.158.103-10030&plugin=v2ray-plugin%3Bmux%3D0#9%20%F0%9F%87%B8%F0%9F%87%AC%20Vultr%20Holdings%20LLC%20WS%20NTLS%20[alya]"

	fmt.Println("--- STARTING SS EXTRACTOR ---")
	fmt.Printf("Initial URI: %s\n\n", uri)

	// 1. Separate Fragment (Tag)
	var rawFragment string
	if strings.Contains(uri, "#") {
		parts := strings.SplitN(uri, "#", 2)
		uri = parts[0]
		rawFragment = parts[1]
	}
	decodedFragment, _ := url.PathUnescape(rawFragment)
	fmt.Printf("TAG: %s\n", decodedFragment)

	// 2. Separate UserInfo and HostInfo
	rawURL := strings.TrimPrefix(uri, "ss://")
	parts := strings.SplitN(rawURL, "@", 2)
	rawUserInfo := parts[0]
	hostInfo := parts[1]

	fmt.Printf("RAW USERINFO: %s\n", rawUserInfo)

	// 3. Process UserInfo
	var method, password string
	cleanUserInfo, err := url.QueryUnescape(rawUserInfo)
	if err != nil {
		cleanUserInfo = rawUserInfo
	}
	fmt.Printf("URL-DECODED USERINFO: %s\n", cleanUserInfo)

	paddedUserInfo := fixB64Padding(cleanUserInfo)
	decodedCreds, err := base64.URLEncoding.DecodeString(paddedUserInfo)
	if err == nil {
		toParse := string(decodedCreds)
		fmt.Printf("BASE64-DECODED USERINFO: %s\n", toParse)
		credParts := strings.SplitN(toParse, ":", 2)
		if len(credParts) > 0 {
			method = credParts[0]
		}
		if len(credParts) > 1 {
			password = credParts[1]
		}
	} else {
		fmt.Printf("BASE64-DECODING FAILED: %v\n", err)
		credParts := strings.SplitN(cleanUserInfo, ":", 2)
		if len(credParts) > 0 {
			method = credParts[0]
		}
		if len(credParts) > 1 {
			password = credParts[1]
		}
	}
	fmt.Printf("==> FINAL METHOD: %s\n", method)
	fmt.Printf("==> FINAL PASSWORD: %s\n\n", password)

	// 4. Process HostInfo
	u, _ := url.Parse("https://" + hostInfo)
	fmt.Printf("HOST: %s\n", u.Hostname())
	fmt.Printf("PORT: %s\n\n", u.Port())

	// 5. Process Query Parameters
	fmt.Println("--- PLUGIN/QUERY PARAMS ---")
	query := u.Query()
	for key, values := range query {
		if len(values) > 0 {
			fmt.Printf("%s: %s\n", key, values[0])
		}
	}

	// 6. Construct final plugin_opts string
	var opts []string
	// Check for mux inside the plugin param first
	if pluginVal, ok := query["plugin"]; ok && strings.Contains(pluginVal[0], "mux=0") {
		opts = append(opts, "mux=0")
	}

	// Check for type=ws to add mode=websocket
	if typeVal, ok := query["type"]; ok && typeVal[0] == "ws" {
		opts = append(opts, "mode=websocket")
	}

	if pathVal, ok := query["path"]; ok {
		opts = append(opts, "path="+pathVal[0])
	}
	if hostVal, ok := query["host"]; ok {
		opts = append(opts, "host="+hostVal[0])
	}
	// Check for security=tls to add the tls flag
	if securityVal, ok := query["security"]; ok && securityVal[0] == "tls" {
		opts = append(opts, "tls")
	}

	finalPluginOpts := strings.Join(opts, ";")
	fmt.Printf("\n==> FINAL PLUGIN_OPTS: %s\n", finalPluginOpts)


	fmt.Println("\n--- EXTRACTION COMPLETE ---")
}
