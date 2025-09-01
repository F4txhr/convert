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
	uri := "ss://bm9uZTpkODNjOGVkYy03YjA0LTRjYmUtOGQ5Yy1kYjc5NDAzZmVkOWY=%3D@quiz.int.vidio.com:443?encryption=none&type=ws&host=gendar.ariyeldlacasa.workers.dev&path=%2F91.187.93.166-443&security=tls&sni=gendar.ariyeldlacasa.workers.dev#%F0%9F%87%A6%F0%9F%87%A9%20(AD)%20Andorra%20Telecom%0D"

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
	// Step 3a: URL-decode the user info
	cleanUserInfo, err := url.QueryUnescape(rawUserInfo)
	if err != nil {
		cleanUserInfo = rawUserInfo
	}
	fmt.Printf("URL-DECODED USERINFO: %s\n", cleanUserInfo)

	// Step 3b: Manually fix padding and Base64-decode
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
		// Fallback for plain text user info
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
	u, _ := url.Parse("https://" + hostInfo) // Use https for safe parsing of query
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
	fmt.Println("\n--- EXTRACTION COMPLETE ---")
}
