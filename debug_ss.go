package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// fixB64Padding adds the required padding to a base64 string.
func fixB64Padding(s string) string {
	// This is the Go equivalent of Python's `s + "=" * (-len(s) % 4)`
	return s + strings.Repeat("=", (4-len(s)%4)%4)
}

func main() {
	// Hardcoded URI from user's log
	uri := "ss://bm9uZTpkODNjOGVkYy03YjA0LTRjYmUtOGQ5Yy1kYjc5NDAzZmVkOWY=%3D@quiz.int.vidio.com:443?encryption=none&type=ws&host=gendar.ariyeldlacasa.workers.dev&path=%2F91.187.93.166-443&security=tls&sni=gendar.ariyeldlacasa.workers.dev#%F0%9F%87%A6%F0%9F%87%A9%20(AD)%20Andorra%20Telecom%0D"

	fmt.Println("--- STARTING SS PARSER DEBUG ---")
	fmt.Printf("1. Initial URI: %s\n\n", uri)

	var fragment string
	if strings.Contains(uri, "#") {
		parts := strings.SplitN(uri, "#", 2)
		uri = parts[0]
		fragment = parts[1]
	}
	fmt.Printf("2. URI after fragment split: %s\n", uri)
	fmt.Printf("3. Raw Fragment: %s\n\n", fragment)

	decodedFragment, err := url.PathUnescape(fragment)
	if err != nil {
		fmt.Printf("4. URL-decoding fragment FAILED: %v\n\n", err)
	} else {
		fmt.Printf("4. URL-decoding fragment SUCCESS: '%s'\n\n", decodedFragment)
	}

	rawURL := strings.TrimPrefix(uri, "ss://")
	fmt.Printf("5. Raw URL body (no scheme): %s\n\n", rawURL)

	if !strings.Contains(rawURL, "@") {
		fmt.Println("Branch: No '@' found. This is not the failing case.")
		return
	}

	fmt.Println("Branch: '@' found. Proceeding with manual parse.")
	parts := strings.SplitN(rawURL, "@", 2)
	userInfoPart := parts[0]
	hostInfoPart := parts[1]
	fmt.Printf("6. Raw UserInfo part: '%s'\n", userInfoPart)
	fmt.Printf("7. Raw HostInfo part: '%s'\n\n", hostInfoPart)

	cleanUserInfo, err := url.QueryUnescape(userInfoPart)
	if err != nil {
		fmt.Printf("8. URL-decoding UserInfo FAILED: %v\n\n", err)
		cleanUserInfo = userInfoPart
	} else {
		fmt.Printf("8. URL-decoding UserInfo SUCCESS: '%s'\n\n", cleanUserInfo)
	}

	paddedUserInfo := fixB64Padding(cleanUserInfo)
	fmt.Printf("9. UserInfo after manual padding: '%s'\n\n", paddedUserInfo)

	// Use URLEncoding for url-safe base64
	decodedCreds, err := base64.URLEncoding.DecodeString(paddedUserInfo)
	var method, password string
	if err == nil {
		toParse := string(decodedCreds)
		fmt.Printf("10. Base64 decoding SUCCESS. Decoded string: '%s'\n\n", toParse)
		credParts := strings.SplitN(toParse, ":", 2)
		if len(credParts) > 0 {
			method = credParts[0]
		}
		if len(credParts) > 1 {
			password = credParts[1]
		}
	} else {
		fmt.Printf("10. Base64 decoding FAILED. Error: %v\n", err)
		fmt.Println("     Falling back to plain text split.")
		credParts := strings.SplitN(cleanUserInfo, ":", 2)
		if len(credParts) > 0 {
			method = credParts[0]
		}
		if len(credParts) > 1 {
			password = credParts[1]
		}
	}

	fmt.Printf("\n11. Final Extracted Method: '%s'\n", method)
	fmt.Printf("12. Final Extracted Password: '%s'\n", password)
	fmt.Println("\n--- END OF DEBUG ---")
}
