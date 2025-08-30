package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"vpn-conv/internal/service"
)

func main() {
	renderer := service.NewRenderer()

	http.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
		uri := r.URL.Query().Get("uri")
		format := r.URL.Query().Get("format")

		out, err := renderer.Convert(uri, format)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"config": out})
	})

	addr := os.Getenv("APP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	log.Printf("server starting on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server failed to start: %v", err)
	}
}
