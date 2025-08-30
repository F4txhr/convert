package main

import (
    "encoding/json"
    "net/http"
    "vpn-conv/internal/service"
)

func main() {
    renderer := service.NewRenderer()

    http.HandleFunc("/render", func(w http.ResponseWriter, r *http.Request) {
        uri := r.URL.Query().Get("uri")
        format := r.URL.Query().Get("format")

        out, err := renderer.Convert(uri, format)
        if err != nil {
            http.Error(w, err.Error(), 400)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"config": out})
    })

    http.ListenAndServe(":8080", nil)
}
