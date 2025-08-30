package core

type Profile struct {
    ID     string            `json:"id"`
    Proto  string            `json:"proto"`
    Server string            `json:"server"`
    Port   int               `json:"port"`
    Auth   map[string]string `json:"auth"`
    Extra  map[string]string `json:"extra"`
}
