package core

// TLSSettings holds all TLS-related configuration.
type TLSSettings struct {
	Enabled    bool
	Insecure   bool
	ServerName string // For SNI
}

// TransportSettings holds all transport-layer configuration.
type TransportSettings struct {
	Type        string // ws, grpc, etc.
	Path        string
	Host        string
	ServiceName string
}

// Profile is the central, protocol-agnostic representation of a proxy configuration.
type Profile struct {
	ID         string
	Proto      string
	Server     string
	Port       int
	Auth       map[string]string
	TLS        *TLSSettings
	Transport  *TransportSettings
	PluginOpts map[string]string      // For SS plugins
	Extra      map[string]interface{} // For any other non-standard data
}
