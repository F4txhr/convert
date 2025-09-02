package export

// This file contains the struct definitions for generating
// ordered and well-structured proxy configurations.

// Common nested structures
type TLSConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Insecure   bool   `json:"insecure,omitempty" yaml:"skip-cert-verify,omitempty"`
	ServerName string `json:"server_name,omitempty" yaml:"servername,omitempty"`
}

type WSHeaders struct {
	Host string `json:"Host" yaml:"Host"`
}

type WSOpts struct {
	Path    string    `json:"path" yaml:"path"`
	Headers WSHeaders `json:"headers" yaml:"headers"`
}

type GRPCOpts struct {
	ServiceName string `json:"grpc-service-name" yaml:"grpc-service-name"`
}

type SingboxTransport struct {
	Type                string    `json:"type"`
	Path                string    `json:"path,omitempty"`
	Headers             WSHeaders `json:"headers,omitempty"`
	ServiceName         string    `json:"service_name,omitempty"`
	EarlyDataHeaderName string    `json:"early_data_header_name,omitempty"`
}

type MultiplexConfig struct {
	Enabled    bool   `json:"enabled"`
	Protocol   string `json:"protocol"`
	MaxStreams int    `json:"max_streams"`
}

// Main proxy structs
type VmessProxy struct {
	Type           string            `json:"type" yaml:"type"`
	Tag            string            `json:"tag" yaml:"name"`
	DomainStrategy string            `json:"domain_strategy,omitempty" yaml:"-"`
	Server         string            `json:"server" yaml:"server"`
	ServerPort     int               `json:"server_port" yaml:"port"`
	UUID           string            `json:"uuid" yaml:"uuid"`
	AlterID        int               `json:"alter_id" yaml:"alterId"`
	Security       string            `json:"security" yaml:"cipher"`
	TLS            *TLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
	Multiplex      *MultiplexConfig  `json:"multiplex,omitempty" yaml:"smux,omitempty"`
	Transport      *SingboxTransport `json:"transport,omitempty" yaml:"-"`
	PacketEncoding string            `json:"packet_encoding,omitempty" yaml:"-"`
	Network        string            `json:"-" yaml:"network,omitempty"`
	WSOpts         *WSOpts           `json:"-" yaml:"ws-opts,omitempty"`
	GRPCOpts       *GRPCOpts         `json:"-" yaml:"grpc-opts,omitempty"`
}

type VlessProxy struct {
	Type           string            `json:"type" yaml:"type"`
	Tag            string            `json:"tag" yaml:"name"`
	DomainStrategy string            `json:"domain_strategy,omitempty" yaml:"-"`
	Server         string            `json:"server" yaml:"server"`
	ServerPort     int               `json:"server_port" yaml:"port"`
	UUID           string            `json:"uuid" yaml:"uuid"`
	TLS            *TLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
	Multiplex      *MultiplexConfig  `json:"multiplex,omitempty" yaml:"smux,omitempty"`
	Transport      *SingboxTransport `json:"transport,omitempty" yaml:"-"`
	PacketEncoding string            `json:"packet_encoding,omitempty" yaml:"-"`
	Network        string            `json:"-" yaml:"network,omitempty"`
	WSOpts         *WSOpts           `json:"-" yaml:"ws-opts,omitempty"`
	GRPCOpts       *GRPCOpts         `json:"-" yaml:"grpc-opts,omitempty"`
}

type TrojanProxy struct {
	Type           string            `json:"type" yaml:"type"`
	Tag            string            `json:"tag" yaml:"name"`
	DomainStrategy string            `json:"domain_strategy,omitempty" yaml:"-"`
	Server         string            `json:"server" yaml:"server"`
	ServerPort     int               `json:"server_port" yaml:"port"`
	Password       string            `json:"password" yaml:"password"`
	TLS            *TLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
	Multiplex      *MultiplexConfig  `json:"multiplex,omitempty" yaml:"smux,omitempty"`
	Transport      *SingboxTransport `json:"transport,omitempty" yaml:"-"`
	Network        string            `json:"-" yaml:"network,omitempty"`
	WSOpts         *WSOpts           `json:"-" yaml:"ws-opts,omitempty"`
	GRPCOpts       *GRPCOpts         `json:"-" yaml:"grpc-opts,omitempty"`
}

type SSProxy struct {
	Type       string            `json:"type" yaml:"type"`
	Tag        string            `json:"tag" yaml:"name"`
	Server     string            `json:"server" yaml:"server"`
	ServerPort int               `json:"server_port" yaml:"port"`
	Method     string            `json:"method" yaml:"cipher"`
	Password   string            `json:"password" yaml:"password"`
	Plugin     string            `json:"plugin,omitempty" yaml:"plugin,omitempty"`
	PluginOpts string            `json:"plugin_opts,omitempty" yaml:"plugin-opts,omitempty"`
	Transport  *SingboxTransport `json:"-" yaml:"-"`
	TLS        *TLSConfig        `json:"-" yaml:"-"`
}

type WGProxy struct {
	Type          string   `json:"type" yaml:"type"`
	Tag           string   `json:"tag" yaml:"name"`
	Server        string   `json:"server" yaml:"server"`
	ServerPort    int      `json:"server_port" yaml:"port"`
	PrivateKey    string   `json:"private_key" yaml:"private-key"`
	PeerPublicKey string   `json:"peer_public_key" yaml:"public-key"`
	LocalAddress  []string `json:"local_address,omitempty" yaml:"-"`
	IP            string   `json:"-" yaml:"ip,omitempty"`
	Reserved      []int    `json:"reserved,omitempty" yaml:"-"`
}
