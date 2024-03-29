package main

type ConfigConn struct {
	Remote    string  `toml:"remote"`
	Name      string  `toml:"name"`
	Key       string  `toml:"key"`
	Retry     uint32  `toml:"retry"`
	Interval  uint64  `toml:"retry-interval"`
	UserAgent *string `toml:"user-agent"`
}

type ConfigAPI struct {
	Resolve     bool `toml:"resolve"`
	Ping        bool `toml:"ping"`
	TCPing      bool `toml:"tcping"`
	MTR         bool `toml:"mtr"`
	Speed       bool `toml:"speed"`
	SpeedUnsafe bool `toml:"speed-unsafe"`
	TLS         bool `toml:"tls"`
}

type ConfigNetwork struct {
	Bind []string `toml:"bind"`
}

type Config struct {
	Conn    ConfigConn    `toml:"connection"`
	API     ConfigAPI     `toml:"api"`
	Network ConfigNetwork `toml:"network"`
}

func (r *Config) SetDefault() {
	r.Conn.Remote = "ws://127.0.0.1:8080"
	r.Conn.Name = "debug-client"
	r.Conn.Retry = 10
	r.Conn.Interval = 10

	r.API.Resolve = true
	r.API.Ping = true
	r.API.TCPing = true
	r.API.MTR = true
	r.API.Speed = true
	r.API.SpeedUnsafe = false
	r.API.TLS = true
}
