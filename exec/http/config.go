package main

type ConfigAuth struct {
	UseAuth bool   `toml:"use_auth"`
	Key     string `toml:"key"`
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

type ConfigSite struct {
	Cert   string `toml:"cert"`
	Key    string `toml:"key"`
	Listen string `toml:"listen"`
}

type Config struct {
	Auth ConfigAuth `toml:"auth"`
	API  ConfigAPI  `toml:"api"`
	Site ConfigSite `toml:"site"`
}

func (r *Config) SetDefault() {
	r.Auth.UseAuth = false

	r.API.Resolve = true
	r.API.Ping = true
	r.API.TCPing = true
	r.API.MTR = true
	r.API.Speed = true
	r.API.SpeedUnsafe = false
	r.API.TLS = true

	r.Site.Listen = ":4096"
}
