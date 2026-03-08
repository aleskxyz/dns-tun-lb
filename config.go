package main

import (
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type DefaultDNSBehaviorMode string

const (
	DefaultDNSModeForward DefaultDNSBehaviorMode = "forward"
	DefaultDNSModeDrop    DefaultDNSBehaviorMode = "drop"
)

type DefaultDNSBehavior struct {
	Mode           DefaultDNSBehaviorMode `yaml:"mode"`
	ForwardResolver string                `yaml:"forward_resolver"`
}

type GlobalConfig struct {
	ListenAddress      string             `yaml:"listen_address"`
	MetricsListen      string             `yaml:"metrics_listen"`
	ReadTimeout        string             `yaml:"read_timeout"`
	DefaultDNSBehavior DefaultDNSBehavior `yaml:"default_dns_behavior"`
}

type BackendConfig struct {
	ID      string `yaml:"id"`
	Address string `yaml:"address"`
	LbID    *uint8 `yaml:"lb_id"`
}

type PoolConfig struct {
	Name         string          `yaml:"name"`
	DomainSuffix string          `yaml:"domain_suffix"`
	Backends     []BackendConfig `yaml:"backends"`
}

type DnsttProtocolConfig struct {
	Pools []PoolConfig `yaml:"pools"`
}

type SlipstreamProtocolConfig struct {
	Pools []PoolConfig `yaml:"pools"`
}

type ProtocolsConfig struct {
	Dnstt      DnsttProtocolConfig      `yaml:"dnstt"`
	Slipstream SlipstreamProtocolConfig `yaml:"slipstream"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

type Config struct {
	Global    GlobalConfig    `yaml:"global"`
	Protocols ProtocolsConfig `yaml:"protocols"`
	Logging   LoggingConfig   `yaml:"logging"`

	parsedReadTimeout time.Duration
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.Global.MetricsListen = strings.TrimSpace(cfg.Global.MetricsListen)
	if cfg.Global.ReadTimeout != "" {
		if d, err := time.ParseDuration(cfg.Global.ReadTimeout); err == nil && d > 0 {
			cfg.parsedReadTimeout = d
		}
	}
	if cfg.parsedReadTimeout == 0 {
		cfg.parsedReadTimeout = 10 * time.Second
	}
	return &cfg, nil
}

