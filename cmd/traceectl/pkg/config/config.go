package config

import "io"

type Config struct {
	Printer PrinterConfig
	Server  ServerConfig
}

type ServerConfig struct {
	Protocol string
	Address  string
}

type PrinterConfig struct {
	Kind    string
	OutPath string
	OutFile io.Writer
}
