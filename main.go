package main

import "github.com/caarlos0/env/v11"

// Configures the running application.
type Config struct {
	Port      int    `env:"PORT" envDefault:"8080"`
	JWTSecret string `env:"JWT_SECRET"`
	BaseURL   string `env:"BASE_URL" envDefault:"http://localhost"`
}

func loadConfigFromEnv() Config {
	var cfg Config
	env.Parse(&cfg)
	return cfg
}

func main() {
	cfg := loadConfigFromEnv()
	println("Running on port:", cfg.Port)
	println("Base URL:", cfg.BaseURL)
}
