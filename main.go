package main

import (
	"fmt"
	"net/http"

	"github.com/caarlos0/env/v11"
)

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<base href="%s">
	<title>Hello World</title>
</head>
<body>
	<h1>Hello, World!</h1>
</body>
</html>`, cfg.BaseURL)
	})

	addr := fmt.Sprintf(":%d", cfg.Port)
	fmt.Printf("Listening on %s:%d\n", cfg.BaseURL, cfg.Port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
