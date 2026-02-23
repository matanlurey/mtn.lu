package main

import "github.com/caarlos0/env/v11"

func loadConfigFromEnv() Config {
	var cfg Config
	env.Parse(&cfg)
	return cfg
}

type Config struct {
	Revision  string `env:"REVISION" envDefault:"unknown"`
	Port      int    `env:"PORT" envDefault:"8080"`
	BaseURL   string `env:"BASE_URL" envDefault:"http://localhost:8080"`
	AdminUser string `env:"ADMIN_USER" envDefault:"admin@mtn.lu"`
	JWTSecret string `env:"JWT_SECRET,required"`

	SMTP     SMTPConfig
	DynamoDB DynamoDBConfig
}

type SMTPConfig struct {
	Host string `env:"SMTP_HOST" envDefault:"localhost"`
	Port int    `env:"SMTP_PORT" envDefault:"1025"`
	User string `env:"SMTP_USER" envDefault:""`
	Pass string `env:"SMTP_PASS" envDefault:""`
	From string `env:"SMTP_FROM" envDefault:"no-reply@mtn.lu"`
}

type DynamoDBConfig struct {
	URL        string `env:"DYNAMODB_URL" envDefault:""`
	UsersTable string `env:"USERS_TABLE" envDefault:"users"`
	LinksTable string `env:"LINKS_TABLE" envDefault:"links"`
}
