package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"

	"mtn.lu/landing/internal/admin"
	"mtn.lu/landing/internal/auth"
	"mtn.lu/landing/internal/db"
)

func createDynamoClient(cfg DynamoDBConfig) *dynamodb.Client {
	ctx := context.Background()
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion("us-west-1")}
	if cfg.URL != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	return dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if cfg.URL != "" {
			o.BaseEndpoint = aws.String(cfg.URL)
		}
	})
}

func main() {
	cfg := loadConfigFromEnv()
	client := createDynamoClient(cfg.DynamoDB)
	database := db.New(client, cfg.DynamoDB.UsersTable, cfg.DynamoDB.LinksTable)

	if err := database.EnsureAdminUser(context.Background(), cfg.AdminUser); err != nil {
		log.Fatalf("Failed to ensure admin user: %v", err)
	}

	mux := http.NewServeMux()

	(&auth.Handler{
		DB:        database,
		JWTSecret: cfg.JWTSecret,
		BaseURL:   cfg.BaseURL,
		Revision:  cfg.Revision,
		SMTP: auth.SMTPConfig{
			Host: cfg.SMTP.Host,
			Port: cfg.SMTP.Port,
			User: cfg.SMTP.User,
			Pass: cfg.SMTP.Pass,
			From: cfg.SMTP.From,
		},
	}).Register(mux)

	(&admin.Handler{
		DB:        database,
		JWTSecret: cfg.JWTSecret,
	}).Register(mux)

	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		lambda.Start(httpadapter.NewV2(mux).ProxyWithContext)
	} else {
		addr := fmt.Sprintf(":%d", cfg.Port)
		log.Printf("Listening on %s", cfg.BaseURL)
		log.Fatal(http.ListenAndServe(addr, mux))
	}
}
