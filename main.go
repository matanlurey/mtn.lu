package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/golang-jwt/jwt/v5"
)

const PermAdmin = 1

type User struct {
	Email       string
	Permissions int
	CreatedAt   string
}

func (u User) IsAdmin() bool { return u.Permissions&PermAdmin != 0 }

type MagicLink struct {
	Token     string
	Email     string
	CreatedAt string
	ExpiresAt int64 // Unix timestamp (Seconds)
	UsedAt    string
}

type PageData struct {
	LoggedIn bool
	IsAdmin  bool
	Email    string
	Message  string
	Error    string
}

type AdminPageData struct {
	Email   string
	Users   []User
	Message string
	Error   string
}

func createDynamoClient(cfg DynamoDBConfig) *dynamodb.Client {
	ctx := context.Background()
	isLocal := os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == ""
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion("us-west-1")}
	if isLocal {
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	return dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(cfg.URL)
	})
}

// --- User Logic ---

func ensureAdminUser(ctx context.Context, client *dynamodb.Client, cfg Config) {
	if cfg.AdminUser == "" {
		return
	}
	now := time.Now().Format(time.RFC3339)
	_, err := client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(cfg.DynamoDB.UsersTable),
		Key:              map[string]types.AttributeValue{"email": &types.AttributeValueMemberS{Value: cfg.AdminUser}},
		UpdateExpression: aws.String("SET #perm = :perm, createdAt = if_not_exists(createdAt, :now)"),
		ExpressionAttributeNames: map[string]string{
			"#perm": "permissions",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":perm": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", PermAdmin)},
			":now":  &types.AttributeValueMemberS{Value: now},
		},
	})
	if err != nil {
		log.Fatalf("Failed to ensure admin user: %v", err)
	}
}

func getUserByEmail(ctx context.Context, client *dynamodb.Client, table, email string) (*User, error) {
	res, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key:       map[string]types.AttributeValue{"email": &types.AttributeValueMemberS{Value: email}},
	})
	if err != nil || res.Item == nil {
		return nil, err
	}
	u := &User{Email: email}
	if v, ok := res.Item["permissions"].(*types.AttributeValueMemberN); ok {
		fmt.Sscanf(v.Value, "%d", &u.Permissions)
	}
	if v, ok := res.Item["createdAt"].(*types.AttributeValueMemberS); ok {
		u.CreatedAt = v.Value
	}
	return u, nil
}

func listAllUsers(ctx context.Context, client *dynamodb.Client, table string) ([]User, error) {
	res, err := client.Scan(ctx, &dynamodb.ScanInput{TableName: aws.String(table)})
	if err != nil {
		return nil, err
	}
	users := []User{}
	for _, item := range res.Items {
		u := User{}
		if v, ok := item["email"].(*types.AttributeValueMemberS); ok {
			u.Email = v.Value
		}
		if v, ok := item["permissions"].(*types.AttributeValueMemberN); ok {
			fmt.Sscanf(v.Value, "%d", &u.Permissions)
		}
		if v, ok := item["createdAt"].(*types.AttributeValueMemberS); ok {
			u.CreatedAt = v.Value
		}
		users = append(users, u)
	}
	return users, nil
}

// --- Magic Link Logic ---

func checkCooldown(ctx context.Context, client *dynamodb.Client, table, email string) (bool, error) {
	cutoff := time.Now().Add(-60 * time.Second).Format(time.RFC3339)
	res, err := client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(table),
		IndexName:              aws.String("email-index"),
		KeyConditionExpression: aws.String("email = :email AND createdAt > :cutoff"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":email":  &types.AttributeValueMemberS{Value: email},
			":cutoff": &types.AttributeValueMemberS{Value: cutoff},
		},
		Limit: aws.Int32(1),
	})
	if err != nil {
		return false, err
	}
	return len(res.Items) > 0, nil
}

func createMagicLink(ctx context.Context, client *dynamodb.Client, table, email, token string, expiresAt time.Time) error {
	_, err := client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item: map[string]types.AttributeValue{
			"token":     &types.AttributeValueMemberS{Value: token},
			"email":     &types.AttributeValueMemberS{Value: email},
			"createdAt": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
			"expiresAt": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", expiresAt.Unix())},
		},
	})
	return err
}

func getMagicLink(ctx context.Context, client *dynamodb.Client, table, token string) (*MagicLink, error) {
	res, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key:       map[string]types.AttributeValue{"token": &types.AttributeValueMemberS{Value: token}},
	})
	if err != nil || res.Item == nil {
		return nil, err
	}
	ml := &MagicLink{Token: token}
	if v, ok := res.Item["email"].(*types.AttributeValueMemberS); ok {
		ml.Email = v.Value
	}
	if v, ok := res.Item["expiresAt"].(*types.AttributeValueMemberN); ok {
		fmt.Sscanf(v.Value, "%d", &ml.ExpiresAt)
	}
	if v, ok := res.Item["usedAt"].(*types.AttributeValueMemberS); ok {
		ml.UsedAt = v.Value
	}
	return ml, nil
}

// --- Rest of App Logic ---

func registerRoutes(mux *http.ServeMux, cfg Config, client *dynamodb.Client) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data := PageData{}
		if email, perm, ok := getUserFromJWT(r, cfg.JWTSecret); ok {
			data.LoggedIn, data.Email, data.IsAdmin = true, email, perm&PermAdmin != 0
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageTmpl.Execute(w, data)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		user, _ := getUserByEmail(r.Context(), client, cfg.DynamoDB.UsersTable, email)
		if user == nil {
			pageTmpl.Execute(w, PageData{Error: "Invite-only system."})
			return
		}
		if cool, _ := checkCooldown(r.Context(), client, cfg.DynamoDB.LinksTable, email); cool {
			pageTmpl.Execute(w, PageData{Error: "Wait a minute."})
			return
		}
		token := generateToken()
		createMagicLink(r.Context(), client, cfg.DynamoDB.LinksTable, email, token, time.Now().Add(15*time.Minute))
		sendMagicLinkEmail(cfg, email, fmt.Sprintf("%s/verify?token=%s", cfg.BaseURL, token))
		pageTmpl.Execute(w, PageData{Message: "Check email."})
	})

	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		ml, _ := getMagicLink(r.Context(), client, cfg.DynamoDB.LinksTable, token)
		if ml == nil || ml.UsedAt != "" || time.Now().Unix() > ml.ExpiresAt {
			pageTmpl.Execute(w, PageData{Error: "Invalid or expired link."})
			return
		}
		client.UpdateItem(r.Context(), &dynamodb.UpdateItemInput{
			TableName:                 aws.String(cfg.DynamoDB.LinksTable),
			Key:                       map[string]types.AttributeValue{"token": &types.AttributeValueMemberS{Value: token}},
			UpdateExpression:          aws.String("SET usedAt = :now"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":now": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)}},
		})
		user, _ := getUserByEmail(r.Context(), client, cfg.DynamoDB.UsersTable, ml.Email)
		jwtToken, _ := createJWT(user, cfg.JWTSecret)
		http.SetCookie(w, &http.Cookie{Name: "token", Value: jwtToken, Path: "/", HttpOnly: true, MaxAge: 86400})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		email, perm, ok := getUserFromJWT(r, cfg.JWTSecret)
		if !ok || perm&PermAdmin == 0 {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		users, _ := listAllUsers(r.Context(), client, cfg.DynamoDB.UsersTable)
		adminTmpl.Execute(w, AdminPageData{Email: email, Users: users})
	})

	mux.HandleFunc("/admin/add", func(w http.ResponseWriter, r *http.Request) {
		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		client.PutItem(r.Context(), &dynamodb.PutItemInput{
			TableName: aws.String(cfg.DynamoDB.UsersTable),
			Item: map[string]types.AttributeValue{
				"email":       &types.AttributeValueMemberS{Value: email},
				"permissions": &types.AttributeValueMemberN{Value: "0"},
				"createdAt":   &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
			},
		})
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	})

	mux.HandleFunc("/admin/remove", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		user, _ := getUserByEmail(r.Context(), client, cfg.DynamoDB.UsersTable, email)
		if user != nil && !user.IsAdmin() {
			client.DeleteItem(r.Context(), &dynamodb.DeleteItemInput{
				TableName: aws.String(cfg.DynamoDB.UsersTable),
				Key:       map[string]types.AttributeValue{"email": &types.AttributeValueMemberS{Value: email}},
			})
		}
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "token", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

// --- Helpers ---

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func createJWT(u *User, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": u.Email, "perm": u.Permissions, "iat": time.Now().Unix(), "exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString([]byte(secret))
}

func getUserFromJWT(r *http.Request, secret string) (string, int, bool) {
	c, err := r.Cookie("token")
	if err != nil {
		return "", 0, false
	}
	t, err := jwt.Parse(c.Value, func(t *jwt.Token) (interface{}, error) { return []byte(secret), nil })
	if err != nil || !t.Valid {
		return "", 0, false
	}
	claims := t.Claims.(jwt.MapClaims)
	return claims["email"].(string), int(claims["perm"].(float64)), true
}

func sendMagicLinkEmail(cfg Config, to, link string) error {
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Login\r\n\r\nLink: %s", cfg.SMTP.From, to, link)
	var auth smtp.Auth
	if cfg.SMTP.User != "" {
		auth = smtp.PlainAuth("", cfg.SMTP.User, cfg.SMTP.Pass, cfg.SMTP.Host)
	}
	return smtp.SendMail(fmt.Sprintf("%s:%d", cfg.SMTP.Host, cfg.SMTP.Port), auth, cfg.SMTP.From, []string{to}, []byte(msg))
}

//go:embed templates/page.html
var pageHTML string
var pageTmpl = template.Must(template.New("page").Parse(pageHTML))

//go:embed templates/admin.html
var adminHTML string
var adminTmpl = template.Must(template.New("admin").Parse(adminHTML))

func main() {
	cfg := loadConfigFromEnv()
	client := createDynamoClient(cfg.DynamoDB)
	ensureAdminUser(context.Background(), client, cfg)
	mux := http.NewServeMux()
	registerRoutes(mux, cfg, client)
	if cfg.IsLambda {
		lambda.Start(httpadapter.NewV2(mux).ProxyWithContext)
	} else {
		addr := fmt.Sprintf(":%d", cfg.Port)
		log.Printf("Listening on %s", cfg.BaseURL)
		log.Fatal(http.ListenAndServe(addr, mux))
	}
}
