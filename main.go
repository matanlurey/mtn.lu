package main

import (
	"context"
	"crypto/rand"
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
	"github.com/caarlos0/env/v11"
	"github.com/golang-jwt/jwt/v5"
)

const PermAdmin = 1

const (
	usersTable = "users"
	linksTable = "links"
)

type Config struct {
	Port      int    `env:"PORT" envDefault:"8080"`
	JWTSecret string `env:"JWT_SECRET" envDefault:"dev_secret_do_not_use_in_prod"`
	BaseURL   string `env:"BASE_URL" envDefault:"http://localhost:8080"`
	AdminUser string `env:"ADMIN_USER" envDefault:"admin@mtn.lu"`
	SMTPHost  string `env:"SMTP_HOST" envDefault:"localhost"`
	SMTPPort  string `env:"SMTP_PORT" envDefault:"1025"`
	SMTPUser  string `env:"SMTP_USER"`
	SMTPPass  string `env:"SMTP_PASS"`
	SMTPFrom  string `env:"SMTP_FROM" envDefault:"no-reply@mtn.lu"`
}

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

func loadConfigFromEnv() Config {
	var cfg Config
	env.Parse(&cfg)
	return cfg
}

func createDynamoClient() *dynamodb.Client {
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
		if isLocal {
			o.BaseEndpoint = aws.String("http://localhost:8000")
		}
	})
}

// --- User Logic ---

func ensureAdminUser(ctx context.Context, client *dynamodb.Client, cfg Config) {
	if cfg.AdminUser == "" {
		return
	}
	now := time.Now().Format(time.RFC3339)
	_, err := client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(usersTable),
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
		user, _ := getUserByEmail(r.Context(), client, usersTable, email)
		if user == nil {
			pageTmpl.Execute(w, PageData{Error: "Invite-only system."})
			return
		}
		if cool, _ := checkCooldown(r.Context(), client, linksTable, email); cool {
			pageTmpl.Execute(w, PageData{Error: "Wait a minute."})
			return
		}
		token := generateToken()
		createMagicLink(r.Context(), client, linksTable, email, token, time.Now().Add(15*time.Minute))
		sendMagicLinkEmail(cfg, email, fmt.Sprintf("%s/verify?token=%s", cfg.BaseURL, token))
		pageTmpl.Execute(w, PageData{Message: "Check email."})
	})

	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		ml, _ := getMagicLink(r.Context(), client, linksTable, token)
		if ml == nil || ml.UsedAt != "" || time.Now().Unix() > ml.ExpiresAt {
			pageTmpl.Execute(w, PageData{Error: "Invalid or expired link."})
			return
		}
		client.UpdateItem(r.Context(), &dynamodb.UpdateItemInput{
			TableName:                 aws.String(linksTable),
			Key:                       map[string]types.AttributeValue{"token": &types.AttributeValueMemberS{Value: token}},
			UpdateExpression:          aws.String("SET usedAt = :now"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":now": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)}},
		})
		user, _ := getUserByEmail(r.Context(), client, usersTable, ml.Email)
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
		users, _ := listAllUsers(r.Context(), client, usersTable)
		adminTmpl.Execute(w, AdminPageData{Email: email, Users: users})
	})

	mux.HandleFunc("/admin/add", func(w http.ResponseWriter, r *http.Request) {
		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		client.PutItem(r.Context(), &dynamodb.PutItemInput{
			TableName: aws.String(usersTable),
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
		user, _ := getUserByEmail(r.Context(), client, usersTable, email)
		if user != nil && !user.IsAdmin() {
			client.DeleteItem(r.Context(), &dynamodb.DeleteItemInput{
				TableName: aws.String(usersTable),
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
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: Login\r\n\r\nLink: %s", cfg.SMTPFrom, to, link)
	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	}
	return smtp.SendMail(cfg.SMTPHost+":"+cfg.SMTPPort, auth, cfg.SMTPFrom, []string{to}, []byte(msg))
}

var pageTmpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>mtn.lu</title>
	<style>
		body { font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 20px; }
		h1 { margin-bottom: 4px; }
		.subtitle { color: #666; margin-top: 0; }
		form { margin-top: 20px; }
		input[type="email"] { padding: 8px; width: 100%; box-sizing: border-box; margin-bottom: 10px; }
		button { padding: 8px 16px; cursor: pointer; }
		.message { color: green; margin-top: 16px; }
		.error { color: red; margin-top: 16px; }
	</style>
</head>
<body>
	<h1>mtn.lu</h1>
	<p class="subtitle">Invite-only microsites</p>

	{{if .LoggedIn}}
		<p>Logged in as <strong>{{.Email}}</strong></p>
		{{if .IsAdmin}}<p><a href="/admin">Manage users</a></p>{{end}}
		<form method="POST" action="/logout">
			<button type="submit">Log out</button>
		</form>
	{{else}}
		<form method="POST" action="/login">
			<label for="email">Email address</label>
			<input type="email" id="email" name="email" placeholder="you@example.com" required>
			<button type="submit">Send login link</button>
		</form>
	{{end}}

	{{if .Message}}<p class="message">{{.Message}}</p>{{end}}
	{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
</body>
</html>`))

var adminTmpl = template.Must(template.New("admin").Parse(`<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>mtn.lu — Admin</title>
	<style>
		body { font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 20px; }
		h1 { margin-bottom: 4px; }
		.subtitle { color: #666; margin-top: 0; }
		table { width: 100%; border-collapse: collapse; margin-top: 20px; }
		th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
		form.inline { display: inline; }
		input[type="email"] { padding: 8px; width: 100%; box-sizing: border-box; margin-bottom: 10px; }
		button { padding: 8px 16px; cursor: pointer; }
		button.danger { background: #c0392b; color: white; border: none; }
		button.danger:disabled { background: #ccc; color: #888; cursor: not-allowed; }
		.message { color: green; margin-top: 16px; }
		.error { color: red; margin-top: 16px; }
		.back { margin-top: 20px; display: inline-block; }
	</style>
</head>
<body>
	<h1>mtn.lu</h1>
	<p class="subtitle">User management</p>

	{{if .Message}}<p class="message">{{.Message}}</p>{{end}}
	{{if .Error}}<p class="error">{{.Error}}</p>{{end}}

	<h2>Add user</h2>
	<form method="POST" action="/admin/add">
		<input type="email" name="email" placeholder="user@example.com" required>
		<button type="submit">Add</button>
	</form>

	<h2>Allowlisted users</h2>
	<table>
		<tr><th>Email</th><th></th></tr>
		{{range .Users}}
		<tr>
			<td>{{.Email}}</td>
			<td>
				{{if .IsAdmin}}
					<button class="danger" disabled title="Admin users cannot be removed">Remove</button>
				{{else}}
					<form class="inline" method="POST" action="/admin/remove">
						<input type="hidden" name="email" value="{{.Email}}">
						<button class="danger" type="submit" onclick="return confirm('Remove {{.Email}}?')">Remove</button>
					</form>
				{{end}}
			</td>
		</tr>
		{{end}}
	</table>

	<a class="back" href="/">← Back</a>
</body>
</html>`))

func main() {
	cfg := loadConfigFromEnv()
	client := createDynamoClient()
	ensureAdminUser(context.Background(), client, cfg)
	mux := http.NewServeMux()
	registerRoutes(mux, cfg, client)
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		lambda.Start(httpadapter.NewV2(mux).ProxyWithContext)
	} else {
		addr := fmt.Sprintf(":%d", cfg.Port)
		log.Printf("Listening on %s", cfg.BaseURL)
		log.Fatal(http.ListenAndServe(addr, mux))
	}
}
