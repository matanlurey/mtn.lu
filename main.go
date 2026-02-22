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
	"github.com/golang-jwt/jwt/v5"
)

const PermAdmin = 1

type Config struct {
	Port           int    `env:"PORT" envDefault:"8080"`
	JWTSecret      string `env:"JWT_SECRET" envDefault:"dev_secret_do_not_use_in_prod"`
	BaseURL        string `env:"BASE_URL" envDefault:"http://localhost:8080"`
	UsersTable     string `env:"USERS_TABLE" envDefault:"mtn-lu-users"`
	LinksTable     string `env:"LINKS_TABLE" envDefault:"mtn-lu-links"`
	DynamoEndpoint string `env:"DYNAMO_ENDPOINT"`
	AdminUser      string `env:"ADMIN_USER" envDefault:"admin@mtn.lu"`
	SMTPHost       string `env:"SMTP_HOST" envDefault:"localhost"`
	SMTPPort       string `env:"SMTP_PORT" envDefault:"1025"`
	SMTPUser       string `env:"SMTP_USER"`
	SMTPPass       string `env:"SMTP_PASS"`
	SMTPFrom       string `env:"SMTP_FROM" envDefault:"no-reply@mtn.lu"`
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

func createDynamoClient(cfg Config) *dynamodb.Client {
	ctx := context.Background()
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion("us-west-1")}
	if cfg.DynamoEndpoint != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	return dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if cfg.DynamoEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.DynamoEndpoint)
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
		TableName:        aws.String(cfg.UsersTable),
		Key:              map[string]types.AttributeValue{"email": &types.AttributeValueMemberS{Value: cfg.AdminUser}},
		UpdateExpression: aws.String("SET permissions = :perm, createdAt = if_not_exists(createdAt, :now)"),
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
		user, _ := getUserByEmail(r.Context(), client, cfg.UsersTable, email)
		if user == nil {
			pageTmpl.Execute(w, PageData{Error: "Invite-only system."})
			return
		}
		if cool, _ := checkCooldown(r.Context(), client, cfg.LinksTable, email); cool {
			pageTmpl.Execute(w, PageData{Error: "Wait a minute."})
			return
		}
		token := generateToken()
		createMagicLink(r.Context(), client, cfg.LinksTable, email, token, time.Now().Add(15*time.Minute))
		sendMagicLinkEmail(cfg, email, fmt.Sprintf("%s/verify?token=%s", cfg.BaseURL, token))
		pageTmpl.Execute(w, PageData{Message: "Check email."})
	})

	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		ml, _ := getMagicLink(r.Context(), client, cfg.LinksTable, token)
		if ml == nil || ml.UsedAt != "" || time.Now().Unix() > ml.ExpiresAt {
			pageTmpl.Execute(w, PageData{Error: "Invalid or expired link."})
			return
		}
		client.UpdateItem(r.Context(), &dynamodb.UpdateItemInput{
			TableName:                 aws.String(cfg.LinksTable),
			Key:                       map[string]types.AttributeValue{"token": &types.AttributeValueMemberS{Value: token}},
			UpdateExpression:          aws.String("SET usedAt = :now"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":now": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)}},
		})
		user, _ := getUserByEmail(r.Context(), client, cfg.UsersTable, ml.Email)
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
		users, _ := listAllUsers(r.Context(), client, cfg.UsersTable)
		adminTmpl.Execute(w, AdminPageData{Email: email, Users: users})
	})

	mux.HandleFunc("/admin/add", func(w http.ResponseWriter, r *http.Request) {
		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		client.PutItem(r.Context(), &dynamodb.PutItemInput{
			TableName: aws.String(cfg.UsersTable),
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
		user, _ := getUserByEmail(r.Context(), client, cfg.UsersTable, email)
		if user != nil && !user.IsAdmin() {
			client.DeleteItem(r.Context(), &dynamodb.DeleteItemInput{
				TableName: aws.String(cfg.UsersTable),
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

var pageTmpl = template.Must(template.New("p").Parse(`<html><body><h1>mtn.lu</h1>{{if .LoggedIn}}<p>{{.Email}}</p><form action="/logout" method="POST"><button>Logout</button></form>{{if .IsAdmin}}<a href="/admin">Admin</a>{{end}}{{else}}<form action="/login" method="POST"><input type="email" name="email" required><button>Login</button></form>{{end}}<p style="color:red">{{.Error}}</p><p style="color:green">{{.Message}}</p></body></html>`))
var adminTmpl = template.Must(template.New("a").Parse(`<html><body><h1>Admin</h1><form action="/admin/add" method="POST"><input type="email" name="email" required><button>Add</button></form><table>{{range .Users}}<tr><td>{{.Email}}</td><td>{{if not .IsAdmin}}<form action="/admin/remove" method="POST"><input type="hidden" name="email" value="{{.Email}}"><button>Remove</button></form>{{end}}</td></tr>{{end}}</table><a href="/">Back</a></body></html>`))

func main() {
	cfg := loadConfigFromEnv()
	client := createDynamoClient(cfg)
	ensureAdminUser(context.Background(), client, cfg)
	mux := http.NewServeMux()
	registerRoutes(mux, cfg, client)
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		lambda.Start(httpadapter.NewV2(mux).ProxyWithContext)
	} else {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), mux))
	}
}
