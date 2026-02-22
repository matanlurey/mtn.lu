package main

import (
	"crypto/rand"
	"database/sql"
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
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/caarlos0/env/v11"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

//go:embed schema.sql
var schemaSQL string

// Permission flags (bit field).
const (
	PermAdmin = 1 << iota // 1
)

// Config configures the running application.
type Config struct {
	Port        int    `env:"PORT" envDefault:"8080"`
	JWTSecret   string `env:"JWT_SECRET" envDefault:"dev_secret_do_not_use_in_prod"`
	BaseURL     string `env:"BASE_URL" envDefault:"http://localhost:8080"`
	DatabaseURL string `env:"DATABASE_URL" envDefault:"postgres://postgres:password123@localhost:5432/mtn_lu?sslmode=disable"`
	AdminUser   string `env:"ADMIN_USER" envDefault:"admin@mtn.lu"`
	SMTPHost    string `env:"SMTP_HOST" envDefault:"localhost"`
	SMTPPort    string `env:"SMTP_PORT" envDefault:"1025"`
	SMTPUser    string `env:"SMTP_USER"`
	SMTPPass    string `env:"SMTP_PASS"`
	SMTPFrom    string `env:"SMTP_FROM" envDefault:"no-reply@mtn.lu"`
}

// User represents a row in the users table.
type User struct {
	ID          string
	Email       string
	Permissions int
}

// IsAdmin returns true if the user has the admin permission flag.
func (u User) IsAdmin() bool {
	return u.Permissions&PermAdmin != 0
}

// PageData holds all data passed to the HTML template.
type PageData struct {
	LoggedIn bool
	IsAdmin  bool
	Email    string
	Message  string
	Error    string
}

// AdminPageData holds data for the admin template.
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

func connectDB(cfg Config) *sql.DB {
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Connected to database")

	// Initialize schema on startup (idempotent).
	initSchema(db)

	// Ensure the admin user exists.
	if cfg.AdminUser != "" {
		_, err := db.Exec(
			`INSERT INTO users (email, permissions) VALUES ($1, $2)
			 ON CONFLICT (email) DO UPDATE SET permissions = users.permissions | $2`,
			cfg.AdminUser, PermAdmin,
		)
		if err != nil {
			log.Fatalf("Failed to seed admin user: %v", err)
		}
		log.Printf("Admin user ensured: %s", cfg.AdminUser)
	}

	return db
}

func initSchema(db *sql.DB) {
	for _, stmt := range strings.Split(schemaSQL, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			log.Fatalf("Failed to run schema statement: %v\n%s", err, stmt)
		}
	}
	log.Println("Schema initialized")
}

// generateToken creates a cryptographically secure random token.
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	return hex.EncodeToString(b)
}

// createJWT creates a signed JWT for a given user.
func createJWT(user User, secret string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"perm":  user.Permissions,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// parseJWT validates a JWT and returns the claims if valid.
func parseJWT(tokenString string, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// getUserFromJWT extracts the user email and permissions from the JWT cookie, if present and valid.
func getUserFromJWT(r *http.Request, secret string) (string, int, bool) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return "", 0, false
	}
	claims, err := parseJWT(cookie.Value, secret)
	if err != nil {
		return "", 0, false
	}
	email, ok := claims["email"].(string)
	if !ok {
		return "", 0, false
	}
	perm := 0
	if p, ok := claims["perm"].(float64); ok {
		perm = int(p)
	}
	return email, perm, true
}

// sendMagicLinkEmail sends a magic link email via SMTP.
func sendMagicLinkEmail(cfg Config, toEmail string, link string) error {
	subject := "Your mtn.lu login link"
	body := fmt.Sprintf("Click here to log in:\n\n%s\n\nThis link expires in 15 minutes.", link)
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		cfg.SMTPFrom, toEmail, subject, body,
	)

	addr := cfg.SMTPHost + ":" + cfg.SMTPPort

	// Use authentication only if credentials are provided (production/SES).
	// Mailpit (local dev) does not require authentication.
	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	}

	err := smtp.SendMail(addr, auth, cfg.SMTPFrom, []string{toEmail}, []byte(msg))
	if err != nil {
		log.Printf("Failed to send email to %s: %v", toEmail, err)
		return err
	}
	log.Printf("Sent login email to %s", toEmail)
	return nil
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
						<input type="hidden" name="id" value="{{.ID}}">
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

func renderAdmin(w http.ResponseWriter, db *sql.DB, email, message, errMsg string) {
	rows, err := db.Query("SELECT id, email, permissions FROM users ORDER BY created_at")
	if err != nil {
		log.Printf("Failed to list users: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Permissions); err != nil {
			log.Printf("Failed to scan user: %v", err)
			continue
		}
		users = append(users, u)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	adminTmpl.Execute(w, AdminPageData{
		Email:   email,
		Users:   users,
		Message: message,
		Error:   errMsg,
	})
}

// registerRoutes registers all HTTP handlers on the given mux.
func registerRoutes(mux *http.ServeMux, cfg Config, db *sql.DB) {
	// Home page: show login form or logged-in state.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data := PageData{}
		if email, perm, ok := getUserFromJWT(r, cfg.JWTSecret); ok {
			data.LoggedIn = true
			data.Email = email
			data.IsAdmin = perm&PermAdmin != 0
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageTmpl.Execute(w, data)
	})

	// Login: validate email exists, create magic link, send email.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		email := r.FormValue("email")
		if email == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Email is required."})
			return
		}

		// Check if the user exists (invite-only).
		var user User
		err := db.QueryRow("SELECT id, email, permissions FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.Permissions)
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "This system is invite-only. No account found for that email."})
			return
		} else if err != nil {
			log.Printf("Database error: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Something went wrong. Please try again."})
			return
		}

		// Cooldown: reject if a magic link was sent to this user in the last 60 seconds.
		var recentExists bool
		err = db.QueryRow(
			"SELECT EXISTS(SELECT 1 FROM magic_links WHERE user_id = $1 AND created_at > NOW() - INTERVAL '60 seconds')",
			user.ID,
		).Scan(&recentExists)
		if err != nil {
			log.Printf("Database error checking cooldown: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Something went wrong. Please try again."})
			return
		}
		if recentExists {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "A login link was already sent. Please wait a minute before trying again."})
			return
		}

		// Create a magic link token.
		token := generateToken()
		expiresAt := time.Now().Add(15 * time.Minute)
		_, err = db.Exec(
			"INSERT INTO magic_links (user_id, token, expires_at) VALUES ($1, $2, $3)",
			user.ID, token, expiresAt,
		)
		if err != nil {
			log.Printf("Failed to create magic link: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Something went wrong. Please try again."})
			return
		}

		// Send the magic link email.
		link := fmt.Sprintf("%s/verify?token=%s", cfg.BaseURL, token)
		if err := sendMagicLinkEmail(cfg, user.Email, link); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Failed to send login email. Please try again."})
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pageTmpl.Execute(w, PageData{Message: "Check your email for a login link."})
	})

	// Verify: validate the magic link token and issue a JWT.
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Look up the magic link.
		var userID string
		var expiresAt time.Time
		var usedAt sql.NullTime
		err := db.QueryRow(
			"SELECT user_id, expires_at, used_at FROM magic_links WHERE token = $1",
			token,
		).Scan(&userID, &expiresAt, &usedAt)

		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Invalid login link."})
			return
		} else if err != nil {
			log.Printf("Database error: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Something went wrong. Please try again."})
			return
		}

		// Check if the link has already been used.
		if usedAt.Valid {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "This login link has already been used."})
			return
		}

		// Check if the link has expired.
		if time.Now().After(expiresAt) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "This login link has expired."})
			return
		}

		// Mark the link as used.
		db.Exec("UPDATE magic_links SET used_at = NOW() WHERE token = $1", token)

		// Look up the user.
		var user User
		err = db.QueryRow("SELECT id, email, permissions FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Email, &user.Permissions)
		if err != nil {
			log.Printf("Database error looking up user: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Something went wrong. Please try again."})
			return
		}

		// Issue a JWT.
		jwtToken, err := createJWT(user, cfg.JWTSecret)
		if err != nil {
			log.Printf("Failed to create JWT: %v", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			pageTmpl.Execute(w, PageData{Error: "Something went wrong. Please try again."})
			return
		}

		// Set the JWT as an HTTP-only cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    jwtToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   86400, // 24 hours
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// Admin: list all users (admin only).
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		email, perm, ok := getUserFromJWT(r, cfg.JWTSecret)
		if !ok || perm&PermAdmin == 0 {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		renderAdmin(w, db, email, "", "")
	})

	// Admin: add a user.
	mux.HandleFunc("/admin/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		email, perm, ok := getUserFromJWT(r, cfg.JWTSecret)
		if !ok || perm&PermAdmin == 0 {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		newEmail := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		if newEmail == "" {
			renderAdmin(w, db, email, "", "Email is required.")
			return
		}

		_, err := db.Exec("INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING", newEmail)
		if err != nil {
			log.Printf("Failed to add user: %v", err)
			renderAdmin(w, db, email, "", "Failed to add user.")
			return
		}
		renderAdmin(w, db, email, fmt.Sprintf("Added %s.", newEmail), "")
	})

	// Admin: remove a user.
	mux.HandleFunc("/admin/remove", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		email, perm, ok := getUserFromJWT(r, cfg.JWTSecret)
		if !ok || perm&PermAdmin == 0 {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		userID := r.FormValue("id")
		if userID == "" {
			renderAdmin(w, db, email, "", "User ID is required.")
			return
		}

		// Prevent removal of admin users.
		var target User
		err := db.QueryRow("SELECT id, email, permissions FROM users WHERE id = $1", userID).Scan(&target.ID, &target.Email, &target.Permissions)
		if err != nil {
			renderAdmin(w, db, email, "", "User not found.")
			return
		}
		if target.IsAdmin() {
			renderAdmin(w, db, email, "", "Admin users cannot be removed.")
			return
		}

		_, err = db.Exec("DELETE FROM users WHERE id = $1", userID)
		if err != nil {
			log.Printf("Failed to remove user: %v", err)
			renderAdmin(w, db, email, "", "Failed to remove user.")
			return
		}
		renderAdmin(w, db, email, fmt.Sprintf("Removed %s.", target.Email), "")
	})

	// Logout: clear the JWT cookie.
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1, // Delete the cookie.
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func main() {
	cfg := loadConfigFromEnv()
	db := connectDB(cfg)
	defer db.Close()

	mux := http.NewServeMux()
	registerRoutes(mux, cfg, db)

	// If running in AWS Lambda, use the Lambda handler.
	// Otherwise, run as a standard HTTP server.
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		log.Println("Running in Lambda mode")
		lambda.Start(httpadapter.NewV2(mux).ProxyWithContext)
	} else {
		addr := fmt.Sprintf(":%d", cfg.Port)
		log.Printf("Listening on %s", cfg.BaseURL)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}
