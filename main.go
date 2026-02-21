package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/caarlos0/env/v11"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

// Config configures the running application.
type Config struct {
	Port        int    `env:"PORT" envDefault:"8080"`
	JWTSecret   string `env:"JWT_SECRET" envDefault:"dev_secret_do_not_use_in_prod"`
	BaseURL     string `env:"BASE_URL" envDefault:"http://localhost:8080"`
	DatabaseURL string `env:"DATABASE_URL" envDefault:"postgres://postgres:password123@localhost:5432/mtn_lu?sslmode=disable"`
	SMTPHost    string `env:"SMTP_HOST" envDefault:"localhost"`
	SMTPPort    string `env:"SMTP_PORT" envDefault:"1025"`
	SMTPUser    string `env:"SMTP_USER"`
	SMTPPass    string `env:"SMTP_PASS"`
	SMTPFrom    string `env:"SMTP_FROM" envDefault:"no-reply@mtn.lu"`
}

// User represents a row in the users table.
type User struct {
	ID    string
	Email string
}

// PageData holds all data passed to the HTML template.
type PageData struct {
	LoggedIn bool
	Email    string
	Message  string
	Error    string
}

func loadConfigFromEnv() Config {
	var cfg Config
	env.Parse(&cfg)
	return cfg
}

func connectDB(databaseURL string) *sql.DB {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Connected to database")
	return db
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

// getUserFromJWT extracts the user email from the JWT cookie, if present and valid.
func getUserFromJWT(r *http.Request, secret string) (string, bool) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return "", false
	}
	claims, err := parseJWT(cookie.Value, secret)
	if err != nil {
		return "", false
	}
	email, ok := claims["email"].(string)
	return email, ok
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

// registerRoutes registers all HTTP handlers on the given mux.
func registerRoutes(mux *http.ServeMux, cfg Config, db *sql.DB) {
	// Home page: show login form or logged-in state.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data := PageData{}
		if email, ok := getUserFromJWT(r, cfg.JWTSecret); ok {
			data.LoggedIn = true
			data.Email = email
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
		err := db.QueryRow("SELECT id, email FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email)
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
		err = db.QueryRow("SELECT id, email FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Email)
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
	db := connectDB(cfg.DatabaseURL)
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
